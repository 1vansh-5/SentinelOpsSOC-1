"""Bounded provider proposals. Child processes enforce deadlines and are reaped.

Only read-only text generation is retried, once, on 500/502/503/504. SDK retries
are disabled. No prompts, keys, raw provider text or exceptions are logged here.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import json
import logging
import multiprocessing
import os
import threading
import time

from .gemini_config import load_ai_settings, MIN_PROVIDER_TIMEOUT_MS

MAX_PROMPT_BYTES = 24000
MAX_RESPONSE_BYTES = 24000
_deadline = ContextVar('sentinelops_ai_deadline',default=None)
_capacity = threading.BoundedSemaphore(2)
TRANSIENT = {'PROVIDER_TRANSIENT'}


@dataclass
class Answer:
    data: dict | None
    code: str
    attempts: int = 0
    model: str | None = None

    def metadata(self):
        return {'provider':'gemini','provider_status':self.code,'attempts':self.attempts,
                'model':self.model,'live_authentication':'verified_this_call' if self.code=='OK' else 'not_verified_this_call'}


def redact_text(value):
    for name,secret in os.environ.items():
        if len(secret)>=8 and any(x in name.upper() for x in ('KEY','TOKEN','PASSWORD','SECRET')):
            value = value.replace(secret,'[REDACTED]')
    return value


@contextmanager
def workflow_budget():
    if _deadline.get() is not None:
        yield
        return
    setting = load_ai_settings()
    marker = _deadline.set(time.monotonic()+setting.budget_ms/1000)
    try:
        yield
    finally:
        _deadline.reset(marker)


def _error_code(exc):
    status = getattr(exc,'code',None)
    if status in (401,403):
        return 'PROVIDER_AUTHENTICATION'
    if status==429:
        return 'PROVIDER_QUOTA'
    if status==404:
        return 'MODEL_UNAVAILABLE'
    if status in (500,502,503,504):
        return 'PROVIDER_TRANSIENT'
    if status==400:
        return 'PROVIDER_REQUEST_REJECTED'
    try:
        import httpx
        if isinstance(exc,(TimeoutError,httpx.TimeoutException)):
            return 'PROVIDER_TIMEOUT'
        if isinstance(exc,httpx.TransportError):
            return 'PROVIDER_TRANSPORT'
    except ImportError:
        pass
    return 'PROVIDER_UNAVAILABLE'


def _sdk_exchange(settings,prompt,schema,timeout_ms):
    if timeout_ms < MIN_PROVIDER_TIMEOUT_MS:
        return {'code':'BUDGET_EXHAUSTED'}
    client = None
    try:
        from google import genai
        from google.genai import types
        # Explicit developer API selection prevents ambient Vertex/enterprise
        # configuration from routing this request to another account.
        options = types.HttpOptions(base_url='https://generativelanguage.googleapis.com',
            api_version='v1beta',timeout=timeout_ms,
            retry_options=types.HttpRetryOptions(attempts=1))
        client = genai.Client(api_key=settings.api_key,vertexai=False,enterprise=False,http_options=options)
        response = client.models.generate_content(model=settings.model,contents=prompt,
            config={'response_mime_type':'application/json','response_json_schema':schema,
                    'temperature':0.1,'max_output_tokens':2048,
                    'automatic_function_calling':{'disable':True}})
        candidates = getattr(response,'candidates',None)
        if not candidates:
            return {'code':'PROVIDER_BLOCKED'}
        finish = getattr(candidates[0],'finish_reason',None)
        if getattr(finish,'value',finish) != 'STOP':
            return {'code':'PROVIDER_INCOMPLETE'}
        text = response.text
        if not isinstance(text,str) or not text.strip():
            return {'code':'PROVIDER_EMPTY'}
        if len(text.encode('utf-8'))>MAX_RESPONSE_BYTES:
            return {'code':'RESPONSE_TOO_LARGE'}
        return {'code':'OK','text':redact_text(text)}
    except ImportError:
        return {'code':'SDK_UNAVAILABLE'}
    except Exception as exc:
        return {'code':_error_code(exc)}
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _sdk_worker(connection,settings,prompt,schema,timeout_ms):
    # Suppress third-party debug logging in the isolated provider worker.
    for name in ('google','google.genai','httpx','httpcore'):
        logging.getLogger(name).setLevel(logging.CRITICAL+1)
    try:
        connection.send(_sdk_exchange(settings,prompt,schema,timeout_ms))
    except Exception:
        try:
            connection.send({'code':'PROVIDER_UNAVAILABLE'})
        except Exception:
            pass
    finally:
        connection.close()


def _run_process(target,args,timeout_ms):
    """Separate bounded worker; no abandoned threads or provider client handles."""
    context = multiprocessing.get_context('spawn')
    receive,send = context.Pipe(duplex=False)
    process = context.Process(target=target,args=(send,*args),daemon=True)
    started = False
    try:
        start = time.monotonic()
        process.start()
        started = True
        send.close()
        remaining = max(0,timeout_ms/1000-(time.monotonic()-start))
        if not receive.poll(remaining):
            return {'code':'PROVIDER_TIMEOUT'}
        result = receive.recv()
        return result if isinstance(result,dict) else {'code':'PROVIDER_UNAVAILABLE'}
    except (OSError,EOFError,ValueError,RuntimeError):
        return {'code':'PROVIDER_UNAVAILABLE'}
    finally:
        receive.close()
        send.close()
        if started:
            if process.is_alive():
                process.terminate()
            process.join(timeout=0.5)
            if process.is_alive():
                process.kill()
                process.join(timeout=0.5)
            if not process.is_alive():
                process.close()


def _invoke(settings,prompt,schema,timeout_ms):
    return _run_process(_sdk_worker,(settings,prompt,schema,timeout_ms),timeout_ms)


def request_proposal(prompt,model_type,reference_check=None):
    settings = load_ai_settings()
    if settings.code!='READY':
        return Answer(None,settings.code)
    prompt = redact_text(prompt)
    if len(prompt.encode('utf-8'))>MAX_PROMPT_BYTES:
        return Answer(None,'PROMPT_TOO_LARGE',model=settings.model)
    end = _deadline.get()
    if end is None:
        end = time.monotonic()+settings.budget_ms/1000
    if not _capacity.acquire(blocking=False):
        return Answer(None,'LOCAL_CAPACITY',model=settings.model)
    attempts = 0
    try:
        while attempts < settings.max_attempts:
            remaining_ms = int((end-time.monotonic())*1000)
            # Never turn a nearly exhausted workflow budget into a provider
            # deadline below Google's 10-second minimum.
            if remaining_ms < MIN_PROVIDER_TIMEOUT_MS:
                return Answer(None,'BUDGET_EXHAUSTED',attempts,settings.model)
            attempts += 1
            result = _invoke(settings,prompt,model_type.model_json_schema(),min(settings.timeout_ms,remaining_ms))
            code = result.get('code','PROVIDER_UNAVAILABLE')
            if code=='OK':
                text = result.get('text')
                if not isinstance(text,str):
                    return Answer(None,'INVALID_RESPONSE',attempts,settings.model)
                if len(text.encode('utf-8'))>MAX_RESPONSE_BYTES:
                    return Answer(None,'RESPONSE_TOO_LARGE',attempts,settings.model)
                try:
                    # Reject duplicate keys and non-finite numbers as malformed JSON.
                    def pairs(items):
                        obj = {}
                        for key,value in items:
                            if key in obj:
                                raise ValueError('Duplicate key')
                            obj[key] = value
                        return obj
                    def constant(value):
                        raise ValueError('Non-finite value')
                    parsed = json.loads(redact_text(text),object_pairs_hook=pairs,parse_constant=constant)
                    validated = model_type.model_validate(parsed).model_dump()
                except (ValueError,TypeError,RecursionError):
                    return Answer(None,'INVALID_RESPONSE',attempts,settings.model)
                if reference_check is not None and not reference_check(validated):
                    return Answer(None,'INVALID_EVIDENCE_REFERENCE',attempts,settings.model)
                return Answer(validated,'OK',attempts,settings.model)
            if code not in TRANSIENT or attempts==settings.max_attempts:
                return Answer(None,code,attempts,settings.model)
            delay = 0.1
            if time.monotonic()+delay+MIN_PROVIDER_TIMEOUT_MS/1000>=end:
                return Answer(None,'BUDGET_EXHAUSTED',attempts,settings.model)
            time.sleep(delay)
        return Answer(None,'PROVIDER_UNAVAILABLE',attempts,settings.model)
    except Exception:
        return Answer(None,'PROVIDER_UNAVAILABLE',attempts,settings.model)
    finally:
        _capacity.release()
