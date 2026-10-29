"""Safe error bodies, bounded requests, and credential redaction at the HTTP edge."""
import json
import os
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import JSONResponse


def operator(store, analyst_id, token, permission='view'):
    if not analyst_id or not token:
        raise HTTPException(status_code=401,detail='Analyst credentials required')
    if store.authorize(analyst_id,token,permission) is None:
        raise HTTPException(status_code=403,detail='Analyst not authorized')


def register_errors(app):
    @app.exception_handler(StarletteHTTPException)
    async def http_error(request,exc):
        codes = {401:'AUTHENTICATION_REQUIRED',403:'OPERATION_DENIED',404:'NOT_FOUND',
                 405:'METHOD_NOT_ALLOWED',409:'STATE_CONFLICT',413:'PAYLOAD_TOO_LARGE',
                 422:'INVALID_INPUT',503:'SERVICE_UNAVAILABLE'}
        detail = exc.detail if isinstance(exc.detail,str) else 'Request denied'
        return JSONResponse(status_code=exc.status_code,content={'detail':detail,'code':codes.get(exc.status_code,'REQUEST_FAILED')})

    @app.exception_handler(RequestValidationError)
    async def invalid(request,exc):
        # Pydantic's default error includes input values, potentially credentials.
        return JSONResponse(status_code=422,content={'detail':'Request validation failed','code':'INVALID_INPUT'})

    @app.exception_handler(Exception)
    async def unavailable(request,exc):
        return JSONResponse(status_code=503,content={'detail':'Service unavailable','code':'SERVICE_UNAVAILABLE'})


def redact(value,secrets,sensitive_fields=True):
    if isinstance(value,dict):
        return {k:('[REDACTED]' if sensitive_fields and any(x in k.lower() for x in ('token','password','secret','signature','api_key','collector_key','signing_key','signed_evidence')) else redact(v,secrets,sensitive_fields)) for k,v in value.items()}
    if isinstance(value,list):
        return [redact(v,secrets,sensitive_fields) for v in value]
    if isinstance(value,str):
        for secret in secrets:
            if secret:
                value = value.replace(secret,'[REDACTED]')
    return value


class PublicBoundary:
    def __init__(self,app):
        self.app = app

    async def __call__(self,scope,receive,send):
        if scope['type'] != 'http':
            return await self.app(scope,receive,send)
        chunks = []
        size = 0
        while True:
            part = await receive()
            if part['type']=='http.disconnect':
                return
            body = part.get('body',b'')
            size += len(body)
            if size > 131072:
                return await JSONResponse(status_code=413,content={'detail':'Request body too large','code':'PAYLOAD_TOO_LARGE'})(scope,receive,send)
            chunks.append(body)
            if not part.get('more_body',False):
                break
        used = False

        async def replay():
            nonlocal used
            if not used:
                used = True
                return {'type':'http.request','body':b''.join(chunks),'more_body':False}
            return await receive()

        headers = dict(scope.get('headers',[]))
        secrets = [v for k,v in os.environ.items() if any(x in k.upper() for x in ('KEY','TOKEN','SECRET','PASSWORD')) and len(v)>=4]
        secrets += [headers.get(k,b'').decode('utf-8',errors='replace') for k in (b'x-api-key',b'x-analyst-token')]
        start = None
        response = []

        async def safe_send(message):
            nonlocal start
            if message['type']=='http.response.start':
                start = message
                return
            if message['type']=='http.response.body':
                response.append(message.get('body',b''))
                if message.get('more_body',False):
                    return
                raw = b''.join(response)
                if start and any(k.lower()==b'content-type' and b'application/json' in v for k,v in start['headers']):
                    try:
                        # Schema property names describe credential INPUTS; they
                        # contain no credentials. Preserve their schema objects.
                        raw = json.dumps(redact(json.loads(raw),secrets,scope.get('path')!='/openapi.json'),ensure_ascii=True).encode()
                    except (ValueError,UnicodeError):
                        pass
                if start:
                    start = dict(start,headers=[(k,v) for k,v in start['headers'] if k.lower()!=b'content-length']+[(b'content-length',str(len(raw)).encode())])
                    await send(start)
                await send({'type':'http.response.body','body':raw})
                return
            await send(message)
        return await self.app(scope,replay,safe_send)
