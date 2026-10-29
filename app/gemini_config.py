"""Explicit Gemini configuration; load only whitelisted AI settings from .env."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import re

AI_SETTINGS = ('GEMINI_API_KEY','GEMINI_MODEL','SENTINELOPS_GEMINI_ENABLED',
               'SENTINELOPS_AI_TIMEOUT_MS','SENTINELOPS_AI_MAX_ATTEMPTS','SENTINELOPS_AI_BUDGET_MS')
PROJECT_ENV = Path(__file__).resolve().parent.parent/'.env'
MIN_PROVIDER_TIMEOUT_MS = 10000


@dataclass(frozen=True)
class Settings:
    api_key: str = field(default='',repr=False)
    model: str = ''
    timeout_ms: int = 15000
    max_attempts: int = 2
    budget_ms: int = 60000
    code: str = 'READY'


def load_ai_settings():
    try:
        if PROJECT_ENV.is_file():
            if PROJECT_ENV.stat().st_size > 65536:
                return Settings(code='INVALID_CONFIGURATION')
            from dotenv import dotenv_values
            values = dotenv_values(PROJECT_ENV,interpolate=False,encoding='utf-8-sig')
            for name in AI_SETTINGS:
                if name not in os.environ and isinstance(values.get(name),str):
                    os.environ[name] = values[name]
    except (OSError,ValueError,ImportError,UnicodeError):
        return Settings(code='CONFIGURATION_UNAVAILABLE')
    enabled = os.environ.get('SENTINELOPS_GEMINI_ENABLED','1').strip()
    if enabled not in ('0','1'):
        return Settings(code='INVALID_CONFIGURATION')
    if enabled=='0':
        return Settings(code='DISABLED')
    key = os.environ.get('GEMINI_API_KEY','').strip()
    model = os.environ.get('GEMINI_MODEL','').strip()
    if not key:
        return Settings(code='KEY_NOT_CONFIGURED')
    if not model:
        return Settings(code='MODEL_NOT_CONFIGURED')
    if (not 16 <= len(key) <= 512 or any(c.isspace() for c in key)
            or not re.fullmatch(r'(?:models/)?gemini-[A-Za-z0-9][A-Za-z0-9._-]{0,100}',model)):
        return Settings(code='INVALID_CONFIGURATION')
    try:
        timeout = int(os.environ.get('SENTINELOPS_AI_TIMEOUT_MS','15000'))
        attempts = int(os.environ.get('SENTINELOPS_AI_MAX_ATTEMPTS','2'))
        budget = int(os.environ.get('SENTINELOPS_AI_BUDGET_MS','60000'))
        if not MIN_PROVIDER_TIMEOUT_MS <= timeout <= 30000 or attempts not in (1,2) or not MIN_PROVIDER_TIMEOUT_MS <= budget <= 60000:
            raise ValueError('Invalid bounds')
    except (ValueError,TypeError):
        return Settings(code='INVALID_CONFIGURATION')
    return Settings(key,model,timeout,attempts,budget)


def public_settings():
    settings = load_ai_settings()
    return {'configured':settings.code=='READY','configuration_status':settings.code,
            'model':settings.model or None,'attempt_timeout_ms':settings.timeout_ms,
            'max_attempts':settings.max_attempts,'workflow_budget_ms':settings.budget_ms,
            'live_authentication':'not_checked','mode':'SIMULATION_ONLY'}
