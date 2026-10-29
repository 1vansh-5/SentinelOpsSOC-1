"""Optional one-attempt authenticated provider check with a fixed non-sensitive prompt.

This calls Gemini and may use provider quota. No SOC data, keys or model text is
printed. Exit zero requires a real, validated response, never a fallback result.
"""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import json
import os
from app.gemini_config import load_ai_settings
from app.gemini_models import LiveProbe
from app.gemini_runtime import request_proposal


def main():
    settings = load_ai_settings()
    if settings.code!='READY':
        print(json.dumps({'status':'LIVE_NOT_VERIFIED','reason':settings.code}))
        return 1
    # A live diagnostic must never silently make a second billed request.
    previous = os.environ.get('SENTINELOPS_AI_MAX_ATTEMPTS')
    os.environ['SENTINELOPS_AI_MAX_ATTEMPTS'] = '1'
    try:
        answer = request_proposal('Connectivity test only. Return the JSON object {"status":"OK"}. No tools or external data.',LiveProbe)
    finally:
        if previous is None:
            os.environ.pop('SENTINELOPS_AI_MAX_ATTEMPTS',None)
        else:
            os.environ['SENTINELOPS_AI_MAX_ATTEMPTS'] = previous
    verified = answer.data is not None and answer.code=='OK'
    print(json.dumps({'status':'LIVE_VERIFIED' if verified else 'LIVE_NOT_VERIFIED',
                      'reason':answer.code,'model':answer.model,'attempts':answer.attempts}))
    return 0 if verified else 1


if __name__=='__main__':
    raise SystemExit(main())
