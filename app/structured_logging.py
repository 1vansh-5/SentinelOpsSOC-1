"""Allowlisted operational events: never format message arguments or exceptions.

Database response_audit remains the authoritative transactional audit. These logs
are best-effort diagnostics, contain no request data, and grant no permissions.
"""
from datetime import datetime, timezone
import json
import logging
import re
import time
import uuid

METHODS={'GET','POST','HEAD','OPTIONS','PUT','PATCH','DELETE'}


class SafeJSONFormatter(logging.Formatter):
    def format(self,record):
        result={'timestamp':datetime.now(timezone.utc).isoformat(),
                'level':record.levelname if record.levelname in ('DEBUG','INFO','WARNING','ERROR','CRITICAL') else 'INFO',
                'event':'http.request' if getattr(record,'event',None)=='http.request' else 'server.lifecycle',
                'mode':'SIMULATION_ONLY'}
        method=getattr(record,'method',None)
        if method in METHODS: result['method']=method
        route=getattr(record,'route_template',None)
        # Templates come from server-owned routes, never request paths or queries.
        if isinstance(route,str) and len(route)<=160 and re.fullmatch(r'/[A-Za-z0-9_/{}/.:-]*',route):
            result['route']=route
        status=getattr(record,'status_code',None)
        if type(status) is int and 100<=status<=599: result['status_code']=status
        duration=getattr(record,'duration_ms',None)
        if type(duration) in (int,float) and 0<=duration<=86400000: result['duration_ms']=round(duration,3)
        ident=getattr(record,'request_id',None)
        if isinstance(ident,str):
            try:
                parsed=uuid.UUID(ident)
                if str(parsed)==ident: result['request_id']=ident
            except ValueError:
                pass
        return json.dumps(result,ensure_ascii=True,allow_nan=False)


def configure():
    logger=logging.getLogger('sentinelops.operations')
    if not any(getattr(handler,'_sentinelops_safe',False) for handler in logger.handlers):
        handler=logging.StreamHandler()
        handler._sentinelops_safe=True
        handler.setFormatter(SafeJSONFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO); logger.propagate=False
    # Raw Uvicorn access logging includes URLs; operational logging uses templates.
    logging.getLogger('uvicorn.access').disabled=True
    return logger


class OperationalLogging:
    def __init__(self,app):
        self.app=app; self.logger=configure()

    async def __call__(self,scope,receive,send):
        if scope['type']!='http': return await self.app(scope,receive,send)
        ident=str(uuid.uuid4()); started=time.monotonic(); status=503
        async def observed_send(message):
            nonlocal status
            if message['type']=='http.response.start':
                status=message['status']
                message=dict(message,headers=[(k,v) for k,v in message.get('headers',[]) if k.lower()!=b'x-request-id']+
                             [(b'x-request-id',ident.encode())])
            await send(message)
        try:
            return await self.app(scope,receive,observed_send)
        finally:
            try:
                route=getattr(scope.get('route'),'path',None)
                # Unknown routes contribute no caller-controlled path text.
                self.logger.info('request',extra={'event':'http.request',
                    'method':scope.get('method'),'route_template':route,
                    'status_code':status,'duration_ms':(time.monotonic()-started)*1000,'request_id':ident})
            except Exception:
                pass  # Operational logging cannot change a committed decision.
