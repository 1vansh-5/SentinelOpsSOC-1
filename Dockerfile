# Experimental Linux recipe: not built or runtime-verified by the Windows gate.
FROM python:3.15.0-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/sentinelops
COPY requirements.txt requirements-step9-lock.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt
RUN groupadd --gid 10001 sentinelops && useradd --uid 10001 --gid 10001 --no-create-home sentinelops && mkdir /data && chown 10001:10001 /data
COPY app ./app
COPY ops/uvicorn_logging.json ./ops/uvicorn_logging.json
ENV SENTINELOPS_DB=/data/incidents.sqlite SENTINELOPS_ANALYST_DB=/data/analysts.sqlite SENTINELOPS_REGISTRY_DB=/data/registry.sqlite SENTINELOPS_GEMINI_ENABLED=0
USER 10001:10001
EXPOSE 8000
CMD ["python","-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--no-access-log","--log-config","ops/uvicorn_logging.json"]
