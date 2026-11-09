# One image for every service (web, engine, Celery worker, Celery beat). Not built in the development
# environment: build and test it on a staging machine first.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt && playwright install --with-deps chromium
COPY . .
ENV HOST=0.0.0.0 PORT=8000 UPLOAD_DIR=/data/uploads ARTIFACT_DIR=/data/artifacts PLAYWRIGHT_NO_SANDBOX=true
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/login', timeout=4)" || exit 1
CMD ["python", "serve.py"]
