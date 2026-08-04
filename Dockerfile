FROM python:3.14.6-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS builder

ARG PIP_VERSION=26.2

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY backend/requirements.txt .
RUN python -m pip install --no-cache-dir "pip==${PIP_VERSION}" && \
    python -m pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM node:26.5.1-slim@sha256:deae974a69e140f44f434ab29cb519fb5f8fe250fd364b8ca446bd0761acdc6a AS frontend-builder

WORKDIR /build/frontend

COPY frontend/package*.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM python:3.14.6-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GRPC_SSL_CIPHER_SUITES=HIGH+ECDSA \
    DEP_ENV=DOCKER \
    SERVICE_PORT=22121

WORKDIR /app

COPY --from=builder /install /usr/local
COPY backend/app ./backend/app
COPY scripts/lnswitchboard-diagnose-lnd /usr/local/bin/lnswitchboard-diagnose-lnd
RUN chmod +x /usr/local/bin/lnswitchboard-diagnose-lnd
COPY --from=frontend-builder /build/frontend/static ./frontend/static
COPY VERSION ./VERSION

EXPOSE 22121

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:22121/api/health', timeout=2).read()"]

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "22121", "--no-proxy-headers"]
