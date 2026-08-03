FROM python:3.11.15-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93 AS builder

ARG PIP_VERSION=26.2

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY backend/requirements.txt .
RUN python -m pip install --no-cache-dir "pip==${PIP_VERSION}" && \
    python -m pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM node:22.23.1-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS frontend-builder

WORKDIR /build/frontend

COPY frontend/package*.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM python:3.11.15-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93 AS runtime

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
