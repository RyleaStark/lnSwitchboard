FROM python:3.14.6-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS builder

ARG PIP_VERSION=26.2

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY backend/requirements.txt .
RUN python -m pip install --no-cache-dir "pip==${PIP_VERSION}" && \
    python -m pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM node:26.7.0-slim@sha256:4ebb5ace66f15a24c14c492e01a8beeed4fddf970a856109f5126e703e5fe503 AS frontend-builder

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
    SERVICE_HOST=0.0.0.0 \
    SERVICE_PORT=22121 \
    PUBLIC_SERVICE_HOST=0.0.0.0 \
    PUBLIC_SERVICE_PORT=21212

WORKDIR /app

COPY --from=builder /install /usr/local
COPY backend/app ./backend/app
COPY scripts/lnswitchboard-diagnose-lnd /usr/local/bin/lnswitchboard-diagnose-lnd
COPY scripts/lnswitchboard-prepare-state /usr/local/bin/lnswitchboard-prepare-state
RUN groupadd --gid 1000 lnswitchboard && \
    useradd --uid 1000 --gid 1000 --home-dir /app --shell /usr/sbin/nologin lnswitchboard && \
    mkdir -p /app/secrets/tailscale /app/secrets/cloudflare-mesh && \
    chown -R 1000:1000 /app/secrets && \
    chmod 0700 /app/secrets /app/secrets/tailscale /app/secrets/cloudflare-mesh && \
    chmod +x /usr/local/bin/lnswitchboard-diagnose-lnd /usr/local/bin/lnswitchboard-prepare-state
COPY --from=frontend-builder /build/frontend/static ./frontend/static
COPY VERSION ./VERSION

USER 1000:1000

EXPOSE 22121 21212

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:22121/api/health', timeout=2).read()"]

CMD ["python", "-m", "backend.app.server"]
