FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY backend/requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM node:22-slim AS frontend-builder

WORKDIR /build/frontend

COPY frontend/package*.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SERVICE_PORT=22121

WORKDIR /app

COPY --from=builder /install /usr/local
COPY backend/app ./backend/app
COPY --from=frontend-builder /build/frontend/static ./frontend/static
COPY VERSION ./VERSION

EXPOSE 22121

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "22121"]
