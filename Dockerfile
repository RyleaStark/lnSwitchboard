FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY backend/requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SERVICE_PORT=22121

WORKDIR /app

COPY --from=builder /install /usr/local
COPY backend/app ./backend/app
COPY frontend/static ./frontend/static

EXPOSE 22121

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "22121"]
