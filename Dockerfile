FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install deps (cache-friendly)
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    apt-get update && apt-get install -y --no-install-recommends curl && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y --auto-remove curl && rm -rf /var/lib/apt/lists/*

# Production image
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=6010 \
    HOST=0.0.0.0

WORKDIR /app

# Copy deps + runtime binaries/libs
COPY --from=builder /usr/local /usr/local
COPY . .

# Install dig + create/fix user in ONE step
USER root
RUN groupadd -g 10001 appuser 2>/dev/null || true && \
    useradd -u 10001 -g 10001 -s /sbin/nologin -d /nonexistent appuser 2>/dev/null || true && \
    apt-get update && \
    apt-get install -y --no-install-recommends dnsutils && \
    apt-get purge -y --auto-remove && \
    rm -rf /var/lib/apt/lists/* && \
    chown -R appuser:appuser /app /usr/local && \
    chmod -R +x /usr/local/bin/*
USER appuser

# Healthcheck (add /health endpoint to src/api.py if needed)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/docs || exit 1

EXPOSE ${PORT}

CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "6010", "--workers", "2"]
