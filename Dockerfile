# syntax=docker/dockerfile:1

############################
# Python dependencies
############################
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

############################
# Trust data (roots and distrust dates, preloaded intermediates, EV roots,
# OneCRL, CT logs, static key pins)
#
# By default the bundled files in src/trust/data are used. Pass any new value in
# REFRESH_TRUST_DATA (deploy.sh passes today's date) to download the current
# data from Mozilla instead; any file that cannot be downloaded keeps its
# bundled version.
############################
FROM builder AS trust-data

ARG REFRESH_TRUST_DATA=""
COPY scripts/ scripts/
COPY src/trust/data/ src/trust/data/
RUN if [ -n "$REFRESH_TRUST_DATA" ]; then \
        python scripts/update_trust_data.py \
        || echo "WARNING: some trust data could not be refreshed, using the bundled files"; \
    fi

############################
# Runtime image
############################
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=6010 \
    WORKERS=4

# dig is used for the DNSSEC check; openssl is already in the base image
RUN apt-get update \
    && apt-get install -y --no-install-recommends dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 appuser \
    && useradd -u 10001 -g 10001 -s /usr/sbin/nologin -d /nonexistent appuser

COPY --from=builder /usr/local /usr/local

WORKDIR /app
COPY src/ src/
COPY --from=trust-data /app/src/trust/data/ src/trust/data/

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/health', timeout=4)" || exit 1

EXPOSE ${PORT}

CMD ["sh", "-c", "exec uvicorn src.api:app --host 0.0.0.0 --port \"$PORT\" --workers \"$WORKERS\""]
