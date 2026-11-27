# Multi-stage Dockerfile for SecureFL Flower Federated Learning Nodes (build context: repo root)
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

FROM base AS builder
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --prefix=/install -r requirements.txt

FROM python:3.11-slim AS production

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/install/bin:$PATH" \
    PYTHONPATH="/app:/install/lib/python3.11/site-packages"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl && rm -rf /var/lib/apt/lists/* && apt-get clean

WORKDIR /app
COPY --from=builder /install /install
COPY federated_learning ./federated_learning

RUN mkdir -p /app/models /app/metrics /app/data /app/logs /app/certs && \
    groupadd --gid 1001 flgroup && \
    useradd --uid 1001 --gid flgroup --shell /bin/bash --create-home fluser && \
    chown -R fluser:flgroup /app

USER fluser
EXPOSE 8080 8081

HEALTHCHECK --interval=30s --timeout=10s --start-period=25s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost',8080)); s.close()" || exit 1

CMD ["python", "-m", "federated_learning.server"]
