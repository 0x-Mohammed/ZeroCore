# =============================================================================
# ZeroCore Agent — Production Dockerfile
# Multi-stage build: builder installs deps, final image is lean.
# Runs as non-root user. Requires CAP_NET_ADMIN for iptables — no sudo.
# =============================================================================

# Stage 1: Builder
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies into isolated prefix
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --prefix=/install --no-cache-dir -r requirements.txt


# Stage 2: Final image
FROM python:3.12-slim AS final

LABEL org.opencontainers.image.title="ZeroCore Agent"
LABEL org.opencontainers.image.description="Automated Incident Response Agent"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Install runtime OS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Create non-root user
RUN groupadd --gid 1001 zerocore \
    && useradd --uid 1001 --gid zerocore --shell /bin/bash --create-home zerocore

WORKDIR /app

# Create data directory for SQLite persistence
RUN mkdir -p /app/data && chown zerocore:zerocore /app/data

# Copy application source
COPY --chown=zerocore:zerocore src/ ./src/
COPY --chown=zerocore:zerocore .env.example .env.example

# Switch to non-root user
USER zerocore

EXPOSE 8000

# Health check for container orchestrators
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# NOTE: CAP_NET_ADMIN must be granted at runtime via:
#   docker run --cap-add NET_ADMIN ...
#   or in docker-compose.yml: cap_add: [NET_ADMIN]
CMD ["python", "-m", "src.main"]
