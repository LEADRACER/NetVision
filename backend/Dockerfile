# syntax=docker/dockerfile:1

# =============================================================================
# NetVision Backend — Multi-stage Dockerfile
# =============================================================================
# Build:  docker build -t netvision:latest .
# Run:    docker run -d -p 8000:8000 --cap-add=NET_RAW --cap-add=NET_ADMIN netvision
# Compose: docker compose up -d
# =============================================================================

# ── Stage 1: Builder ──────────────────────────────────────────────────────
FROM python:3.13-slim AS builder

WORKDIR /build

# Install build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ── Stage 2: Runtime ──────────────────────────────────────────────────────
FROM python:3.13-slim AS runtime

# System deps for network tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    tshark \
    sqlite3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && nmap --version | head -1 \
    && tshark --version | head -1

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Create non-root user
RUN groupadd -r netvision && useradd -r -g netvision -d /app -s /sbin/nologin netvision

WORKDIR /app

# Copy application
COPY . .

# Create data directories
RUN mkdir -p captures reports logs && chown -R netvision:netvision /app

# Expose API port
EXPOSE 8000

# Switch to non-root
USER netvision

# Healthcheck
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/live')" || exit 1

# Run
CMD ["python3", "main.py"]
