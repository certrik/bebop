FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    proxychains-ng \
    nmap \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 bebop

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/

# Copy application code
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    SOCKS_PORT=9050 \
    SOCKS_HOST=127.0.0.1 \
    PYTHONDONTWRITEBYTECODE=1

# Add metadata
LABEL org.opencontainers.image.title="bebop" \
      org.opencontainers.image.authors="@joshhighet" \
      org.opencontainers.image.base.name="ghcr.io/joshhighet/bebop:latest" \
      org.opencontainers.image.description="scanner" \
      org.opencontainers.image.documentation="https://github.com/joshhighet/bebop#readme" \
      org.opencontainers.image.url="https://github.com/joshhighet/bebop/pkgs/container/bebop" \
      org.opencontainers.image.source="https://github.com/joshhighet/bebop/blob/main/bebop/dockerfile"

# Change ownership to non-root user
RUN chown -R bebop:bebop /app

# Switch to non-root user
USER bebop

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${SOCKS_PORT} || exit 1

# Set entrypoint
ENTRYPOINT ["python3", "-m", "app"]