# Project Unit42-FirmwareX — Automated IoT Firmware Analysis Engine
# Palo Alto Networks // Unit 42 Threat Research & Security Engineering
# Multi-stage Container with Sandboxing & Cross-Architecture Emulation Tools

FROM python:3.11-slim-bookworm AS base

# Prevent interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies, cross-architecture tools, and unpackers
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    procps \
    qemu-user-static \
    binwalk \
    squashfs-tools \
    cpio \
    gzip \
    bzip2 \
    tar \
    p7zip-full \
    libmagic1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated unprivileged user for secure sandboxed analysis (PRD SC-1.3)
RUN useradd -m -u 1000 -s /bin/bash firmwarex

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy project files
COPY --chown=firmwarex:firmwarex . /app

# Prepare storage directories with proper permissions
RUN mkdir -p /app/data_storage/uploads \
             /app/data_storage/extracted \
             /app/data_storage/reports \
             /app/data_storage/logs && \
    chown -R firmwarex:firmwarex /app/data_storage && \
    chmod +x /app/docker-entrypoint.sh

USER firmwarex

# Expose default ports
EXPOSE 8000 8501 10000

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["dashboard"]
