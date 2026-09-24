# syntax=docker/dockerfile:1

FROM python:3.12-slim AS base

# System deps: lxml needs libxml2/libxslt; cryptography needs libssl
RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2 \
        libxslt1.1 \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project metadata first for better layer caching
COPY pyproject.toml README.md ./
COPY umani ./umani

# Install UMANI + runtime deps
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
 && pip install --no-cache-dir -e .

# Default working dir for state (DB, generated CA)
RUN mkdir -p /data
WORKDIR /data

# Drop to non-root user
RUN useradd --create-home --shell /bin/bash umani \
 && chown -R umani:umani /data /app
USER umani

ENTRYPOINT ["umani"]
CMD ["--help"]
