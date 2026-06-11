# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    RAINMAN_DB=/data/rainman.db

WORKDIR /app

# Install deps first (cached) using only the project metadata.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# SQLite file lives on a volume so the graph survives container restarts.
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

# 0.0.0.0 so the API is reachable from outside the container.
CMD ["sh", "-c", "rainman --db \"$RAINMAN_DB\" serve --host 0.0.0.0 --port 8000"]
