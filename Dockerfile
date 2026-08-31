FROM python:3.14-slim

# Install system dependencies
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-eng && \
    rm -rf /var/lib/apt/lists/*

# Set application working directory
WORKDIR /app

# Install Python package dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy settings loader and application source (all secrets come from env, never the image)
COPY settings.py .
COPY src/ ./src/

# PYTHONPATH makes settings and src importable regardless of the working directory
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    OUTPUT_DIR=/app/output

# Precompile bytecode: read-only root filesystems cannot cache it at runtime
RUN python -m compileall -q /app

# OpenShift runs containers as a random non-root UID in the root group:
# group 0 needs the same permissions as the owner
RUN mkdir -p /app/output && chgrp -R 0 /app && chmod -R g=u /app

USER 1001

# Run the scanner
CMD ["python", "-m", "src.dspm_scanner_worker_handler"]
