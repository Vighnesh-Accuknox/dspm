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

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy settings
COPY settings.py .

# Copy application source code
COPY src/ ./src/

# Create directory for scan findings
RUN mkdir -p /app/output

# Make Python able to import settings and src
ENV PYTHONPATH=/app

# Run the scanner
CMD ["python", "-m", "src.dspm_scanner_worker_handler"]
