FROM python:3.14-slim

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-eng && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt ${LAMBDA_TASK_ROOT}/

# Install Python package dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy Settings
COPY settings.py ${LAMBDA_TASK_ROOT}/

# Copy application source code
COPY src/ ${LAMBDA_TASK_ROOT}/src/

# Set the CMD to your handler (could also be src/handler.py)
CMD ["python", "-m", "src.dspm_scanner_worker_handler"]
