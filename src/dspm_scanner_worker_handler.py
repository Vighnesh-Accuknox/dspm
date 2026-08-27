import json
import sys
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlsplit

import boto3
import requests

import settings
from src.engine.detector import DetectionEngine
from src.scanners.aws.ddb import DynamoDBScanner
from src.scanners.aws.s3 import S3Scanner
from src.scanners.db.mongo import MongoScanner
from src.scanners.db.sql import SQLScanner
from src.utils.logger import get_logger

logger = get_logger("handler")

BASE_DIR = Path(__file__).resolve().parent.parent

# Overridable so containers can point at a writable volume (OpenShift runs as a
# random non-root UID). Directories are created lazily inside the handler, never
# at import time.
OUTPUT_DIR = Path(settings.OUTPUT_DIR) if settings.OUTPUT_DIR else BASE_DIR / "output"
FINDINGS_DIR = OUTPUT_DIR / "findings"
S3_BUCKETS_DIR = OUTPUT_DIR / "s3buckets"

# OBJECT_TYPE values -> canonical engine name for database scans
DB_OBJECT_TYPES = {
    "MONGO": "mongo",
    "MONGODB": "mongo",
    "DOCUMENTDB": "mongo",
    "POSTGRES": "postgres",
    "POSTGRESQL": "postgres",
    "MYSQL": "mysql",
    "MARIADB": "mariadb",
    "MSSQL": "mssql",
    "SQLSERVER": "mssql",
}

UPLOAD_RETRIES = 3


def post_findings_to_api(api_url: str, zip_path: Path) -> bool:
    """
    HTTP POST request to upload the findings archive to the CSPM Backend.
    Retries with backoff; returns True on success.
    """
    if not api_url:
        return False

    url = f"{api_url.rstrip('/')}/api/v1/dspm/upload"
    headers = {"Authorization": f"Bearer {settings.DSPM_TOKEN}"}

    for attempt in range(1, UPLOAD_RETRIES + 1):
        try:
            logger.info(f"Sending findings to CSPM Backend (attempt {attempt}/{UPLOAD_RETRIES})")
            with open(zip_path, "rb") as zip_file:
                resp = requests.post(url=url, headers=headers, files={"file": zip_file}, timeout=60)

            logger.info(f"Upload response status: {resp.status_code}")
            logger.info(f"Upload response body: {resp.text}")
            if resp.status_code < 300:
                return True
        except Exception as e:
            logger.error(f"Failed to post findings to CSPM Backend: {str(e)}")

        if attempt < UPLOAD_RETRIES:
            time.sleep(2 * attempt)

    return False


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler entry point.
    """

    # loading environment variables
    object_type = settings.OBJECT_TYPE
    object_name = settings.OBJECT_NAME

    logger.info(f"Scanning {object_type}")

    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)

    errors = []
    config = {
        "enabled_regions": settings.ENABLED_REGIONS,
        "log_queries": settings.LOG_QUERIES,
    }

    engine = DetectionEngine(config=config)

    findings_file = FINDINGS_DIR / f"{object_name}.json"

    start_time = datetime.now()

    final_json = {
        "scan_time" : start_time,
        "files_scanned" : 0,
        "object_type": object_type,
        "object_name": object_name,
        "time_taken": None,
        "findings": [],
    }

    if object_type and object_type.upper() == "S3":
        try:
            logger.info("Creating S3 Client instance")
            # Static keys if provided; falls back to instance profile / IRSA when unset
            s3_client = boto3.client(
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                service_name="s3",
            )

            s3scanner = S3Scanner(engine, config, s3_client)

            files = s3scanner.list_all_files(bucket=object_name)

            S3_BUCKETS_DIR.mkdir(parents=True, exist_ok=True)
            bucket_file = S3_BUCKETS_DIR / f"{object_name}.json"

            with bucket_file.open('w') as file:
                json.dump(files, file, indent=4, default=str)

            for file in files:
                file_size = file.get("Size", None)
                file_key = file.get("Key", None)

                if (file_size and file_size < 100*1024*1024) and file_key:
                    target = {
                        "bucket": object_name,
                        "key": file_key,
                        "version_id": file.get("VersionId", None),
                        "last_modified": file.get("LastModified", None),
                    }
                    findings_for_file = s3scanner.scan(target)
                    final_json['findings'].append({file_key: findings_for_file})
                    final_json['files_scanned'] += 1
                    with findings_file.open("w") as f:
                        json.dump(final_json, f, indent=4, default=str)
                else:
                    logger.info(f"Skipping file {file_key} with size {file_size}")
        except Exception as e:
            errors.append(f"S3 scan failed: {str(e)}")
            logger.error(errors[-1])

    elif object_type and object_type.upper() in DB_OBJECT_TYPES:
        engine_name = DB_OBJECT_TYPES[object_type.upper()]
        logger.info(f"Creating {engine_name} scanner instance")

        target = {
            "engine": engine_name,
            "host": settings.DB_HOST,
            "port": settings.DB_PORT,
            "username": settings.DB_USERNAME,
            "password": settings.DB_PASSWORD,
            "database": object_name,
        }

        # DB_URI-only setups: derive the host so findings carry the real
        # resource id instead of 'localhost'
        if settings.DB_URI and not target["host"]:
            try:
                target["host"] = urlsplit(settings.DB_URI).hostname
            except ValueError:
                pass

        if engine_name == "mongo":
            if settings.DB_URI:
                target["uri"] = settings.DB_URI
            db_scanner = MongoScanner(engine, config)
        else:
            if settings.DB_URI:
                target["connection_string"] = settings.DB_URI
            db_scanner = SQLScanner(engine, config)

        db_findings = db_scanner.scan(target)

        # Group findings per table/collection, mirroring the per-file S3 layout
        grouped = {}
        for finding in db_findings:
            grouped.setdefault(finding.get("resource_id", object_name), []).append(finding)
        final_json['findings'] = [{resource: items} for resource, items in grouped.items()]
        final_json['files_scanned'] = (
            db_scanner.stats.get("tables_scanned")
            or db_scanner.stats.get("collections_scanned", 0)
        )

        scan_errors = db_scanner.stats.get("errors", 0)
        if scan_errors:
            errors.append(f"{scan_errors} error(s) during {engine_name} scan, see logs")
            logger.error(errors[-1])

    else:
        errors.append(f"Unsupported OBJECT_TYPE '{object_type}'")
        logger.error(errors[-1])

    end_time = datetime.now()
    final_json['time_taken'] = str(end_time - start_time)
    final_json['errors'] = errors

    with findings_file.open("w") as f:
        json.dump(final_json, f, indent=4, default=str)

    logger.info(f"Time taken for scanning {object_name}: {end_time - start_time}")

    logger.info("zipping the file before sending to artifact API")
    zip_file = FINDINGS_DIR / f"{object_name}.zip"

    with zipfile.ZipFile(
        zip_file,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zipf:
        zipf.write(findings_file, arcname=findings_file.name)

    try:
        if findings_file.exists():
            findings_file.unlink(missing_ok=True)
            logger.info(f"Successfully removed the JSON file after compression: {findings_file}")
    except Exception as e:
        logger.error(f"Failed to remove JSON file {findings_file}: {str(e)}")

    # Post results to the CSPM backend if configured
    api_url = settings.CSPM_URL
    logger.info(f"API URL: {api_url}")

    if api_url:
        if post_findings_to_api(api_url, zip_file):
            try:
                zip_file.unlink(missing_ok=True)
                logger.info("Findings uploaded; local archive removed")
            except Exception:
                pass
        else:
            errors.append("findings upload to CSPM Backend failed")
            logger.error(f"Upload failed; findings kept locally at {zip_file}")
    else:
        logger.warning(f"CSPM_URL is not configured; findings kept locally at {zip_file}")

    status_code = 200 if not errors else 500
    return {
        "statusCode": status_code,
        "body": json.dumps({
            "status": "success" if not errors else "error",
            "files scanned": final_json['files_scanned'],
            "errors": errors,
        }),
    }

# Run-once mode only when executed directly (python -m src.dspm_scanner_worker_handler,
# as the container CMD does) — importing this module must never start a scan
if __name__ == "__main__" and settings.SCANNING_OBJECT_TYPE == "EC2":
    result = lambda_handler(None, None)
    sys.exit(0 if result.get("statusCode") == 200 else 1)
