import json
import os
import sys
import time
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
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

# OBJECT_TYPE values accepted for S3 buckets
S3_OBJECT_TYPES = {"S3", "S3BUCKET"}

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
MAX_WORKERS = 2  # objects scanned in parallel when several are configured


def club_findings(raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Club raw findings by detector name and type/category for a file.
    Output schema:
    [
        {
            "name": "Email",
            "type": "PII",
            "finding_values": {
                "[EMAIL_ADDRESS]": "location"
            },
            "total_count": "n"
        }
    ]
    """
    if not raw_findings:
        return []

    grouped: Dict[tuple, Dict[str, Any]] = {}

    for f in raw_findings:
        name = f.get("detector", "Unknown")
        category = f.get("category", "General")
        val = str(f.get("value", ""))
        location = f.get("location", "")

        key = (name, category)
        if key not in grouped:
            grouped[key] = {
                "name": name,
                "type": category,
                "finding_values": {},
                "total_count": 0,
            }

        # Aggregated DB findings stand for many rows/documents (see BaseScanner.flush_grouped_findings)
        grouped[key]["total_count"] += f.get("occurrences", 1)

        # If the same value is found in multiple locations, record them
        if val in grouped[key]["finding_values"]:
            existing_loc = grouped[key]["finding_values"][val]
            if isinstance(existing_loc, list):
                if location not in existing_loc:
                    existing_loc.append(location)
            elif existing_loc != location:
                grouped[key]["finding_values"][val] = [existing_loc, location]
        else:
            grouped[key]["finding_values"][val] = location

    return list(grouped.values())


def post_findings_to_api(api_url: str, zip_path: Path) -> bool:
    """
    HTTP POST request to upload the findings archive to the Artifact API / CSPM Backend.
    Matches:
    curl --location '<CSPM_URL>/api/v1/artifact/?data_type=DSPM&save_to_s3=false&label_id=test' \
         --header 'Authorization: Bearer <ARTIFACT_TOKEN>' \
         --form 'file=@<findings.zip>'
    Retries with backoff; returns True on success.
    """
    if not api_url:
        return False

    if not zip_path.exists():
        logger.error(f"Findings zip file {zip_path} does not exist for upload.")
        return False

    # URL ensuring clean trailing slash before query params
    url = f"{api_url.rstrip('/')}/api/v1/artifact/"
    params = {
        "data_type": "DSPM",
        "save_to_s3": "false",
        "label_id": settings.LABEL_ID or "test",
    }
    headers = {}
    if settings.ARTIFACT_TOKEN:
        headers["Authorization"] = f"Bearer {settings.ARTIFACT_TOKEN}"

    for attempt in range(1, UPLOAD_RETRIES + 1):
        try:
            logger.info(
                f"Sending {zip_path.name} to CSPM Backend: {url} with params {params} "
                f"(attempt {attempt}/{UPLOAD_RETRIES})",
            )
            with open(zip_path, "rb") as zip_file:
                resp = requests.post(
                    url=url,
                    params=params,
                    headers=headers,
                    files={"file": (zip_path.name, zip_file, "application/zip")},
                    timeout=60,
                )

            logger.info(f"Upload response status for {zip_path.name}: {resp.status_code}")
            logger.info(f"Upload response body for {zip_path.name}: {resp.text}")
            if resp.status_code < 300:
                return True
        except Exception as e:
            logger.error(f"Failed to post findings to Artifact API: {str(e)}")

        if attempt < UPLOAD_RETRIES:
            time.sleep(2 * attempt)

    return False


def process_bucket(bucket_name: str, object_type: str = "s3", object_region: str = None) -> Dict[str, Any]:
    """
    Process scan for a single bucket/target (an S3 bucket or a database).
    """
    logger.info(f"Starting scan for object: {bucket_name} (type: {object_type})")

    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)

    errors = []
    config = {
        "enabled_regions": settings.ENABLED_REGIONS,
        "log_queries": settings.LOG_QUERIES,
    }

    scan_date = datetime.today().date()
    start_time = datetime.now()

    engine = DetectionEngine(config=config)
    findings_file = FINDINGS_DIR / f"{bucket_name}-{scan_date}.json"

    final_json = {
        "scan_time": start_time,
        "files_scanned": 0,
        "object_type": object_type,
        "object_name": bucket_name,
        "account_id": settings.AWS_ACCOUNT_ID,
        "time_taken": None,
        "findings": {},
    }

    normalized_type = str(object_type or "").upper()

    if normalized_type in S3_OBJECT_TYPES:
        try:
            logger.info(f"Creating S3 Client instance for {bucket_name}")
            # Static keys if provided; falls back to instance profile / IRSA when unset
            client_kwargs = {
                "aws_secret_access_key": settings.AWS_SECRET_ACCESS_KEY,
                "aws_access_key_id": settings.AWS_ACCESS_KEY_ID,
                "service_name": "s3",
            }
            if object_region:
                client_kwargs["region_name"] = object_region

            s3_client = boto3.client(**client_kwargs)
            s3scanner = S3Scanner(engine, config, s3_client)

            files = s3scanner.list_all_files(bucket=bucket_name)

            for file in files:
                file_size = file.get("Size", None)
                file_key = file.get("Key", None)

                if (file_size and file_size < 100 * 1024 * 1024) and file_key:
                    target = {
                        "bucket": bucket_name,
                        "key": file_key,
                        "version_id": file.get("VersionId", None),
                        "last_modified": file.get("LastModified", None),
                    }
                    raw_findings_for_file = s3scanner.scan(target)

                    # If findings have multiple resource_ids (e.g. per-sheet Excel files or archive items)
                    # group findings by sub-target/sheet
                    ext = os.path.splitext(file_key)[1].lower()
                    if ext in [".xlsx", ".xls"]:
                        # Group raw findings by sheet
                        sheet_findings_map: Dict[str, List[Dict[str, Any]]] = {}
                        for finding in raw_findings_for_file:
                            res_id = finding.get("resource_id", "")
                            # Check if resource_id has [SheetName]
                            if f"{target['bucket']}/{file_key} [" in res_id and res_id.endswith("]"):
                                sheet_part = res_id.split(f"{target['bucket']}/{file_key} ")[-1]
                                sheet_key = f"{file_key} {sheet_part}"
                            else:
                                sheet_key = file_key

                            sheet_findings_map.setdefault(sheet_key, []).append(finding)

                        if not sheet_findings_map:
                            # Even if no findings, record the file entry
                            final_json["findings"][file_key] = []
                        else:
                            for sheet_entry_key, s_findings in sheet_findings_map.items():
                                final_json["findings"][sheet_entry_key] = club_findings(s_findings)
                    else:
                        final_json["findings"][file_key] = club_findings(raw_findings_for_file)

                    final_json["files_scanned"] += 1
                    with findings_file.open("w") as f:
                        json.dump(final_json, f, indent=4, default=str)
                else:
                    logger.info(f"Skipping file {file_key} with size {file_size}")

            scan_errors = s3scanner.stats.get("errors", 0)
            if scan_errors:
                errors.append(f"{scan_errors} error(s) during S3 scan, see logs")
                logger.error(errors[-1])
        except Exception as e:
            errors.append(f"S3 scan failed: {str(e)}")
            logger.error(errors[-1])

    elif normalized_type in DB_OBJECT_TYPES:
        engine_name = DB_OBJECT_TYPES[normalized_type]
        try:
            logger.info(f"Creating {engine_name} scanner instance for {bucket_name}")
            target = {
                "engine": engine_name,
                "host": settings.DB_HOST,
                "port": settings.DB_PORT,
                "username": settings.DB_USERNAME,
                "password": settings.DB_PASSWORD,
                "database": bucket_name,
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

            # A table/collection is the database counterpart of an S3 object: one entry
            # per relation (schema-qualified) or collection, clean ones included, checkpointed
            # after each just like the per-object S3 loop above
            for _resource_id, relation_name, relation_findings in db_scanner.iter_scan(target):
                final_json["findings"][relation_name] = club_findings(relation_findings)
                final_json["files_scanned"] += 1
                with findings_file.open("w") as f:
                    json.dump(final_json, f, indent=4, default=str)

            scan_errors = db_scanner.stats.get("errors", 0)
            if scan_errors:
                errors.append(f"{scan_errors} error(s) during {engine_name} scan, see logs")
                logger.error(errors[-1])
        except Exception as e:
            errors.append(f"{engine_name} scan failed: {str(e)}")
            logger.error(errors[-1])

    else:
        errors.append(f"Unsupported object type '{object_type}' for {bucket_name}")
        logger.error(errors[-1])

    end_time = datetime.now()
    final_json["time_taken"] = str(end_time - start_time)
    final_json["errors"] = errors

    with findings_file.open("w") as f:
        json.dump(final_json, f, indent=4, default=str)

    logger.info(f"Time taken for scanning {bucket_name}: {end_time - start_time}")

    # Zip findings file
    logger.info(f"Zipping findings for {bucket_name} before sending to Artifact API")
    zip_file = FINDINGS_DIR / f"{bucket_name}-{scan_date}.zip"

    with zipfile.ZipFile(
        zip_file,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zipf:
        if findings_file.exists():
            zipf.write(findings_file, arcname=findings_file.name)

    # Post results to the Artifact API if configured
    api_url = settings.CSPM_URL
    if api_url:
        if not post_findings_to_api(api_url, zip_file):
            errors.append("findings upload to CSPM Backend failed")
            logger.error(f"Upload failed for {bucket_name}; findings kept locally at {findings_file}")
    else:
        logger.warning(f"CSPM_URL is not configured; findings kept locally at {findings_file}")

    # The JSON stays in FINDINGS_DIR as the local record; the archive is only the upload vehicle
    try:
        if zip_file.exists():
            zip_file.unlink(missing_ok=True)
            logger.info(f"Successfully removed ZIP file after upload attempt: {zip_file}")
    except Exception as e:
        logger.error(f"Failed to remove ZIP file {zip_file}: {str(e)}")

    return {
        "object_name": bucket_name,
        "object_type": object_type,
        "status": "success" if not errors else "error",
        "files_scanned": final_json["files_scanned"],
        "errors": errors,
    }


def parse_objects_to_scan() -> Dict[str, str]:
    """
    Parse the target objects and their types from environment variables.
    Supports JSON formats in OBJECTS_TO_SCAN, or fallback to OBJECT_NAME and OBJECT_TYPE.
    Example: {"bucket1": "s3", "bucket2": "s3"}
    """
    raw_env = settings.OBJECTS_TO_SCAN
    if not raw_env:
        raw_env = settings.OBJECT_NAME

    if raw_env:
        try:
            parsed = json.loads(raw_env)
            if isinstance(parsed, dict):
                return parsed
            elif isinstance(parsed, list):
                return {item: settings.OBJECT_TYPE or "s3" for item in parsed}
        except (json.JSONDecodeError, TypeError):
            pass

    # Fallback to single object if configured
    if settings.OBJECT_NAME:
        return {settings.OBJECT_NAME: settings.OBJECT_TYPE or "s3"}

    return {}


def lambda_handler(event: Dict[str, Any] = None, context: Any = None) -> Dict[str, Any]:
    """
    Handler entry point: scans every configured object, MAX_WORKERS at a time.
    """
    objects_dict = parse_objects_to_scan()
    if not objects_dict:
        logger.warning("No objects found to scan.")
        return {
            "statusCode": 200,
            "body": json.dumps({
                "status": "success",
                "message": "No objects to scan",
                "results": [],
            }),
        }

    # The Artifact API attributes S3 findings to an AWS account; database targets don't need one
    s3_targets = [name for name, obj_type in objects_dict.items() if str(obj_type).upper() in S3_OBJECT_TYPES]
    if s3_targets and not settings.AWS_ACCOUNT_ID:
        logger.error("AWS Account ID is not configured. Please configure it in settings.py")
        return {
            "statusCode": 400,
            "body": json.dumps({
                "status": "failed",
                "error": "AWS Account ID is not configured. Please configure it in settings.py",
            }),
        }

    logger.info(f"Target objects to scan: {objects_dict}")
    results = []

    # If only 1 object, process directly without spawning process pool overhead
    if len(objects_dict) == 1:
        obj_name, obj_type = next(iter(objects_dict.items()))
        results.append(process_bucket(obj_name, obj_type, settings.OBJECT_REGION))
    else:
        # Multiprocessing: process MAX_WORKERS objects at a time
        logger.info(f"Launching multiprocessing pool with max_workers={MAX_WORKERS}")
        with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(process_bucket, obj_name, obj_type, settings.OBJECT_REGION): obj_name
                for obj_name, obj_type in objects_dict.items()
            }
            for future in as_completed(futures):
                obj_name = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    logger.error(f"Scanning {obj_name} generated an exception: {exc}")
                    results.append({
                        "object_name": obj_name,
                        "status": "failed",
                        "error": str(exc),
                    })

    failed = [r for r in results if r.get("status") != "success"]
    return {
        "statusCode": 200 if not failed else 500,
        "body": json.dumps({
            "status": "success" if not failed else "error",
            "results": results,
        }),
    }


# Run-once mode when executed directly (python -m src.dspm_scanner_worker_handler,
# as the container CMD does). Importing the module never starts a scan: the Lambda
# runtime imports it under its real module name, so __name__ is never "__main__".
if __name__ == "__main__":
    result = lambda_handler(None, None)
    sys.exit(0 if result.get("statusCode") == 200 else 1)
