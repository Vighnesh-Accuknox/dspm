import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent.parent

FINDINGS_DIR = BASE_DIR / "output"

import zipfile
from datetime import datetime

import boto3
import requests

import settings
from src.engine.detector import DetectionEngine
from src.utils.logger import get_logger
# from src.scanners.aws.rds import RDSScanner
from src.scanners.aws.ddb import DynamoDBScanner
from src.scanners.aws.s3 import S3Scanner
from src.utils.aws import get_secret
import boto3
import requests
from concurrent.futures import ProcessPoolExecutor, as_completed

logger = get_logger("handler")

# Create the folder if doesn't exist
FINDINGS_DIR.mkdir(parents=True, exist_ok=True)


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

        grouped[key]["total_count"] += 1

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


def post_findings_to_api(api_url: str, object_name: str, time: datetime) -> None:
    """
    HTTP POST request to upload findings to the Artifact API / CSPM Backend.
    Matches:
    curl --location '<CSPM_URL>/api/v1/artifact/?data_type=DSPM&save_to_s3=false&label_id=test' \
         --header 'Authorization: Bearer <DSPM_TOKEN>' \
         --form 'file=@<findings.zip>'
    """
    if not api_url:
        return

    try:
        token = settings.ARTIFACT_TOKEN
        label_id = settings.LABEL_ID or "test"

        #  URL ensuring clean trailing slash before query params
        base_url = api_url.rstrip("/")
        endpoint_url = f"{base_url}/api/v1/artifact/"

        params = {
            "data_type": "DSPM",
            "save_to_s3": "false",
            "label_id": label_id,
        }
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        findings_file = FINDINGS_DIR / f"{object_name}-{time}.zip"

        if not findings_file.exists():
            logger.error(f"Findings zip file {findings_file} does not exist for upload.")
            return

        logger.info(f"Sending findings for {object_name} to CSPM Backend: {endpoint_url} with params {params}")

        with open(findings_file, "rb") as zip_file:
            resp = requests.post(
                url=endpoint_url,
                params=params,
                headers=headers,
                files={"file": (findings_file.name, zip_file, "application/zip")},
            )

        logger.info(f"Upload response status for {object_name}: {resp.status_code}")
        logger.info(f"Upload response body for {object_name}: {resp.text}")

    except Exception as e:
        logger.error(f"Failed to post findings to Artifact API for {object_name}: {str(e)}")


def process_bucket(bucket_name: str, object_type: str = "s3", object_region: str = None) -> Dict[str, Any]:
    """
    Process scan for a single bucket/target.
    """
    logger.info(f"Starting scan for object: {bucket_name} (type: {object_type})")

    config = {
        "enabled_regions": ['US', 'IN', 'UK'],
    }

    time = datetime.today().date()

    engine = DetectionEngine(config=config)
    findings_file = FINDINGS_DIR / f"{bucket_name}-{time}.json"

    final_json = {
        "scan_time": datetime.now(),
        "files_scanned": 0,
        "object_type": object_type,
        "object_name": bucket_name,
        "account_id": settings.AWS_ACCOUNT_ID,
        "time_taken": None,
        "findings": {},
    }

    if object_type.lower() in ["s3", "s3bucket"]:
        logger.info(f"Creating S3 Client instance for {bucket_name}")
        client_kwargs = {
            "aws_secret_access_key": settings.AWS_SECRET_ACCESS_KEY,
            "aws_access_key_id": settings.AWS_ACCESS_KEY_ID,
            "service_name": "s3",
        }
        if object_region:
            client_kwargs["region_name"] = object_region

        s3_client = boto3.client(**client_kwargs)
        s3scanner = S3Scanner(engine, config, s3_client)

        try:
            files = s3scanner.list_all_files(bucket=bucket_name)
        except Exception as e:
            logger.error(f"Failed to list files in bucket {bucket_name}: {str(e)}")
            files = []

        start_time = datetime.now()

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
                        final_json['findings'][file_key] = []
                    else:
                        for sheet_entry_key, s_findings in sheet_findings_map.items():
                            clubbed = club_findings(s_findings)
                            final_json['findings'][sheet_entry_key] = clubbed
                else:
                    clubbed = club_findings(raw_findings_for_file)
                    final_json['findings'][file_key] = clubbed

                final_json['files_scanned'] += 1
                with findings_file.open("w") as f:
                    json.dump(final_json, f, indent=4, default=str)
            else:
                logger.info(f"Skipping file {file_key} with size {file_size}")

        end_time = datetime.now()
        final_json["time_taken"] = str(end_time - start_time)

        with findings_file.open("w") as f:
            json.dump(final_json, f, indent=4, default=str)

        logger.info(f"Time taken for scanning {bucket_name}: {end_time - start_time}")
    else:
        logger.warning(f"Unsupported object type '{object_type}' for {bucket_name}")

    # Zip findings file
    logger.info(f"Zipping findings for {bucket_name} before sending to Artifact API")
    zip_file = FINDINGS_DIR / f"{bucket_name}-{time}.zip"

    with zipfile.ZipFile(
        zip_file,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zipf:
        if findings_file.exists():
            zipf.write(findings_file, arcname=findings_file.name)


    # Post results to Artifact API if configured
    api_url = settings.CSPM_URL
    if api_url:
        post_findings_to_api(api_url, bucket_name, time)
    else:
        logger.error("API URL is not configured in settings.py")

    try:
        # if findings_file.exists():
        #     findings_file.unlink(missing_ok=True)
        #     logger.info(f"Successfully removed JSON file after compression: {findings_file}")
        if zip_file.exists():
            zip_file.unlink(missing_ok=True)
            logger.info(f"Successfully removed ZIP file after compression: {zip_file}")
    except Exception as e:
        logger.error(f"Failed to remove files {findings_file} or {zip_file}: {str(e)}")

    return {
        "object_name": bucket_name,
        "status": "success",
        "files_scanned": final_json['files_scanned'],
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
    Handler entry point supporting multiprocessing for 2 buckets at a time.
    """
    if not settings.AWS_ACCOUNT_ID:
        logger.error("AWS Account ID is not configured. Please configure it in settings.py")
        return {
            "statusCode": 400,
            "body": json.dumps({
                "status": "failed",
                "error": "AWS Account ID is not configured. Please configure it in settings.py",
            }),
        }

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

    logger.info(f"Target objects to scan: {objects_dict}")
    results = []

    # If only 1 object, process directly without spawning process pool overhead
    if len(objects_dict) == 1:
        obj_name, obj_type = next(iter(objects_dict.items()))
        res = process_bucket(obj_name, obj_type, settings.OBJECT_REGION)
        results.append(res)
    else:
        # Multiprocessing: Process 2 buckets at a time
        max_workers = 2
        logger.info(f"Launching multiprocessing pool with max_workers={max_workers}")
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(process_bucket, obj_name, obj_type, settings.OBJECT_REGION): obj_name
                for obj_name, obj_type in objects_dict.items()
            }
            for future in as_completed(futures):
                obj_name = futures[future]
                try:
                    res = future.result()
                    results.append(res)
                except Exception as exc:
                    logger.error(f"Scanning {obj_name} generated an exception: {exc}")
                    results.append({
                        "object_name": obj_name,
                        "status": "failed",
                        "error": str(exc),
                    })

    return {
        "statusCode": 200,
        "body": json.dumps({
            "status": "success",
            "results": results,
        }),
    }


if __name__ == "__main__":
    lambda_handler(None, None)
