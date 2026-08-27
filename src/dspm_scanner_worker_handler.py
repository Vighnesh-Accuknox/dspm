import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent.parent

OUTPUT_DIR = BASE_DIR / "output"
FINDINGS_DIR = OUTPUT_DIR / "findings"
S3_BUCKETS_DIR = OUTPUT_DIR / "s3buckets"

FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
S3_BUCKETS_DIR.mkdir(parents=True, exist_ok=True)

import zipfile
from datetime import datetime

import boto3
import requests

import settings
from src.engine.detector import DetectionEngine
# from src.scanners.aws.rds import RDSScanner
from src.scanners.aws.ddb import DynamoDBScanner
from src.scanners.aws.s3 import S3Scanner
from src.utils.aws import get_secret
from src.utils.logger import get_logger

logger = get_logger("handler")


def post_findings_to_api(api_url: str, object_name: str):
    """
    HTTP POST request to upload findings to the Artifact API / CSPM Backend.
    """

    if not api_url:
        return

    try:
        token = settings.DSPM_TOKEN

        logger.info(f"Sending findings to CSPM Backend")
        headers = {"Authorization": f"Bearer {token}"}

        findings_file = FINDINGS_DIR / f"{object_name}.zip"

        with open(findings_file, "rb") as zip_file:
            resp = requests.post(
                url=f"{settings.CSPM_URL}api/v1/dspm/upload",
                headers=headers,
                files={"file": zip_file},
            )

        logger.info(f"Upload response status: {resp.status_code}")
        logger.info(f"Upload response body: {resp.text}")

    except Exception as e:
        logger.error(f"Failed to post findings to Artifact API: {str(e)}")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler entry point.
    """

    # loading environment variables
    object_type = settings.OBJECT_TYPE
    object_name = settings.OBJECT_NAME
    object_region = settings.OBJECT_REGION

    logger.info(f"Scanning {object_type}")

    config = {"enabled_regions": ["US", "IN", "UK"]}

    engine = DetectionEngine(config=config)

    findings_file = FINDINGS_DIR / f"{object_name}.json"

    if object_type == "S3":
        logger.info("Creating S3 Client instance")
        # Create AWS clients
        s3_client = boto3.client(
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            service_name="s3",
        )

        s3scanner = S3Scanner(engine, config, s3_client)

        files = s3scanner.list_all_files(bucket=object_name)

        bucket_file = S3_BUCKETS_DIR / f"{object_name}.json"

        with bucket_file.open("w") as file:
            json.dump(files, file, indent=4, default=str)

        start_time = datetime.now()

        final_json = {
            "scan_time": start_time,
            "files_scanned": 0,
            "object_type": object_type,
            "object_name": object_name,
            "time_taken": None,
            "findings": [],
        }

        for file in files:
            file_size = file.get("Size", None)
            file_key = file.get("Key", None)

            if (file_size and file_size < 100 * 1024 * 1024) and file_key:
                target = {
                    "bucket": object_name,
                    "key": file_key,
                    "version_id": file.get("VersionId", None),
                    "last_modified": file.get("LastModified", None),
                }
                findings_for_file = s3scanner.scan(target)
                final_json["findings"].append({file_key: findings_for_file})
                final_json["files_scanned"] += 1
                with findings_file.open("w") as f:
                    json.dump(final_json, f, indent=4, default=str)
            else:
                logger.info(f"Skipping file {file_key} with size {file_size}")

        end_time = datetime.now()
        final_json["time_taken"] = str(end_time - start_time)

        with findings_file.open("w") as f:
            json.dump(final_json, f, indent=4, default=str)

        logger.info(f"Time taken for scanning {object_name}: {end_time - start_time}")
    else:
        pass

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
            logger.info(
                f"Successfully removed the JSON file after compression: {findings_file}",
            )
    except Exception as e:
        logger.error(f"Failed to remove JSON file {findings_file}: {str(e)}")

    # Post results to Artifact API if configured in environments/config
    api_url = settings.CSPM_URL
    logger.info(f"API URL: {api_url}")

    if api_url:
        post_findings_to_api(api_url, object_name)
    else:
        logger.error(
            "API URL or API Key is not configured. Please configure it in settings.py",
        )

    return {
        "statusCode": 200,
        "body": json.dumps(
            {"status": "success", "files scanned": final_json["files_scanned"]},
        ),
    }


if settings.SCANNING_OBJECT_TYPE == "EC2":
    lambda_handler(None, None)
