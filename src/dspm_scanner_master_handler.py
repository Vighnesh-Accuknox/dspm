import json
import urllib.request
from typing import Any, Dict, List

import settings
from src.engine.detector import DetectionEngine
# from src.scanners.aws.rds import RDSScanner
from src.scanners.aws.ddb import DynamoDBScanner
from src.scanners.aws.s3 import S3Scanner
from src.utils.aws import get_secret
from src.utils.logger import get_logger

logger = get_logger("handler")


def post_findings_to_api(
    api_url: str,
    findings: List[Dict[str, Any]],
    api_key: str = None,
):
    """
    HTTP POST request to upload findings to the Artifact API / CSPM Backend.
    """
    if not api_url or not findings:
        return

    logger.info(f"Sending {len(findings)} findings to Artifact API at {api_url}")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        data = json.dumps({"findings": findings}).encode("utf-8")
        req = urllib.request.Request(api_url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as response:
            res_body = response.read().decode("utf-8")
            logger.info(
                f"Artifact API responded with status {response.status}: {res_body}",
            )
    except Exception as e:
        logger.error(f"Failed to post findings to Artifact API: {str(e)}")


def process_single_event(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Helper to process a single scan payload target.
    """
    scan_type = event.get("scan_type", "").lower()
    target = event.get("target", {})
    config = event.get("config", {})

    engine = DetectionEngine(config)

    if scan_type == "s3":
        scanner = S3Scanner(engine, config)
        return scanner.scan(target)

    # elif scan_type in ["rds", "aurora"]:
    #     # Retrieve credentials from Secrets Manager if password_secret is specified
    #     secret_arn = target.get("password_secret")
    #     if secret_arn:
    #         secret_data = get_secret(secret_arn)
    #         if secret_data:
    #             target["username"] = target.get("username") or secret_data.get("username")
    #             target["password"] = target.get("password") or secret_data.get("password")
    #             target["host"] = target.get("host") or secret_data.get("host")
    #             target["port"] = target.get("port") or secret_data.get("port")
    #             target["database"] = target.get("database") or secret_data.get("database")

    #     scanner = RDSScanner(engine, config)
    #     return scanner.scan(target)

    elif scan_type == "dynamodb":
        scanner = DynamoDBScanner(engine, config)
        return scanner.scan(target)

    else:
        logger.warning(f"Unknown or unsupported scan type: '{scan_type}'")
        return []


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler entry point.
    """
    logger.info(f"Received Lambda invocation event: {json.dumps(event)}")
    findings = []

    # 1. Check for SQS event wrapper
    if "Records" in event and event["Records"] and "body" in event["Records"][0]:
        logger.info(
            f"Processing event as SQS queue message batch (size: {len(event['Records'])})",
        )
        for record in event["Records"]:
            try:
                body = json.loads(record["body"])
                # SQS events might wrap actual S3/DDB notifications or manual invoke payloads
                findings.extend(lambda_handler(body, context).get("findings", []))
            except Exception as e:
                logger.error(f"Error parsing SQS record: {str(e)}")

    # 2. Check for DynamoDB Streams record batch
    elif "Records" in event and event["Records"] and "dynamodb" in event["Records"][0]:
        logger.info("Processing event as DynamoDB Streams CDC triggers")
        engine = DetectionEngine()
        scanner = DynamoDBScanner(engine)
        findings = scanner.scan_stream_records(event["Records"])

    # 3. Check for direct S3 bucket event notifications
    elif "Records" in event and event["Records"] and "s3" in event["Records"][0]:
        logger.info("Processing event as S3 ObjectCreated notification")
        for record in event["Records"]:
            try:
                s3_data = record["s3"]
                bucket = s3_data["bucket"]["name"]
                key = s3_data["object"]["key"]

                # Check for object delete/restoration if needed, or simply scan
                engine = DetectionEngine()
                scanner = S3Scanner(engine)
                findings.extend(scanner.scan({"bucket": bucket, "key": key}))
            except Exception as e:
                logger.error(f"Error handling S3 notification record: {str(e)}")

    # 4. Direct invoke / Baseline Scan / Cron scan
    else:
        logger.info("Processing event as direct/manual scanning payload")
        findings = process_single_event(event)

    # Post results to Artifact API if configured in environments/config
    api_url = settings.CSPM_URL
    api_key = settings.ARTIFACT_TOKEN
    if api_url and api_key:
        post_findings_to_api(api_url, findings, api_key)
    else:
        logger.error(
            "API URL or API Key is not configured. Please configure it in settings.py",
        )

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "status": "success",
                "findings_count": len(findings),
                "findings": findings,
            },
        ),
    }
