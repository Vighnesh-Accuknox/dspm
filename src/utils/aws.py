import json

import boto3

from src.utils.logger import get_logger

logger = get_logger(__name__)


def get_secret(secret_arn_or_name: str, region_name: str = None) -> dict:
    """
    Retrieves a JSON secret from AWS Secrets Manager.
    """
    try:
        client = (
            boto3.client("secretsmanager", region_name=region_name)
            if region_name
            else boto3.client("secretsmanager")
        )
        response = client.get_secret_value(SecretId=secret_arn_or_name)

        if "SecretString" in response:
            return json.loads(response["SecretString"])
        elif "SecretBinary" in response:
            import base64

            decoded = base64.b64decode(response["SecretBinary"]).decode("utf-8")
            return json.loads(decoded)
    except Exception as e:
        logger.error(f"Failed to retrieve secret '{secret_arn_or_name}': {str(e)}")

    return {}
