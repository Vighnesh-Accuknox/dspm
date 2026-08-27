"""
    Use this file for AWS Credentials and other Secrets.
    Automatically loads values from a .env file in the project root if present.
"""
import os
from pathlib import Path

# Load .env file into environment variables before reading them
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _key, _, _val = _line.partition("=")
                os.environ.setdefault(_key.strip(), _val.strip())

# AWS Credentials
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", None)
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", None)
CSPM_URL = os.environ.get("CSPM_URL", None)
ARTIFACT_TOKEN = os.environ.get("ARTIFACT_TOKEN", None)
OBJECT_TYPE = os.environ.get("OBJECT_TYPE", None)
OBJECT_NAME = os.environ.get("OBJECT_NAME", None)
OBJECT_REGION = os.environ.get("OBJECT_REGION", None)
DSPM_TOKEN = os.environ.get("DSPM_TOKEN", None)
SCANNING_OBJECT_TYPE = os.environ.get("SCANNING_OBJECT_TYPE", "LAMBDA")  # EC2|LAMBDA
