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
OBJECTS_TO_SCAN=os.environ.get("OBJECTS_TO_SCAN", None)
AWS_ACCOUNT_ID=os.environ.get("AWS_ACCOUNT_ID", None)
LABEL_ID=os.environ.get("LABEL_ID", "test")
OBJECT_REGION=os.environ.get("OBJECT_REGION", None)
