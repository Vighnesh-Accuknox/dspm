"""
    All configuration is environment-driven so images stay credential-free.
    Values are loaded from a .env file in the project root if present
    (real environment variables always take precedence over .env entries).
    Never hardcode secrets in this file: it is baked into the Docker image.
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


def _bool_env(name: str, default: str = "false") -> bool:
    value = os.environ.get(name)
    if value is None or not value.strip():
        value = default  # empty placeholder values fall back to the safe default
    return value.strip().lower() in ("1", "true", "yes")


# AWS Credentials (optional: falls back to instance profile / IRSA when unset)
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", None)
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", None)
AWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", None)  # required for S3 targets; recorded in the findings

# CSPM backend (findings are uploaded to <CSPM_URL>/api/v1/artifact/)
CSPM_URL = os.environ.get("CSPM_URL", None)
ARTIFACT_TOKEN = os.environ.get("ARTIFACT_TOKEN", None)
LABEL_ID = os.environ.get("LABEL_ID", "test")

# Scan targets: OBJECTS_TO_SCAN is a JSON object {"name": "type", ...} (or a JSON list of
# names that all use OBJECT_TYPE); falls back to the single OBJECT_NAME/OBJECT_TYPE pair
OBJECTS_TO_SCAN = os.environ.get("OBJECTS_TO_SCAN", None)
OBJECT_TYPE = os.environ.get("OBJECT_TYPE", None)
OBJECT_NAME = os.environ.get("OBJECT_NAME", None)
OBJECT_REGION = os.environ.get("OBJECT_REGION", None)  # AWS region for the S3 client

# Database scan settings (used when OBJECT_TYPE is MONGODB|POSTGRES|MYSQL|MARIADB|MSSQL;
# OBJECT_NAME holds the database name to scan)
DB_URI = os.environ.get("DB_URI", None)  # full connection string/URI, overrides the fields below
DB_HOST = os.environ.get("DB_HOST", None)
DB_PORT = os.environ.get("DB_PORT", None)
DB_USERNAME = os.environ.get("DB_USERNAME", None)
DB_PASSWORD = os.environ.get("DB_PASSWORD", None)

# Scanner behaviour
LOG_QUERIES = True  # every query issued during DB scans is logged
REPORT_TOKEN_LIKE_VALUES = _bool_env("REPORT_TOKEN_LIKE_VALUES", "true")  # random tokens with no field/keyword evidence -> Secret.TokenLikeValue
_threshold = os.environ.get("SCORE_THRESHOLD", "").strip()
SCORE_THRESHOLD = float(_threshold) if _threshold else 0.9  # minimum detection confidence to report
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", None)  # findings/work dir; default <repo>/output

# Regional compliance packs, comma-separated (US, IN, CA, GB)
_regions = os.environ.get("ENABLED_REGIONS", "US,IN,GB")
ENABLED_REGIONS = [
    "GB" if r.strip().upper() == "UK" else r.strip().upper()
    for r in _regions.split(",") if r.strip()
]
