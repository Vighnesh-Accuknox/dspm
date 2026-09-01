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


def _list_env(name: str) -> list:
    """A JSON list ('["a", "b"]') or a comma-separated list ('a, b'); empty -> []."""
    import json

    value = (os.environ.get(name) or "").strip()
    if not value:
        return []
    if value.startswith("["):
        try:
            parsed = json.loads(value)
            return [str(item).strip() for item in parsed if str(item).strip()]
        except ValueError:
            pass
    return [item.strip() for item in value.split(",") if item.strip()]


def _number_env(name: str, default, cast=float):
    value = (os.environ.get(name) or "").strip()
    if not value:
        return default
    try:
        return cast(value)
    except ValueError:
        return default


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

# Scanner behaviour (see .env.example for the recommended values and README "Classification")
LOG_QUERIES = True  # every query issued during DB scans is logged
REPORT_TOKEN_LIKE_VALUES = _bool_env("REPORT_TOKEN_LIKE_VALUES", "false")  # random tokens with no field/keyword evidence -> Secret.TokenLikeValue
# Lowest confidence tier reported: possible | likely | very_likely. The legacy SCORE_THRESHOLD
# float is still accepted (0.9 -> very_likely, 0.8 -> likely, lower -> possible).
MIN_CONFIDENCE = os.environ.get("MIN_CONFIDENCE", "").strip() or os.environ.get("SCORE_THRESHOLD", "").strip() or "likely"
REPORT_PRIVATE_IPS = _bool_env("REPORT_PRIVATE_IPS", "false")  # RFC 1918 / loopback / link-local addresses as PII.IPAddress
DISABLED_DETECTORS = _list_env("DISABLED_DETECTORS")  # detector names never reported (see fixtures/findings-mapping.json)
ALLOW_LIST = _list_env("ALLOW_LIST")  # exact values never reported (public contact addresses, known sample data)
ALLOW_REGEX = _list_env("ALLOW_REGEX")  # JSON list of regexes over values never reported
COLUMN_RATIO = _number_env("COLUMN_RATIO", None, float)  # share of a column's values that classifies it; None -> per-detector policy (0.5)
MIN_COUNT = _number_env("MIN_COUNT", None, int)  # distinct `possible` hits per unit that become `likely`; None -> per-detector policy (10)
AGGREGATION_THRESHOLD = _number_env("AGGREGATION_THRESHOLD", 25, int)  # hits per (detector, column) that collapse into one finding; 0 disables
SAMPLE_LIMIT = _number_env("SAMPLE_LIMIT", 10000, int)  # rows / documents read per table or collection
SAMPLE_STRATEGY = os.environ.get("SAMPLE_STRATEGY", "head").strip().lower() or "head"  # head | random (TABLESAMPLE / $sample)
ADAPTIVE_SAMPLING = _bool_env("ADAPTIVE_SAMPLING", "false")  # stop reading a table/collection once its column verdicts settle
NER_ENABLED = _bool_env("NER_ENABLED", "true")  # person names in prose when the optional spaCy model is installed (requirements-ner.txt)
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", None)  # findings/work dir; default <repo>/output

# Regional compliance packs, comma-separated (US, IN, CA, GB)
_regions = os.environ.get("ENABLED_REGIONS", "US,IN,GB")
ENABLED_REGIONS = [
    "GB" if r.strip().upper() == "UK" else r.strip().upper()
    for r in _regions.split(",") if r.strip()
]
