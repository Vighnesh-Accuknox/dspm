"""
Worker handler tests: the findings JSON must have the same layout whether the
target is an S3 bucket or a database, and failures must surface the same way.
Settings are patched so a developer .env never points the tests at real endpoints.
"""
import json
import os
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import settings
import src.dspm_scanner_worker_handler as handler

_NEUTRAL_SETTINGS = {
    "DB_URI": None, "DB_HOST": None, "DB_PORT": None, "DB_USERNAME": None, "DB_PASSWORD": None,
    "CSPM_URL": None, "ARTIFACT_TOKEN": None, "LABEL_ID": "test", "AWS_ACCOUNT_ID": None,
    "AWS_ACCESS_KEY_ID": None, "AWS_SECRET_ACCESS_KEY": None, "OBJECT_REGION": None,
    "OBJECTS_TO_SCAN": None, "OBJECT_NAME": None, "OBJECT_TYPE": None, "NER_ENABLED": False, "SAMPLE_STRATEGY": "head",
    "DISABLED_DETECTORS": [], "ALLOW_LIST": [], "ALLOW_REGEX": [], "COLUMN_RATIO": None, "MIN_COUNT": None,
    "AGGREGATION_THRESHOLD": 25, "SAMPLE_LIMIT": 10000, "REPORT_PRIVATE_IPS": False, "REPORT_TOKEN_LIKE_VALUES": False,
    "MIN_CONFIDENCE": "likely", "ADAPTIVE_SAMPLING": False,
}


def _isolated(**overrides):
    """Context stack: neutral settings (+overrides), temp FINDINGS_DIR, sqlite engine alias."""
    stack = ExitStack()
    for key, value in {**_NEUTRAL_SETTINGS, **overrides}.items():
        stack.enter_context(patch.object(settings, key, value))
    findings_dir = Path(tempfile.mkdtemp()) / "findings"
    stack.enter_context(patch.object(handler, "FINDINGS_DIR", findings_dir))
    stack.enter_context(patch.dict(handler.DB_OBJECT_TYPES, {"SQLITE": "sqlite"}))
    return stack, findings_dir


def _create_sqlite_db():
    from sqlalchemy import create_engine, text

    db_path = os.path.join(tempfile.mkdtemp(), "worker.db")
    conn_str = f"sqlite:///{db_path}"
    sa_engine = create_engine(conn_str)
    with sa_engine.begin() as conn:
        conn.execute(text("CREATE TABLE users (id INTEGER, email TEXT, password TEXT)"))
        conn.execute(text("INSERT INTO users VALUES (1, 'john.doe@accuknox.com', 'SuperSecret123!')"))
        conn.execute(text("CREATE TABLE settings (id INTEGER, flag TEXT)"))
        conn.execute(text("INSERT INTO settings VALUES (1, 'on')"))
    sa_engine.dispose()
    return conn_str


def _read_findings(findings_dir, name):
    files = list(findings_dir.glob(f"{name}-*.json"))
    assert len(files) == 1, files
    return json.loads(files[0].read_text())


def _fake_s3_scanner(files, scan_side_effect, errors=0):
    scanner = MagicMock()
    scanner.stats = {"objects_scanned": len(files), "errors": errors}
    scanner.list_all_files.return_value = files
    scanner.scan.side_effect = scan_side_effect
    return scanner


def test_worker_db_scan_layout():
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        print("        (skipped: sqlalchemy not installed)")
        return

    conn_str = _create_sqlite_db()
    stack, findings_dir = _isolated(DB_URI=conn_str)
    with stack:
        result = handler.process_bucket("testdb", "SQLITE")
        doc = _read_findings(findings_dir, "testdb")

    assert result["status"] == "success" and result["errors"] == []
    assert result["files_scanned"] == 2
    # One entry per relation, schema-qualified, clean ones included with []
    assert set(doc["findings"]) == {"main.users", "main.settings"}
    assert doc["findings"]["main.settings"] == []
    clubbed = doc["findings"]["main.users"]
    assert {c["name"] for c in clubbed} == {"Email", "Password Pattern"}
    for entry in clubbed:
        assert set(entry) == {"name", "type", "confidence", "finding_values", "total_count"}
        assert entry["confidence"] in ("likely", "very_likely")
        assert entry["total_count"] == 1
    assert doc["object_name"] == "testdb" and doc["object_type"] == "SQLITE"
    assert doc["account_id"] is None and doc["errors"] == []
    assert not list(findings_dir.glob("*.zip"))


def test_worker_s3_scan_layout():
    def fake_scan(target):
        key = target["key"]
        rid = f"arn:aws:s3:::{target['bucket']}/{key}"
        if key.endswith(".xlsx"):
            return [{
                "resource_id": f"{rid} [Employees]", "detector": "Email", "category": "PII",
                "severity": "medium", "value": "e@corp.com", "location": "Sheet 'Employees', Row 0, Column 'Contact'",
            }]
        if key == "clean.txt":
            return []
        return [{
            "resource_id": rid, "detector": "Credit Card", "category": "Financial Data",
            "severity": "high", "value": "4111", "location": "Line 1, Column 1-19",
        }]

    files = [
        {"Key": "data.xlsx", "Size": 10}, {"Key": "clean.txt", "Size": 5}, {"Key": "cards.txt", "Size": 20},
        {"Key": "huge.bin", "Size": 200 * 1024 * 1024}, {"Key": "empty.txt", "Size": 0},
    ]
    scanner = _fake_s3_scanner(files, fake_scan)
    stack, findings_dir = _isolated(AWS_ACCOUNT_ID="123456789012")
    with stack, patch.object(handler.boto3, "client") as boto_client, patch.object(handler, "S3Scanner", return_value=scanner):
        result = handler.process_bucket("my-bucket", "s3", "ap-south-1")
        doc = _read_findings(findings_dir, "my-bucket")

    assert boto_client.call_args.kwargs["region_name"] == "ap-south-1"
    assert result["status"] == "success" and result["files_scanned"] == 3
    # Same layout as the database case: one entry per scanned unit, clean ones with []
    assert set(doc["findings"]) == {"data.xlsx [Employees]", "clean.txt", "cards.txt"}
    assert doc["findings"]["clean.txt"] == []
    assert doc["findings"]["cards.txt"][0]["name"] == "Credit Card"
    assert doc["account_id"] == "123456789012"


def test_worker_scanner_errors_are_reported_for_both_connectors():
    # S3: per-object failures counted by the scanner become an error entry (status "error")
    scanner = _fake_s3_scanner([{"Key": "a.txt", "Size": 5}], lambda target: [], errors=2)
    stack, _ = _isolated(AWS_ACCOUNT_ID="123456789012")
    with stack, patch.object(handler.boto3, "client"), patch.object(handler, "S3Scanner", return_value=scanner):
        result = handler.process_bucket("bucket", "s3")
    assert result["status"] == "error"
    assert result["errors"] == ["2 error(s) during S3 scan, see logs"]

    # DB: an unreachable database is reported the same way
    stack, _ = _isolated(DB_URI="sqlite:////nonexistent-dir/none.db")
    with stack:
        result = handler.process_bucket("ghost", "SQLITE")
    assert result["status"] == "error"
    # the failing unit is named in the error so scan gaps are visible in the findings file
    assert len(result["errors"]) == 1
    assert result["errors"][0].startswith("1 error(s) during sqlite scan: connect:")

    # Either branch: an exception outside the scanner is captured, never raised
    stack, _ = _isolated()
    with stack, patch.object(handler, "SQLScanner", side_effect=RuntimeError("boom")):
        result = handler.process_bucket("db", "POSTGRES")
    assert result["errors"] == ["postgres scan failed: boom"]
    with stack, patch.object(handler.boto3, "client", side_effect=RuntimeError("no creds")):
        result = handler.process_bucket("bucket", "S3")
    assert result["errors"] == ["S3 scan failed: no creds"]


def test_worker_upload_contract_and_retries():
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        print("        (skipped: sqlalchemy not installed)")
        return

    conn_str = _create_sqlite_db()
    ok = MagicMock(status_code=200, text="created")
    stack, findings_dir = _isolated(DB_URI=conn_str, CSPM_URL="https://cspm.example.com/", ARTIFACT_TOKEN="tok", LABEL_ID="lbl")
    with stack, patch.object(handler.requests, "post", return_value=ok) as post:
        result = handler.process_bucket("testdb", "SQLITE")
    assert result["status"] == "success" and post.call_count == 1
    call = post.call_args.kwargs
    assert call["url"] == "https://cspm.example.com/api/v1/artifact/"
    assert call["params"] == {"data_type": "DSPM", "save_to_s3": "false", "label_id": "lbl"}
    assert call["headers"] == {"Authorization": "Bearer tok"}
    name, _, content_type = call["files"]["file"]
    assert name.startswith("testdb-") and name.endswith(".zip") and content_type == "application/zip"
    assert list(findings_dir.glob("testdb-*.json")) and not list(findings_dir.glob("*.zip"))

    down = MagicMock(status_code=503, text="down")
    stack, findings_dir = _isolated(DB_URI=conn_str, CSPM_URL="https://cspm.example.com/")
    with stack, patch.object(handler.requests, "post", return_value=down) as post, patch.object(handler.time, "sleep") as sleep:
        result = handler.process_bucket("testdb", "SQLITE")
    assert post.call_count == handler.UPLOAD_RETRIES
    assert [c.args[0] for c in sleep.call_args_list] == [2, 4]
    assert result["status"] == "error" and "upload to CSPM Backend failed" in result["errors"][0]
    assert list(findings_dir.glob("testdb-*.json")) and not list(findings_dir.glob("*.zip"))


def test_worker_target_parsing_and_guards():
    stack, _ = _isolated(OBJECTS_TO_SCAN='{"b1": "s3", "appdb": "postgres"}')
    with stack:
        assert handler.parse_objects_to_scan() == {"b1": "s3", "appdb": "postgres"}
    stack, _ = _isolated(OBJECTS_TO_SCAN='["b1", "b2"]', OBJECT_TYPE="S3")
    with stack:
        assert handler.parse_objects_to_scan() == {"b1": "S3", "b2": "S3"}
    stack, _ = _isolated(OBJECT_NAME="appdb", OBJECT_TYPE="POSTGRES")
    with stack:
        assert handler.parse_objects_to_scan() == {"appdb": "POSTGRES"}

    stack, _ = _isolated()
    with stack:
        response = handler.lambda_handler()
    assert response["statusCode"] == 200 and json.loads(response["body"])["message"] == "No objects to scan"

    # AWS_ACCOUNT_ID is only required when an S3 target is configured
    stack, _ = _isolated(OBJECT_NAME="b1", OBJECT_TYPE="s3")
    with stack:
        assert handler.lambda_handler()["statusCode"] == 400
    stack, _ = _isolated(OBJECT_NAME="thing", OBJECT_TYPE="ORACLE")
    with stack:
        response = handler.lambda_handler()
    body = json.loads(response["body"])
    assert response["statusCode"] == 500 and body["status"] == "error"
    assert "Unsupported object type 'ORACLE'" in body["results"][0]["errors"][0]


def test_env_settings_reach_the_scan_config():
    import importlib
    import os

    env = {
        "DISABLED_DETECTORS": "PII.IPAddress, MAC_ADDRESS", "ALLOW_LIST": '["support@acme-corp.io", "+91 80 4000 0000"]',
        "ALLOW_REGEX": '["@partner-example$"]', "COLUMN_RATIO": "0.6", "MIN_COUNT": "8", "AGGREGATION_THRESHOLD": "40",
        "SAMPLE_LIMIT": "2500", "MIN_CONFIDENCE": "very_likely", "SAMPLE_STRATEGY": "random", "NER_ENABLED": "false",
        "REPORT_PRIVATE_IPS": "true", "ENABLED_REGIONS": "US,IN",
    }
    with patch.dict(os.environ, env, clear=False):
        fresh = importlib.reload(settings)
    try:
        assert fresh.DISABLED_DETECTORS == ["PII.IPAddress", "MAC_ADDRESS"]
        assert fresh.ALLOW_LIST == ["support@acme-corp.io", "+91 80 4000 0000"] and fresh.ALLOW_REGEX == ["@partner-example$"]
        assert fresh.COLUMN_RATIO == 0.6 and fresh.MIN_COUNT == 8 and fresh.AGGREGATION_THRESHOLD == 40 and fresh.SAMPLE_LIMIT == 2500
        assert fresh.MIN_CONFIDENCE == "very_likely" and fresh.SAMPLE_STRATEGY == "random" and fresh.NER_ENABLED is False
        assert fresh.REPORT_PRIVATE_IPS is True and fresh.ENABLED_REGIONS == ["US", "IN"]
        config = handler.scan_config()
        assert config["disabled_detectors"] == ["PII.IPAddress", "MAC_ADDRESS"] and config["column_ratio"] == 0.6
        assert config["min_count"] == 8 and config["aggregation_threshold"] == 40 and config["min_confidence"] == "very_likely"
        assert config["sample_strategy"] == "random" and config["ner"] is False and config["report_private_ips"] is True
    finally:
        with patch.dict(os.environ, {k: "" for k in env}, clear=False):
            importlib.reload(settings)
    # defaults come back once the variables are unset
    assert settings.DISABLED_DETECTORS == [] and settings.COLUMN_RATIO is None and settings.MIN_CONFIDENCE == "likely"
