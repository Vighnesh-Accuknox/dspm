import os
import tempfile
from unittest.mock import MagicMock, patch

from src.engine.detector import DetectionEngine
from src.scanners.aws.ddb import DynamoDBScanner
from src.scanners.aws.rds import RDSScanner
from src.scanners.aws.s3 import S3Scanner


@patch("boto3.client")
def test_s3_scanner(mock_boto_client):
    # Mock S3 download_file to create a local text file with test data
    def mock_download(bucket, key, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("Admin password: SecretPassword123!\n")
            f.write("User email: john.doe@accuknox.com\n")

    s3_mock = MagicMock()
    s3_mock.download_file.side_effect = mock_download
    mock_boto_client.return_value = s3_mock

    engine = DetectionEngine()
    scanner = S3Scanner(engine)

    target = {"bucket": "test-bucket", "key": "test-data.txt"}
    findings = scanner.scan(target)

    assert len(findings) == 2
    detectors = [f["detector"] for f in findings]
    assert "Password Pattern" in detectors
    assert "Email" in detectors


# @patch("src.scanners.rds.create_engine")
# @patch("src.scanners.rds.inspect")
# def test_rds_scanner(mock_inspect, mock_create_engine):
#     # Mock SQLAlchemy engine, connection and inspection
#     mock_engine = MagicMock()
#     mock_create_engine.return_value = mock_engine

#     # Mock Inspector
#     mock_inspector = MagicMock()
#     mock_inspector.get_schema_names.return_value = ["public"]
#     mock_inspector.get_table_names.return_value = ["users"]
#     mock_inspector.get_view_names.return_value = []
#     mock_inspector.get_columns.return_value = [
#         {"name": "id", "type": "INTEGER"},
#         {"name": "email", "type": "VARCHAR"},
#         {"name": "password", "type": "VARCHAR"}
#     ]
#     mock_inspect.return_value = mock_inspector

#     # Mock connection execution returning a row
#     mock_conn = MagicMock()
#     mock_engine.connect.return_value.__enter__.return_value = mock_conn

#     mock_result = MagicMock()
#     # Mock row data: id=1, email="test@email.com", password="SecretPassword123"
#     mock_result.fetchall.side_effect = [
#         [(1, "test@email.com", "SecretPassword123")], # first call returns users
#         [] # second call returns empty
#     ]
#     mock_conn.execute.return_value = mock_result

#     engine = DetectionEngine()
#     scanner = RDSScanner(engine)

#     target = {
#         "engine": "postgres",
#         "host": "localhost",
#         "port": 5432,
#         "username": "user",
#         "password": "pwd",
#         "database": "db"
#     }

#     findings = scanner.scan(target)

#     assert len(findings) == 2
#     detectors = [f["detector"] for f in findings]
#     assert "Email" in detectors
#     assert "Password Pattern" in detectors


@patch("boto3.client")
def test_dynamodb_scanner(mock_boto_client):
    # Mock boto3 DynamoDB client and pagination
    ddb_mock = MagicMock()
    mock_boto_client.return_value = ddb_mock

    mock_paginator = MagicMock()
    ddb_mock.get_paginator.return_value = mock_paginator

    # Mock pages: one page containing user items
    mock_paginator.paginate.return_value = [
        {
            "Items": [
                {
                    "PK": {"S": "USER#1"},
                    "Email": {"S": "alice@email.com"},
                    "APIKey": {"S": "api_key:abcdef1234567890abcdef"},
                },
            ],
        },
    ]

    engine = DetectionEngine()
    scanner = DynamoDBScanner(engine)

    target = {"table_name": "users-table"}
    findings = scanner.scan(target)

    assert len(findings) == 2
    detectors = [f["detector"] for f in findings]
    assert "Email" in detectors
    assert "API Key" in detectors


def test_dynamodb_stream_scanner():
    engine = DetectionEngine()
    scanner = DynamoDBScanner(engine)

    # Mock stream records
    stream_records = [
        {
            "eventName": "INSERT",
            "eventSourceARN": "arn:aws:dynamodb:us-east-1:123456789012:table/users-table/stream/2026-06-28",
            "dynamodb": {
                "Keys": {"PK": {"S": "USER#2"}},
                "NewImage": {
                    "PK": {"S": "USER#2"},
                    "Email": {"S": "bob@email.com"},
                    "Secret": {"S": "Password: MySecurePassword!"},
                },
            },
        },
    ]

    findings = scanner.scan_stream_records(stream_records)

    assert len(findings) == 2
    detectors = [f["detector"] for f in findings]
    assert "Email" in detectors
    assert "Password Pattern" in detectors


@patch("boto3.client")
def test_s3_scanner_single_line_multiple_instances(mock_boto_client):
    def mock_download(bucket, key, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "Some code here AKIA1234567890ABCDEF and later AKIA9876543210FEDCBA in same file\n",
            )

    s3_mock = MagicMock()
    s3_mock.download_file.side_effect = mock_download
    mock_boto_client.return_value = s3_mock

    engine = DetectionEngine()
    scanner = S3Scanner(engine)

    target = {"bucket": "test-bucket", "key": "minified.js"}
    findings = scanner.scan(target)

    assert len(findings) == 2
    locations = [f["location"] for f in findings]
    assert any("Column 16-" in loc for loc in locations)
    assert any("Column 47-" in loc for loc in locations)
