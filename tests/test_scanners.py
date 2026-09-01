import os
import tempfile
from unittest.mock import MagicMock, patch

from src.engine.detector import DetectionEngine
from src.scanners.aws.ddb import DynamoDBScanner
from src.scanners.aws.rds import RDSScanner
from src.scanners.aws.s3 import S3Scanner
from src.scanners.db.mongo import MongoScanner
from src.scanners.db.sql import SQLScanner


def _create_sqlite_db():
    """Creates a throwaway SQLite database with PII test rows, returns its connection string."""
    from sqlalchemy import create_engine, text

    db_path = os.path.join(tempfile.mkdtemp(), "test.db")
    conn_str = f"sqlite:///{db_path}"
    sa_engine = create_engine(conn_str)
    with sa_engine.begin() as conn:
        conn.execute(text("CREATE TABLE users (id INTEGER, email TEXT, password TEXT)"))
        conn.execute(
            text(
                "INSERT INTO users VALUES (1, 'john.doe@accuknox.com', 'SuperSecret123!')",
            ),
        )
    sa_engine.dispose()
    return conn_str


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


def test_sql_scanner():
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        print("        (skipped: sqlalchemy not installed)")
        return

    conn_str = _create_sqlite_db()

    engine = DetectionEngine()
    scanner = SQLScanner(engine)

    target = {"engine": "sqlite", "connection_string": conn_str, "database": "testdb"}
    findings = scanner.scan(target)

    assert len(findings) == 2
    detectors = [f["detector"] for f in findings]
    assert "Email" in detectors
    assert "Password Pattern" in detectors
    assert scanner.stats["tables_scanned"] == 1
    assert scanner.stats["rows_scanned"] == 1
    locations = [f["location"] for f in findings]
    assert any("Column 'email'" in loc for loc in locations)
    assert any("Column 'password'" in loc for loc in locations)


def test_sql_scanner_sample_limit():
    try:
        import sqlalchemy  # noqa: F401
        from sqlalchemy import create_engine, text
    except ImportError:
        print("        (skipped: sqlalchemy not installed)")
        return

    db_path = os.path.join(tempfile.mkdtemp(), "limit.db")
    conn_str = f"sqlite:///{db_path}"
    sa_engine = create_engine(conn_str)
    with sa_engine.begin() as conn:
        conn.execute(text("CREATE TABLE contacts (id INTEGER, email TEXT)"))
        for i in range(10):
            conn.execute(text(f"INSERT INTO contacts VALUES ({i}, 'user{i}@accuknox.com')"))
    sa_engine.dispose()

    engine = DetectionEngine()
    scanner = SQLScanner(engine)
    findings = scanner.scan({"engine": "sqlite", "connection_string": conn_str, "sample_limit": 3})

    assert scanner.stats["rows_scanned"] == 3
    assert len(findings) == 3


def test_rds_scanner():
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        print("        (skipped: sqlalchemy not installed)")
        return

    conn_str = _create_sqlite_db()

    engine = DetectionEngine()
    scanner = RDSScanner(engine)

    target = {
        "engine": "sqlite",
        "connection_string": conn_str,
        "host": "mydb.xyz.us-east-1.rds.amazonaws.com",
        "database": "production",
    }
    findings = scanner.scan(target)

    assert len(findings) == 2
    for f in findings:
        assert f["resource_id"].startswith("arn:aws:rds:db:mydb.xyz.us-east-1.rds.amazonaws.com/production")


def test_sql_scanner_aggregation():
    try:
        import sqlalchemy  # noqa: F401
        from sqlalchemy import create_engine, text
    except ImportError:
        print("        (skipped: sqlalchemy not installed)")
        return

    db_path = os.path.join(tempfile.mkdtemp(), "agg.db")
    conn_str = f"sqlite:///{db_path}"
    sa_engine = create_engine(conn_str)
    with sa_engine.begin() as conn:
        conn.execute(text("CREATE TABLE contacts (id INTEGER, email TEXT)"))
        for i in range(30):
            conn.execute(text(f"INSERT INTO contacts VALUES ({i}, 'user{i}@accuknox.com')"))
    sa_engine.dispose()

    engine = DetectionEngine()
    scanner = SQLScanner(engine)
    findings = scanner.scan({"engine": "sqlite", "connection_string": conn_str})

    # 30 hits in one (detector, column) pair collapse into a single column-level finding
    assert len(findings) == 1
    assert findings[0]["aggregated"] is True
    assert findings[0]["occurrences"] == 30
    assert findings[0]["column"] == "email"
    assert "(30 matches)" in findings[0]["location"]

    # threshold 0 disables aggregation
    scanner = SQLScanner(engine, config={"aggregation_threshold": 0})
    findings = scanner.scan({"engine": "sqlite", "connection_string": conn_str})
    assert len(findings) == 30


def test_sql_scanner_column_suppression():
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        print("        (skipped: sqlalchemy not installed)")
        return

    conn_str = _create_sqlite_db()
    engine = DetectionEngine()

    scanner = SQLScanner(engine, config={"column_suppression": {"Email": "email"}})
    findings = scanner.scan({"engine": "sqlite", "connection_string": conn_str})
    detectors = [f["detector"] for f in findings]
    assert "Email" not in detectors
    assert "Password Pattern" in detectors



def test_mongo_scanner():
    # Mock pymongo client: one user database next to system databases
    coll_mock = MagicMock()
    coll_mock.find.return_value.limit.return_value = [
        {
            "_id": "user-1",
            "email": "carol.smith@yahoo.com",
            "profile": {"work_email": "carol@zoho.com"},
            "api_key": "sk_live_abcdef1234567890", # pragma: allowlist secret
        },
    ]

    db_mock = MagicMock()
    db_mock.list_collection_names.return_value = ["users", "system.indexes"]
    db_mock.__getitem__.return_value = coll_mock

    client_mock = MagicMock()
    client_mock.list_database_names.return_value = ["appdb", "admin", "local", "config"]
    client_mock.__getitem__.return_value = db_mock

    engine = DetectionEngine()
    scanner = MongoScanner(engine, client=client_mock)

    findings = scanner.scan({"host": "mongo.local"})

    detectors = [f["detector"] for f in findings]
    assert "Email" in detectors
    assert "API Key" in detectors

    # Nested fields are reported with their dotted path
    locations = [f["location"] for f in findings]
    assert any("Field 'profile.work_email'" in loc for loc in locations)

    # System databases and system.* collections are skipped
    for f in findings:
        assert f["resource_id"] == "mongodb://mongo.local/appdb/users"
    assert scanner.stats["collections_scanned"] == 1
    assert scanner.stats["documents_scanned"] == 1


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


@patch("src.scanners.files.parsers.pd")
@patch("boto3.client")
def test_s3_scanner_excel_per_sheet(mock_boto_client, mock_pd):
    # Mock pandas ExcelFile parsing
    mock_excel_file = MagicMock()
    mock_excel_file.sheet_names = ["Employees", "Credentials"]

    import pandas as _real_pd
    # Mock dataframes for the two sheets
    df_sheet1 = MagicMock()
    df_sheet1.columns = ["Name", "Contact"]
    df_sheet1.__getitem__.side_effect = lambda col: ["Alice", "alice@accuknox.com"] if col == "Contact" else ["Alice", "Bob"]

    df_sheet2 = MagicMock()
    df_sheet2.columns = ["Service", "Secret"]
    df_sheet2.__getitem__.side_effect = lambda col: ["MySecretPass123!"] if col == "Secret" else ["AWS"]

    def parse_sheet(sheet_name, **kwargs):
        if sheet_name == "Employees":
            return df_sheet1
        return df_sheet2

    mock_excel_file.parse.side_effect = parse_sheet
    mock_pd.isna.side_effect = lambda x: False
    mock_pd.ExcelFile.return_value = mock_excel_file

    engine = DetectionEngine()
    scanner = S3Scanner(engine)

    target = {"bucket": "test-bucket", "key": "data.xlsx"}
    findings = scanner.scan(target)

    assert len(findings) == 2
    resource_ids = [f["resource_id"] for f in findings]
    assert "arn:aws:s3:::test-bucket/data.xlsx [Employees]" in resource_ids
    assert "arn:aws:s3:::test-bucket/data.xlsx [Credentials]" in resource_ids


def test_sql_scanner_iter_scan():
    # Per-relation results: every relation is yielded (clean ones with []),
    # names are schema-qualified and scan() is the concatenation of iter_scan()
    try:
        import sqlalchemy  # noqa: F401
        from sqlalchemy import create_engine, text
    except ImportError:
        print("        (skipped: sqlalchemy not installed)")
        return

    db_path = os.path.join(tempfile.mkdtemp(), "iter.db")
    conn_str = f"sqlite:///{db_path}"
    sa_engine = create_engine(conn_str)
    with sa_engine.begin() as conn:
        conn.execute(text("CREATE TABLE users (id INTEGER, email TEXT, password TEXT)"))
        conn.execute(text("INSERT INTO users VALUES (1, 'john.doe@accuknox.com', 'SuperSecret123!')"))
        conn.execute(text("CREATE TABLE settings (id INTEGER, flag TEXT)"))
        conn.execute(text("INSERT INTO settings VALUES (1, 'on')"))
    sa_engine.dispose()

    engine = DetectionEngine()
    target = {"engine": "sqlite", "connection_string": conn_str, "database": "testdb"}

    scanner = SQLScanner(engine)
    units = {name: (resource_id, findings) for resource_id, name, findings in scanner.iter_scan(target)}

    assert set(units) == {"main.users", "main.settings"}
    assert units["main.settings"][1] == []
    assert units["main.users"][0] == "sqlite://localhost/testdb/main.users"
    assert {f["detector"] for f in units["main.users"][1]} == {"Email", "Password Pattern"}
    assert scanner.stats["tables_scanned"] == 2

    assert len(SQLScanner(engine).scan(target)) == 2


def test_sql_scanner_repeated_value_per_row():
    # A value repeated across rows keeps one finding per row (with its own location),
    # exactly as the S3 CSV/Excel parsers report it; aggregation handles hot columns
    try:
        import sqlalchemy  # noqa: F401
        from sqlalchemy import create_engine, text
    except ImportError:
        print("        (skipped: sqlalchemy not installed)")
        return

    db_path = os.path.join(tempfile.mkdtemp(), "dup.db")
    conn_str = f"sqlite:///{db_path}"
    sa_engine = create_engine(conn_str)
    with sa_engine.begin() as conn:
        conn.execute(text("CREATE TABLE contacts (id INTEGER, email TEXT)"))
        for i in range(3):
            conn.execute(text(f"INSERT INTO contacts VALUES ({i}, 'dup@accuknox.com')"))
    sa_engine.dispose()

    findings = SQLScanner(DetectionEngine()).scan({"engine": "sqlite", "connection_string": conn_str})
    emails = [f for f in findings if f["detector"] == "Email"]
    assert len(emails) == 3
    assert len({f["location"] for f in emails}) == 3


def test_rds_scanner_reader_routing():
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        print("        (skipped: sqlalchemy not installed)")
        return

    conn_str = _create_sqlite_db()
    target = {
        "engine": "sqlite",
        "connection_string": conn_str,
        "host": "writer.rds.amazonaws.com",
        "reader_endpoint": "reader.rds.amazonaws.com",
        "use_reader": True,
        "database": "production",
    }
    units = list(RDSScanner(DetectionEngine()).iter_scan(target))
    assert [name for _, name, _ in units] == ["main.users"]
    assert units[0][0] == "arn:aws:rds:db:reader.rds.amazonaws.com/production/main.users"
    assert len(units[0][2]) == 2


def test_mongo_scanner_iter_scan():
    users_coll = MagicMock()
    users_coll.find.return_value.limit.return_value = [
        {"_id": "user-1", "email": "carol.smith@yahoo.com"},
    ]
    audit_coll = MagicMock()
    audit_coll.find.return_value.limit.return_value = [{"_id": "evt-1", "status": "ok"}]

    db_mock = MagicMock()
    db_mock.list_collection_names.return_value = ["users", "audit", "system.indexes"]
    db_mock.__getitem__.side_effect = lambda name: {"users": users_coll, "audit": audit_coll}[name]

    client_mock = MagicMock()
    client_mock.list_database_names.return_value = ["appdb", "admin", "local", "config"]
    client_mock.__getitem__.return_value = db_mock

    engine = DetectionEngine()

    # Pinned database: names are collection-relative, clean collections are yielded with []
    scanner = MongoScanner(engine, client=client_mock)
    units = list(scanner.iter_scan({"host": "mongo.local", "database": "appdb"}))
    assert [name for _, name, _ in units] == ["users", "audit"]
    assert units[0][0] == "mongodb://mongo.local/appdb/users"
    assert [f["detector"] for f in units[0][2]] == ["Email"]
    assert units[1][2] == []
    assert scanner.stats["collections_scanned"] == 2

    # No pinned database: names are database-qualified
    units = list(MongoScanner(engine, client=client_mock).iter_scan({"host": "mongo.local"}))
    assert [name for _, name, _ in units] == ["appdb.users", "appdb.audit"]


def test_mongo_uri_direct_connection_for_port_forwards():
    scanner = MongoScanner(DetectionEngine(), client=MagicMock())
    assert scanner._build_uri({"host": "127.0.0.1", "port": 27017}).endswith("?directConnection=true")
    assert scanner._build_uri({"host": "localhost"}).endswith("?directConnection=true")
    assert "directConnection" not in scanner._build_uri({"host": "mongo.internal", "port": 27017})
    assert scanner._build_uri({"host": "mongo.internal", "direct_connection": True}).endswith("?directConnection=true")
    assert "directConnection" not in scanner._build_uri({"host": "127.0.0.1", "direct_connection": False})


def test_sql_random_sampling_uses_tablesample_on_postgres():
    from sqlalchemy import column as sql_column, select, table as sql_table
    from sqlalchemy.dialects import postgresql

    scanner = SQLScanner(DetectionEngine(), config={"sample_strategy": "random"})
    fake_engine = MagicMock()
    fake_engine.dialect.name = "postgresql"
    conn = fake_engine.connect.return_value.__enter__.return_value
    conn.execute.return_value.scalar.return_value = 5_000_000
    relation = sql_table("users", sql_column("id"), sql_column("email"), schema="public")
    source = scanner._random_sample_source(fake_engine, relation, "public", "users", 10000)
    compiled = str(select(source).limit(10000).compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    assert "TABLESAMPLE system(0.6)" in compiled and "LIMIT 10000" in compiled
    # small tables and other engines read the head
    conn.execute.return_value.scalar.return_value = 1500
    assert scanner._random_sample_source(fake_engine, relation, "public", "users", 10000) is None
    fake_engine.dialect.name = "mysql"
    assert scanner._random_sample_source(fake_engine, relation, "public", "users", 10) is None
    # sqlite scans are unchanged under the random strategy
    conn_str = _create_sqlite_db()
    findings = scanner.scan({"engine": "sqlite", "connection_string": conn_str, "sample_strategy": "random"})
    assert {f["detector"] for f in findings} == {"Email", "Password Pattern"}


def test_mongo_random_sampling_uses_sample_stage():
    coll_mock = MagicMock()
    coll_mock.aggregate.return_value = [{"_id": "u1", "email": "carol.smith@yahoo.com"}]
    db_mock = MagicMock()
    db_mock.list_collection_names.return_value = ["users"]
    db_mock.__getitem__.return_value = coll_mock
    client_mock = MagicMock()
    client_mock.__getitem__.return_value = db_mock

    scanner = MongoScanner(DetectionEngine(), config={"sample_strategy": "random"}, client=client_mock)
    findings = scanner.scan({"host": "mongo.local", "database": "appdb", "sample_limit": 500})
    assert [f["detector"] for f in findings] == ["Email"]
    pipeline = coll_mock.aggregate.call_args.args[0]
    assert pipeline == [{"$sample": {"size": 500}}]
    coll_mock.find.assert_not_called()
