# dspm

DSPM scanner: discovers sensitive data (PII, credentials & secrets, financial, healthcare, regional-compliance identifiers) in cloud data stores and posts findings to the CSPM backend.

Supported connectors: **S3, PostgreSQL, MySQL, MariaDB, MSSQL, MongoDB/DocumentDB, DynamoDB, RDS/Aurora**.

## Setup

```bash
python -m venv venv && ./venv/bin/pip install -r requirements.txt
```

Configuration is read from environment variables (a `.env` file in the project root is loaded automatically by `settings.py`).

## Running

There are two entry points:

1. **Worker** (`src/dspm_scanner_worker_handler.py`) — scans one whole resource (a bucket or a database) configured via environment variables. This is what the Docker image runs.

   ```bash
   python -m src.dspm_scanner_worker_handler
   ```

   Findings are written to `output/findings/<OBJECT_NAME>.zip` and uploaded to `CSPM_URL` if configured.

2. **Master** (`src/dspm_scanner_master_handler.py`) — AWS Lambda handler that scans one target per invocation payload (also accepts SQS-wrapped payloads, S3 event notifications, and DynamoDB Stream batches).

---

## Worker mode — environment variables per connector

### Common (all connectors)

| Variable | Required | Description |
|---|---|---|
| `SCANNING_OBJECT_TYPE` | yes (for CLI/Docker) | `EC2` runs the scan immediately on start; `LAMBDA` (default) only registers the handler |
| `OBJECT_TYPE` | yes | Selects the connector, see sections below |
| `OBJECT_NAME` | yes | S3 bucket name, or database name for the DB connectors |
| `CSPM_URL` | no | CSPM backend base URL; findings upload is skipped when unset |
| `DSPM_TOKEN` | with `CSPM_URL` | Bearer token for the findings upload (`api/v1/dspm/upload`) |
| `OBJECT_REGION` | no | Reserved; not currently used by any connector |
| `LOG_QUERIES` | no | `true`/`1`/`yes` logs every query issued during DB scans (SQL statements, Mongo filters, DynamoDB scans). Default `false` |
| `ENABLED_REGIONS` | no | Comma-separated regional compliance packs, default `US,IN,GB` (valid: `US`, `IN`, `CA`, `GB`; `UK` is accepted as an alias for `GB`) |
| `OUTPUT_DIR` | no | Findings/work directory. Default `<repo>/output`; the container image sets `/app/output` — point it at a mounted volume to persist findings |

### S3

| Variable | Required | Description |
|---|---|---|
| `OBJECT_TYPE` | yes | `S3` |
| `OBJECT_NAME` | yes | Bucket name |
| `AWS_ACCESS_KEY_ID` | yes | IAM credentials with `s3:ListBucket` + `s3:GetObject` |
| `AWS_SECRET_ACCESS_KEY` | yes | |

Objects larger than 100 MB are skipped. Archives (`.zip/.tar/.gz/.bz2`) are unpacked and scanned recursively; CSV/TSV, Parquet, Excel, JSON, XML, PDF, DOCX and images (OCR) have dedicated parsers, everything else falls back to plain-text scanning.

### PostgreSQL / MySQL / MariaDB / MSSQL

| Variable | Required | Description |
|---|---|---|
| `OBJECT_TYPE` | yes | `POSTGRES` (or `POSTGRESQL`), `MYSQL`, `MARIADB`, `MSSQL` (or `SQLSERVER`) |
| `OBJECT_NAME` | yes | Database name to scan |
| `DB_HOST` | yes* | Database host |
| `DB_PORT` | yes* | Typical defaults: 5432 (postgres), 3306 (mysql/mariadb), 1433 (mssql) |
| `DB_USERNAME` | yes* | A read-only account is sufficient and recommended |
| `DB_PASSWORD` | yes* | |
| `DB_URI` | no | Full SQLAlchemy connection string, e.g. `postgresql+psycopg2://user:pass@host:5432/db`. Overrides all `DB_*` fields above (\* not needed when `DB_URI` is set) | # pragma: allowlist secret

Drivers used: `psycopg2` (postgres), `PyMySQL` (mysql/mariadb), `pymssql` (mssql). All non-system schemas of the database are discovered and scanned, up to 10 000 rows per table.

### MongoDB / DocumentDB

| Variable | Required | Description |
|---|---|---|
| `OBJECT_TYPE` | yes | `MONGODB` (or `MONGO`, `DOCUMENTDB`) |
| `OBJECT_NAME` | yes | Database name to scan |
| `DB_HOST` | yes* | MongoDB host |
| `DB_PORT` | yes* | Typically 27017 |
| `DB_USERNAME` | no* | Omit for unauthenticated instances |
| `DB_PASSWORD` | no* | |
| `DB_URI` | no | Full MongoDB URI, e.g. `mongodb://user:pass@host:27017/?authSource=admin`. Overrides all `DB_*` fields above (\* not needed when `DB_URI` is set) |. # pragma: allowlist secret

All non-`system.*` collections of the database are discovered and scanned, up to 10 000 documents per collection. Documents are walked recursively; nested fields are reported with dotted paths.

> DynamoDB is currently only available through the master handler, not through worker mode.

### Example `.env` (PostgreSQL)

```bash
SCANNING_OBJECT_TYPE=EC2
OBJECT_TYPE=POSTGRES
OBJECT_NAME=appdb
DB_HOST=127.0.0.1
DB_PORT=5432
DB_USERNAME=scanner
DB_PASSWORD=secret
CSPM_URL=https://cspm.example.com/
DSPM_TOKEN=eyJ...
```

---

## Master mode — payload fields per connector

Invocation payload shape:

```json
{
  "scan_type": "...",
  "target": { ... },
  "config": { "enabled_regions": ["US", "IN"] }
}
```

`ARTIFACT_TOKEN` + `CSPM_URL` environment variables control the findings upload in this mode.

### `scan_type: "s3"`

| Target field | Required | Description |
|---|---|---|
| `bucket` | yes | Bucket name |
| `key` | yes | Object key |
| `version_id` | no | Specific object version |
| `last_modified` | no | With `config.last_scan_time`, enables skip-if-unchanged |

### `scan_type: "postgres" | "postgresql" | "mysql" | "mariadb" | "mssql" | "sqlserver"`

| Target field | Required | Description |
|---|---|---|
| `host`, `port` | yes* | Database endpoint |
| `username`, `password` | yes* | Credentials |
| `database` | yes* | Database name |
| `connection_string` | no | Full SQLAlchemy DSN; overrides the fields above (\*) |
| `password_secret` | no | AWS Secrets Manager ARN/name; fills any missing `username/password/host/port/database/uri` |
| `schema` | no | Restrict to one schema (default: all non-system schemas) |
| `tables` | no | Restrict to specific tables, plain or schema-qualified: `["users", "sales.orders"]` |
| `include_views` | no | Also scan views (default `false`) |
| `incremental_column` | no | Timestamp column for incremental scans |
| `last_scan_time` | no | Only rows where `incremental_column > last_scan_time` are scanned |
| `sample_limit` | no | Max rows per table (default 10000) |

### `scan_type: "rds" | "aurora"`

Same fields as the SQL engines above (set `engine` to one of `postgres/mysql/mariadb/mssql`), plus:

| Target field | Required | Description |
|---|---|---|
| `engine` | yes | Database engine of the RDS instance |
| `reader_endpoint` | no | Aurora reader endpoint |
| `use_reader` | no | Route the scan to `reader_endpoint` |

### `scan_type: "mongo" | "mongodb" | "documentdb"`

| Target field | Required | Description |
|---|---|---|
| `host`, `port` | yes* | MongoDB endpoint (port defaults to 27017) |
| `username`, `password` | no* | Omit for unauthenticated instances |
| `uri` | no | Full MongoDB URI; overrides the fields above (\*) |
| `password_secret` | no | AWS Secrets Manager ARN/name, as for SQL |
| `database` | no | Restrict to one database (default: all non-system databases) |
| `collection` | no | Restrict to one collection (default: all non-`system.*` collections) |
| `incremental_field` | no | Field for incremental scans, with `last_scan_time` |
| `last_scan_time` | no | Only documents where `incremental_field > last_scan_time` |
| `sample_limit` | no | Max documents per collection (default 10000) |

### `scan_type: "dynamodb"`

| Target field | Required | Description |
|---|---|---|
| `table_name` | yes | DynamoDB table name |
| `region` | no | AWS region (default from environment) |
| `sample_limit` | no | Max items (default 10000) |

Uses ambient AWS credentials (Lambda role / environment). DynamoDB Stream CDC batches are handled automatically when the Lambda is wired to a stream.

### `config` keys (all scan types)

| Key | Default | Description |
|---|---|---|
| `enabled_regions` | `[]` | Regional compliance packs: `US`, `IN`, `CA`, `GB` (SSN, Aadhaar/PAN/GST, SIN, NINO) |
| `chunk_size` | 5000 (SQL) / 1000 (Mongo) | Rows/documents fetched per batch |
| `connect_timeout` | 10 | Connection timeout in seconds (SQL and Mongo) |
| `log_queries` | `false` | Log every query issued during DB scans (dialect-compiled SQL with bound values, Mongo filters, DynamoDB scans). Note: emits table/column names into logs |
| `last_scan_time` | – | S3 only: skip objects not modified since this timestamp |
| `aggregation_threshold` | `25` | DB scans: a (detector, column) pair firing on at least this many rows/documents collapses into one column-level finding with an `occurrences` count. `0` disables |
| `column_suppression` | id/hash rule for entropy | Per-detector regexes of column/field names to skip (default: entropy findings in `*_id`/`hash`/`arn`-style columns). Pass `{}` to disable, or your own `{detector: regex}` map |
| `entropy_min_length` | `24` | Minimum token length for the entropy detector |
| `entropy_min_entropy` | `4.5` | Shannon-entropy threshold for the entropy detector |

## TLS to databases

- **SQL engines**: pass DBAPI options via the target's `connect_args` (master mode), e.g. `{"sslmode": "verify-full", "sslrootcert": "/certs/rds-ca.pem"}` for PostgreSQL — or put them on the DSN: `DB_URI=postgresql+psycopg2://user:pass@host:5432/db?sslmode=require`. # pragma: allowlist secret
- **MongoDB / DocumentDB**: use URI parameters: `DB_URI=mongodb://user:pass@host:27017/?tls=true&tlsCAFile=/certs/global-bundle.pem` (DocumentDB requires TLS with the Amazon CA bundle). # pragma: allowlist secret
- Mount the CA bundle into the container (e.g. via a ConfigMap/Secret volume) and reference it by path.

## Deployment (OpenShift / Kubernetes)

`deploy/openshift-cronjob.yaml` contains a CronJob + Secret template that runs under the restricted SCC: the image runs as a non-root arbitrary UID (group-0 writable `/app`), takes all credentials from a Secret, and writes findings to an `emptyDir` mounted at `OUTPUT_DIR`.

In `SCANNING_OBJECT_TYPE=EC2` (run-once) mode the process exit code reflects the result — `0` when the scan and upload succeeded, `1` on scan errors, unsupported `OBJECT_TYPE`, or upload failure (details in the logs and in the `errors` field of the findings JSON) — so failed Jobs are visible in Kubernetes. The findings archive is deleted after a successful upload and kept locally when the upload fails.

## Tests

```bash
python run_tests.py
```
