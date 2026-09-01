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

1. **Worker** (`src/dspm_scanner_worker_handler.py`) — scans whole resources (buckets and/or databases) configured via environment variables; several targets are scanned two at a time. This is what the Docker image runs.

   ```bash
   python -m src.dspm_scanner_worker_handler
   ```

   Findings are written to `output/findings/<OBJECT_NAME>-<YYYY-MM-DD>.json` (one file per target) and uploaded as a zip archive to `CSPM_URL` if configured. The JSON has the same layout for buckets and databases: `findings` holds one entry per scanned object key, `schema.table` or collection (an empty list when it is clean), and `files_scanned` counts them.

2. **Master** (`src/dspm_scanner_master_handler.py`) — AWS Lambda handler that scans one target per invocation payload (also accepts SQS-wrapped payloads, S3 event notifications, and DynamoDB Stream batches).

---

## Worker mode — environment variables per connector

### Common (all connectors)

| Variable | Required | Description |
|---|---|---|
| `OBJECT_TYPE` | yes* | Selects the connector, see sections below |
| `OBJECT_NAME` | yes* | S3 bucket name, or database name for the DB connectors |
| `OBJECTS_TO_SCAN` | no | Several targets at once: a JSON object `{"name": "type", ...}` (e.g. `{"bucket-a": "s3", "appdb": "postgres"}`) or a JSON list of names that all use `OBJECT_TYPE`. Overrides `OBJECT_NAME`/`OBJECT_TYPE` (\* not needed when set) |
| `CSPM_URL` | no | CSPM backend base URL; findings upload is skipped when unset |
| `ARTIFACT_TOKEN` | with `CSPM_URL` | Bearer token for the findings upload (`api/v1/artifact/`) |
| `LABEL_ID` | no | Label the uploaded findings are filed under in the CSPM backend, default `test` |
| `OBJECT_REGION` | no | AWS region for the S3 client (applies to every S3 target) |
| `ENABLED_REGIONS` | no | Comma-separated regional compliance packs, default `US,IN,GB` (valid: `US`, `CA`, `GB`, `DE`, `SE`, `FI`, `PL`, `ES`, `IT`, `TR`, `IN`, `SG`, `AU`, `KR`, `TH`, `ZA`, `NG`, `PH`; `UK` is accepted as an alias for `GB`). Also used as the regions for national-format phone numbers |
| `REPORT_TOKEN_LIKE_VALUES` | no | `false` (default): random-looking tokens with no supporting evidence (credential-named field, `key=`/`token:` keyword, known format) are dropped; `true` reports them as `Secret.TokenLikeValue` (Medium) |
| `SCORE_THRESHOLD` | no | Minimum detection confidence, default `0.8` (see *Detection engine* below) |
| `OUTPUT_DIR` | no | Findings/work directory. Default `<repo>/output`; the container image sets `/app/output` — point it at a mounted volume to persist findings |

### S3

| Variable | Required | Description |
|---|---|---|
| `OBJECT_TYPE` | yes | `S3` |
| `OBJECT_NAME` | yes | Bucket name |
| `AWS_ACCOUNT_ID` | yes | Account that owns the bucket(s); recorded in the findings and required by the CSPM backend |
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

> Reaching a replica set through `kubectl port-forward` / an SSH tunnel: the members advertise cluster-internal hostnames (`…rs0-0.…svc.cluster.local`) that do not resolve locally, so topology discovery fails with *Could not reach any servers*. The scanner adds `directConnection=true` automatically when `DB_HOST` is `localhost`/`127.0.0.1`; with `DB_URI`, append `?directConnection=true` yourself.

> DynamoDB is currently only available through the master handler, not through worker mode.

### Example `.env` (PostgreSQL)

```bash
OBJECT_TYPE=POSTGRES
OBJECT_NAME=appdb
DB_HOST=127.0.0.1
DB_PORT=5432
DB_USERNAME=scanner
DB_PASSWORD=secret
CSPM_URL=https://cspm.example.com/
ARTIFACT_TOKEN=eyJ...
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
| `enabled_regions` | `[]` | Regional compliance packs (ISO alpha-2): `US`, `CA`, `GB`, `DE`, `SE`, `FI`, `PL`, `ES`, `IT`, `TR`, `IN`, `SG`, `AU`, `KR`, `TH`, `ZA`, `NG`, `PH` — 80+ national identifiers (SSN/ITIN/passport/driver licence, NHS/NINO, Aadhaar/PAN/GST/voter ID, PESEL, fiscal codes, ID cards, tax ids, health insurance numbers, …) |
| `phone_regions` | `enabled_regions` | Regions used to parse national-format phone numbers (`5678942315` in a `mobile` field); international `+…` numbers are always detected |
| `chunk_size` | 5000 (SQL) / 1000 (Mongo) | Rows/documents fetched per batch |
| `connect_timeout` | 10 | Connection timeout in seconds (SQL and Mongo) |
| `log_queries` | `false` (worker mode: always on) | Log every query issued during DB scans (dialect-compiled SQL with bound values, Mongo filters, DynamoDB scans). Note: emits table/column names into logs |
| `last_scan_time` | – | S3 only: skip objects not modified since this timestamp |
| `aggregation_threshold` | `25` | DB scans: a (detector, column) pair firing on at least this many rows/documents collapses into one column-level finding with an `occurrences` count. `0` disables |
| `score_threshold` | `0.8` | Minimum confidence a finding needs to be reported |
| `field_suppression` | `true` | Structural field-name rules: token detectors never fire in `*_id`/`hash`/`etag`/`path`/… fields, digit-run detectors never fire in counter/timestamp fields. Corroborated findings are exempt |
| `decode_base64` | `true` | Decode base64 blobs (`Authorization: Basic …`, base64 JSON, PEM) and scan the plaintext |
| `entropy_report_uncorroborated` | `false` | Report random-looking tokens that have no supporting evidence as `Secret.TokenLikeValue` (Medium) instead of dropping them |
| `disabled_detectors` | `[]` | Detector names never reported |
| `report_private_ips` | `false` | Report RFC 1918 / loopback / link-local addresses as `PII.IPAddress`; by default only public IPs count |
| `direct_connection` | auto | MongoDB: add `directConnection=true` to the built URI. Automatic for `localhost`/`127.0.0.1`, i.e. port-forwarded replica sets whose members advertise cluster-internal hostnames |
| `column_suppression` | id/hash rule for entropy | Scanner-level escape hatch: per-detector regexes of column/field names to skip on top of the engine's own field rules. Pass `{}` to disable, or your own `{detector: regex}` map |
| `entropy_min_length` | `24` | Minimum token length for the entropy detector |
| `entropy_min_entropy` | `4.5` | Shannon-entropy threshold for base64-shaped tokens (hex tokens use 3.0 and need 32+ chars) |

## Detection engine

`src/engine/` turns each cell / document field / file chunk into findings. Every scan gets the text **and the field name** it came from (`DetectionEngine.scan_text(text, field_name=...)`) — in structured data the field name is the strongest signal there is, and it is never mixed into the scanned text.

**Scoring.** Every detector produces a confidence and only findings above `score_threshold` (0.8) are reported:

| Score | Meaning | Examples |
|---|---|---|
| 0.95 | self-validating **and** corroborated | JWT with a decodable header, checksum-valid national id next to its context word, vendor-prefixed token, opaque value in a credential-named column |
| 0.85 | self-validating alone | valid e-mail (IANA TLD, no demo/automated sender), Luhn + issuer prefix **with separators**, structured street address, Verhoeff-valid Aadhaar |
| 0.6 | plausible shape, needs evidence | contiguous digit runs, BIC-shaped 8-letter words, header-only private keys |
| 0.3 | documented example / test value | `AKIAIOSFODNN7EXAMPLE`, `4111 1111 1111 1111`, `hunter2` in advisory text |

**Checksums are not enough on their own.** A mod-10/mod-11 checksum passes ~10 % of random numbers, so a bare, separator-free match of a checksum-only recognizer (NPI, NHS, ABA, DEA, Aadhaar…) needs a context word or a field hint; epoch timestamps are never identifiers; private/loopback IPs are infrastructure, not PII (`report_private_ips`).

**Evidence.** Context words are detector-specific whole words near the match (`ssn`, `aadhaar`, `swift`, `card`, `password=`) or in the field name; generic words (`code`, `state`, `number`, `identity`, `key`) no longer count. Checksums (Luhn, Verhoeff, mod-97, mod-11, …) decide national ids, IBANs and cards. The entropy detector classifies token *shape* first — paths, URLs, ARNs, UUIDs, dates, slugs and word-built identifiers are never secrets — and then needs evidence (credential field, inline `token:`/`secret=` keyword, known vendor format); base64 `Salted__` blobs are reported as `Encrypted Secret`, base64 PEM as private keys, JWT claims are scanned for PII.

**One finding per span.** Overlapping matches are resolved by specificity: a JWT is not also a bearer token and two entropy blobs, a card number is not also a bank account, an IBAN is not also a BIC.

**Field-name rules** (`src/engine/context.py`): credential-named fields (`token`, `secret_key`, `authorization`, `cookie`, `webhook_url`, …) classify their value as a credential whatever its entropy; identifier fields (`*_id`, `hash`, `etag`, `if-none-match`, `path`, `references`, …) never yield token findings; counter/timestamp fields never yield card/id numbers; `full_name`/`first_name` fields yield `PII.PersonName`; `mobile`/`phone` fields enable national-format phone parsing.

**Output.** Every finding carries a `value_hash` (sha256 prefix) for correlating the same value across scans; reported values are capped at 200 characters.

**Recognizer packs.** `src/engine/recognizers/` holds 90 country-specific and generic recognizers as native `Rule` objects (`src/engine/rules.py`: pattern scores, context words, validators/invalidators; test vectors in `tests/test_recognizers_*.py`). Rules are grouped by region pack; generic ones (IBAN, crypto wallets, IP, MAC) always run, `URL`/`UUID` are shipped disabled.

**Regression corpus.** `tests/fixtures/detection_corpus.json` is an anonymised corpus built from real Postgres/Mongo scans: 370+ reviewed false positives that must stay silent and 160+ true positives that must stay detected (`tests/test_regression_corpus.py`).

## TLS to databases

- **SQL engines**: pass DBAPI options via the target's `connect_args` (master mode), e.g. `{"sslmode": "verify-full", "sslrootcert": "/certs/rds-ca.pem"}` for PostgreSQL — or put them on the DSN: `DB_URI=postgresql+psycopg2://user:pass@host:5432/db?sslmode=require`. # pragma: allowlist secret
- **MongoDB / DocumentDB**: use URI parameters: `DB_URI=mongodb://user:pass@host:27017/?tls=true&tlsCAFile=/certs/global-bundle.pem` (DocumentDB requires TLS with the Amazon CA bundle). # pragma: allowlist secret
- Mount the CA bundle into the container (e.g. via a ConfigMap/Secret volume) and reference it by path.

## Deployment (OpenShift / Kubernetes)

`deploy/openshift-cronjob.yaml` contains a CronJob + Secret template that runs under the restricted SCC: the image runs as a non-root arbitrary UID (group-0 writable `/app`), takes all credentials from a Secret, and writes findings to an `emptyDir` mounted at `OUTPUT_DIR`.

Running the worker (`python -m src.dspm_scanner_worker_handler`, which is the image's `CMD`) always performs one scan run and exits; the exit code reflects the result — `0` when every target was scanned and uploaded successfully, `1` on scan errors, unsupported `OBJECT_TYPE`, or upload failure (details in the logs and in the `errors` field of the findings JSON) — so failed Jobs are visible in Kubernetes. The findings JSON stays in `OUTPUT_DIR/findings/`; the zip archive is only the upload vehicle and is removed after the upload attempt.

## Tests

```bash
python run_tests.py
```
