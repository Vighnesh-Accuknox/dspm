# dspm

DSPM scanner: discovers sensitive data (PII, credentials & secrets, financial, healthcare, regional-compliance identifiers) in cloud data stores and posts findings to the CSPM backend.

Supported connectors: **S3, PostgreSQL, MySQL, MariaDB, MSSQL, MongoDB/DocumentDB, DynamoDB, RDS/Aurora**.

## Setup

```bash
python -m venv venv && ./venv/bin/pip install -r requirements.txt
```

Configuration is read from environment variables (a `.env` file in the project root is loaded automatically by `settings.py`). `.env.example` lists every variable with the recommended production values — `cp .env.example .env` and fill in the targets and credentials.

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
| `REPORT_TOKEN_LIKE_VALUES` | no | `false` (default): random-looking tokens with no supporting evidence (credential-named field, `key=`/`token:` keyword, known format) are dropped; `true` keeps them as `possible` candidates reported as `Secret.TokenLikeValue` (Medium) when a whole column is made of them |
| `MIN_CONFIDENCE` | no | Lowest confidence tier reported: `possible`, `likely` (default) or `very_likely` (see *Classification* below). The legacy `SCORE_THRESHOLD` float is still accepted (`0.9` → `very_likely`, `0.8` → `likely`, lower → `possible`) |
| `ADAPTIVE_SAMPLING` | no | `false` (default). `true` stops reading a table/collection once its column verdicts have settled (see *Sampling*) |
| `SAMPLE_STRATEGY` | no | `head` (default): the first `SAMPLE_LIMIT` rows/documents. `random`: `TABLESAMPLE` on PostgreSQL/MSSQL tables larger than twice the limit, `$sample` on MongoDB, head elsewhere (see *Sampling*) |
| `SAMPLE_LIMIT` | no | Rows / documents read per table or collection, default `10000` |
| `NER_ENABLED` | no | `true` (default): person names in free text through spaCy; `false` skips the model |
| `NER_MODEL` | no | `en_core_web_trf` (transformer, best accuracy — the default when installed) or `en_core_web_sm` (12 MB, ~40× faster per cell); both ship in `requirements.txt` |
| `REPORT_PRIVATE_IPS` | no | `false` (default): RFC 1918 / loopback / link-local addresses are infrastructure, not `PII.IPAddress` |
| `DISABLED_DETECTORS` | no | Detector names never reported (comma-separated or JSON list), e.g. `PII.IPAddress,MAC_ADDRESS` |
| `ALLOW_LIST` / `ALLOW_REGEX` | no | Macie-style exceptions: exact values (comma-separated or JSON list) / JSON list of regexes over values that are never findings |
| `COLUMN_RATIO` / `MIN_COUNT` | no | Override every detector's column-classification share (policy default `0.5`) / distinct-`possible`-hits promotion count (policy default `10`); empty keeps the per-detector policies |
| `AGGREGATION_THRESHOLD` | no | Hits per (detector, column) that collapse into one column-level finding, default `25`; `0` disables |
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
| `enabled_regions` | `[]` | Regional compliance packs (ISO alpha-2), 62 packs: `AE`, `AR`, `AT`, `AU`, `BE`, `BG`, `BR`, `CA`, `CH`, `CL`, `CN`, `CZ`, `DE`, `DK`, `EE`, `EG`, `ES`, `FI`, `FR`, `GB`, `GH`, `GR`, `HK`, `HR`, `HU`, `ID`, `IE`, `IL`, `IN`, `IS`, `IT`, `JP`, `KR`, `LK`, `LT`, `LU`, `LV`, `MX`, `MY`, `NG`, `NL`, `NO`, `NZ`, `PH`, `PK`, `PL`, `PT`, `RO`, `RS`, `RU`, `SA`, `SE`, `SG`, `SI`, `SK`, `TH`, `TR`, `TW`, `UA`, `US`, `VN`, `ZA` — national ids, tax numbers, passports, driver licences, health identifiers with their public check-digit algorithms |
| `phone_regions` | `enabled_regions` | Regions used to parse national-format phone numbers (`5678942315` in a `mobile` field); international `+…` numbers are always detected |
| `chunk_size` | 5000 (SQL) / 1000 (Mongo) | Rows/documents fetched per batch |
| `connect_timeout` | 10 | Connection timeout in seconds (SQL and Mongo) |
| `log_queries` | `false` (worker mode: always on) | Log every query issued during DB scans (dialect-compiled SQL with bound values, Mongo filters, DynamoDB scans). Note: emits table/column names into logs |
| `last_scan_time` | – | S3 only: skip objects not modified since this timestamp |
| `aggregation_threshold` | `25` | A (detector, column) pair firing on at least this many rows/documents/cells collapses into one column-level finding with an `occurrences` count. `0` disables |
| `min_confidence` | `likely` | Lowest confidence tier reported: `possible` / `likely` / `very_likely` (a legacy `score_threshold` float is accepted) |
| `column_ratio` | per detector (`0.5`) | Share of a column's sampled non-empty values that must match before the column is classified (Sentra's 50 % rule); overrides every detector policy |
| `column_min_matches` | per detector (`3`) | Distinct matching values needed before a column verdict is drawn |
| `min_count` | per detector (`10`) | Distinct `possible` hits in one unit (file, table column) that promote them to `likely` |
| `allow_list` / `allow_regex` | `[]` | Macie-style allow lists: exact values / regexes never reported (public phone numbers, sample data) |
| `adaptive_sampling` | `false` | Stop reading a unit once its column verdicts settle; `settle_min_records` (2000), `settle_window` (1000), `settle_margin` (0.05) tune the stop rule |
| `sample_strategy` | `head` | `random` draws rows with `TABLESAMPLE` (PostgreSQL, MSSQL) / `$sample` (MongoDB) instead of reading the head; per-target `sample_strategy` overrides it |
| `ner` | `true` | Person names in prose via the spaCy model |
| `field_suppression` | `true` | Structural field-name rules: token detectors never fire in `*_id`/`hash`/`etag`/`path`/… fields, digit-run detectors never fire in counter/timestamp fields. Corroborated findings are exempt |
| `decode_base64` | `true` | Decode base64 blobs (`Authorization: Basic …`, base64 JSON, PEM) and scan the plaintext |
| `entropy_report_uncorroborated` | `false` | Report random-looking tokens that have no supporting evidence as `Secret.TokenLikeValue` (Medium) instead of dropping them |
| `disabled_detectors` | `[]` | Detector names never reported |
| `report_private_ips` | `false` | Report RFC 1918 / loopback / link-local addresses as `PII.IPAddress`; by default only public IPs count |
| `direct_connection` | auto | MongoDB: add `directConnection=true` to the built URI. Automatic for `localhost`/`127.0.0.1`, i.e. port-forwarded replica sets whose members advertise cluster-internal hostnames |
| `column_suppression` | id/hash rule for entropy | Scanner-level escape hatch: per-detector regexes of column/field names to skip on top of the engine's own field rules. Pass `{}` to disable, or your own `{detector: regex}` map |
| `entropy_min_length` | `24` | Minimum token length for the entropy detector |
| `entropy_min_entropy` | `4.5` | Shannon-entropy threshold for base64-shaped tokens (hex tokens use 3.0 and need 32+ chars) |

## Classification

```
connector  ──►  Record / TextBlob stream  ──►  src/pipeline (per unit)  ──►  findings
                                                    │
                                              src/engine (per value)
```

The code is split the way the vendor engines we studied are (Wiz, Cyera, Orca, Sentra, Varonis, Amazon Macie, Google Sensitive Data Protection, Microsoft Purview, Nightfall — see *How the vendors do it* below):

* **Connectors** (`src/scanners/`) know a data source. They enumerate its *units* (tables, collections, objects, sheets) and turn each unit into a stream of `Record`s (rows / documents made of `Cell`s that carry the value, its column name or field path, and a rendered location) or `TextBlob`s (pages, paragraphs, text blocks). They never call the detection engine.
* **The engine** (`src/engine/`) judges one value at a time: pattern + validator + context words + field name → a score and a confidence tier. It stays the place where detectors are defined.
* **The pipeline** (`src/pipeline/`) does everything a DSPM product does *after* pattern matching, once, for every connector: context policy, record-level corroboration, column density verdicts, minimum counts, adaptive sampling and aggregation.

### Confidence tiers

Every finding carries `confidence` and `evidence`:

| Tier | Meaning | Examples |
|---|---|---|
| `very_likely` | validated shape **and** corroboration | checksum-valid national id next to its keyword or in a column named for it, JWT with a decodable header, vendor-prefixed token, opaque value in a credential-named column, a classified column of `likely` cells |
| `likely` | one strong signal | valid e-mail (IANA TLD, no demo/automated sender), Luhn + issuer prefix **with separators**, mod-97 IBAN, structured street address, a plausible shape backed by its column name or a context word, a classified column of `possible` cells |
| `possible` | plausible shape only | SSN-shaped digit groups, a bare mod-10/mod-11-valid number, a random-looking token, a BIC-shaped word. Never reported on its own |

`MIN_CONFIDENCE` picks the lowest tier reported (`likely` by default — Google's default is `possible`, Nightfall recommends `likely`). **Checksums are not enough on their own**: a mod-10/mod-11 check passes ~10 % of random numbers, so a checksum-valid number with no context word, field hint or column evidence is `possible` (a US phone number is a valid NHS number one time in ten). Epoch timestamps are never identifiers; private/loopback IPs are infrastructure (`report_private_ips`); documented examples (`AKIAIOSFODNN7EXAMPLE`, test cards, `hunter2` in advisory text) are never real.

`evidence` lists what backs the finding: `checksum`, `format` (self-validating shape), `context:<word>`, `field` (the column/path names the entity), `key:<name>` (assigned to a credential keyword), `column:<ratio>` (column density), `record:identity` (same record holds two identity signals), `count:<n>` (many in one file), `shape` / `needs_context` / `uncorroborated` (why something stayed `possible`).

### Detector policies

Each detector has a reporting policy (`src/engine/policy.py`, looked up by name with category defaults, so a new recognizer needs no entry unless it deviates):

| Field | Meaning | Vendor precedent |
|---|---|---|
| `context` | `required`: a hit with neither validation nor context is capped at `possible` (national ids, bank accounts, cards, SWIFT, opaque tokens); `boost`: context raises the tier; `none`: self-identifying (e-mail, JWT, IBAN, vendor tokens) | Macie keyword requirements per data type |
| `column_ratio`, `column_min_matches` | share of a column's sampled values (and distinct matches) that classify the column | Sentra 50 % rule, Google column profiles |
| `min_count`, `count_promotion` | distinct `possible` hits in one unit that become `likely`; off for word-shaped patterns (SWIFT/BIC) and random strings | Orca statistical scan, Purview "low-confidence patterns with 20+ instances", Nightfall minimum findings |
| `identity`, `identity_corroboration` | identity signals (name, e-mail, phone, address, DOB) promote a `possible` national id / card in the same record | Purview supporting elements, Cyera identifiability |
| `negative_fields` | column names that veto the detector (`txn`, `hash`, `invoice`, `port`, `amount` …) | DLP negative keywords, Google exclude-by-hotword |

### Field-name rules

Structured data carries its strongest signal in the field name (`DetectionEngine.scan_text(text, field_name=...)`; the name is never mixed into the scanned text). Macie counts a keyword in the column name or any element of the JSON path as proximity, and so does the engine: `src/engine/context.py` classifies credential-named fields (`token`, `secret_key`, `authorization`, `cookie`, `webhook_url`, …) whose values are credentials whatever their entropy, identifier fields (`*_id`, `hash`, `etag`, `path`, …) that never yield token findings, counter/timestamp fields that never yield card/id numbers, `full_name`/`first_name` fields that yield `PII.PersonName`, and `mobile`/`phone` fields that enable national-format phone parsing (a phone-named column whose numbers do not parse for the enabled regions still yields `possible` phones that column density can promote). Overlapping matches keep the most specific detector (a JWT is not also a bearer token, a card number is not also a bank account).

**Names in prose.** A name in a name-labelled column is a field rule; a name inside a support note, a PDF page or a comment field needs a model (Macie NAME, Purview named entities, Cyera NER). With spaCy (`requirements.txt` ships `en_core_web_trf`, a RoBERTa transformer with OntoNotes NER F1 0.90, and `en_core_web_sm`, F1 0.84, as the fallback; `NER_MODEL` chooses, `NER_ENABLED=false` skips), `src/engine/ner.py` accepts PERSON entities that look like written names — two to four title-case tokens, no digits or acronyms, no company suffix — and entities the small model mislabels when their first token is in the shipped given-name lexicon (`src/engine/data/given_names.txt`). A name next to a context word or honorific (patient, customer, employee, regards, dear, Mr/Dr …) is `likely`; otherwise it is `possible` and the pipeline decides: a document with ten distinct names is `likely`, a lone name in a sentence stays hidden.

### Column, record and file verdicts (`src/pipeline`)

* **Column density** — a column whose sampled non-empty values match a detector at `column_ratio` (default 50 %) with at least `column_min_matches` distinct values is classified as that detector one tier above its cells: 40 SSN-shaped values under a meaningless header are a `likely` SSN column; a column of valid e-mails is `very_likely`. An isolated `possible` hit in an otherwise clean column is noise and stays hidden.
* **Unit-name context** — the table, collection, sheet or object name is part of the path to a value (Macie counts a keyword "in the name of an element in the path"): a `possible` card number in `credit_cards.number` or an SSN-shaped value in `ssn_export.csv` is `likely` (`unit:<name>`). Only `possible` candidates are lifted; very weak patterns still need their column name.
* **Sibling columns** — companions named for the detector raise its column one more tier (Sentra): `expiry`/`cvv` next to a card column, `routing`/`ifsc`/`swift` next to a bank account, `date_of_birth`/`first_name` next to a national id (`siblings:<columns>`).
* **Record corroboration** — a `possible` national id or card in a row/document that also carries two identity signals (name, e-mail, phone, address, birth date) becomes `likely` (`record:identity`).
* **Column exclusivity** — once a column is classified, other detectors' hits in it are coincidences (a phone number that happens to pass the NHS mod-11 check) and are dropped unless `very_likely` on their own (Google SDP's exclude-if-another-infoType-matched).
* **Minimum counts** — in a document or a mixed column, `min_count` distinct `possible` hits of one detector become `likely` (`count:<n>`): a file with 30 SSN-shaped numbers is not a coincidence, one is.
* **Aggregation** — a (detector, column) pair with `aggregation_threshold` or more hits collapses into one column-level finding carrying `aggregated`, `occurrences`, `column`, `column_sampled`, `column_matches`, `column_ratio`.
* **Allow lists** — `allow_list` / `allow_regex` suppress known values (public contact numbers, sample data), like Macie allow lists.

### Sampling

Connectors read up to `sample_limit` rows/documents per unit (10 000). By default that is the head of the table; `SAMPLE_STRATEGY=random` (or `sample_strategy` per target) draws a random sample instead — `TABLESAMPLE SYSTEM (p)` on PostgreSQL and MSSQL when the planner estimate says the table holds more than twice the limit (p is sized to about three times the limit before `LIMIT` cuts it), `$sample` on MongoDB, the head on MySQL/MariaDB where no cheap random read exists. With `adaptive_sampling` the pipeline stops reading a unit once `settle_min_records` records have been seen, no new (column, detector) pair appeared for `settle_window` records and no column sits within `settle_margin` of its classification ratio — Wiz's "expand the sample until statistical confidence is reached". Rows already read count in the stats.

### Output

Every finding carries `resource_id`, `detector`, `category`, `severity`, `value` (capped at 200 characters), `location`, `confidence`, `evidence` and a `value_hash` (sha256 prefix for correlating the same value across scans). Column-level findings add the aggregation fields above. The worker's clubbed JSON entries carry the highest `confidence` among their findings.

**Recognizer packs.** `src/engine/recognizers/` holds 159 country-specific and generic recognizers across 62 region packs as native `Rule` objects (`src/engine/rules.py`: pattern scores, context words, validators/invalidators; test vectors in `tests/test_recognizers_*.py`). Rules are grouped by region pack; generic ones (IBAN, crypto wallets, IP, MAC, IMEI, ICCID, VIN, passport MRZ, coordinates, ICD-10 / NDC codes, medical record numbers) always run, `URL`/`UUID` are shipped disabled. Validators return True (checksum holds), False (dropped) or None where the algorithm is not authoritative for every number (Danish CPR after 2007, Latvian 32-prefixed codes, UK UTR, Mexican RFC). Every detector name must exist in `fixtures/findings-mapping.json` (`tests/test_detector_names.py`).

**Regression corpus.** `tests/fixtures/detection_corpus.json` is an anonymised corpus built from real Postgres/Mongo scans: 370+ reviewed false positives that must stay silent and 160+ true positives that must stay detected (`tests/test_regression_corpus.py`). `tests/test_pipeline.py` covers the column/record/file rules and the connector contract.

**Sample dataset.** `sample_data/all_detectors.jsonl` / `.txt` hold one synthetic example per detector (built by `python -m tests.sample_dataset_builder`; `--check` scans them and lists anything not detected) — scan them to see every finding type the engine can produce, and `tests/test_sample_dataset.py` keeps them in sync with the catalogue.

## Adding a connector

A connector is a `BaseScanner` subclass (`src/scanners/base.py`) that implements how to *reach* and *read* a source; classification is inherited:

```python
from src.pipeline import Cell, Record, TextBlob          # what a connector emits
from src.scanners.base import BaseScanner

class SnowflakeScanner(BaseScanner):
    def __init__(self, engine, config=None, client=None):
        super().__init__(engine, config, client)
        self.stats = {"tables_scanned": 0, "rows_scanned": 0, "errors": 0}

    def iter_scan(self, target):                          # one unit at a time, so callers can checkpoint
        for schema, table in self._list_tables(target):
            resource_id = f"snowflake://{target['account']}/{schema}.{table}"
            findings = self.classify(                     # the whole pipeline: context policy, column verdicts,
                resource_id,                              # record corroboration, min counts, aggregation
                self._rows(schema, table, target),
                location_fn=lambda column, n: f"Table '{table}', Column '{column}' ({n} matches)",
            )
            self.stats["tables_scanned"] += 1
            yield resource_id, f"{schema}.{table}", self.dedup_findings(findings)

    def scan(self, target):
        return self.collect(target)

    def _rows(self, schema, table, target):               # a generator of Records; count rows in stats
        for idx, row in enumerate(self._query(schema, table, target.get("sample_limit", 10000))):
            self.stats["rows_scanned"] += 1
            yield Record([Cell(str(v), column, f"Table '{table}', Row {idx}, Column '{column}'") for column, v in row.items() if v])
```

Rules of the contract:

1. Emit `Record`s for rows/documents (`Cell.field` is the column name or dotted path the engine uses as context; `Cell.key` the aggregation key when array indices should collapse; `src.pipeline.document_record` builds one from any nested document) and `TextBlob`s for free text (`locate(start, end)` renders span locations).
2. Keep `location` strings connector-specific and stable; pass `location_fn(column, n)` for column-level findings.
3. Count what you read in `self.stats` inside the generator (it keeps counting when adaptive sampling stops early) and let `classify()` record read errors (`self.stats["errors"]`, `error_details`).
4. Files of any origin go through `src/scanners/files.iter_units(path, resource_id, config)` — an object-store connector only downloads.
5. New detectors are `Rule`s in `src/engine/recognizers/` plus a `fixtures/findings-mapping.json` entry, and, only if they deviate from their category, a `DetectorPolicy` in `src/engine/policy.py`.

## How the vendors do it

What the design above copies, with sources:

* **Detector = pattern + validation + context policy.** Macie's managed data identifiers require a keyword within 30 characters for ambiguous types (SSN, bank account, passport, birth date, AWS secret key) and none for self-describing formats; custom identifiers add keywords (max match distance 50, 1–300), ignore words and occurrence thresholds ("if an object contains fewer occurrences than the lowest threshold, Macie doesn't create a finding") — [keyword requirements](https://docs.aws.amazon.com/macie/latest/user/managed-data-identifiers-keywords.html), [custom identifiers](https://docs.aws.amazon.com/macie/latest/user/cdis-options.html). Purview SITs are a primary element plus supporting elements within a proximity window (250 characters), with confidence low 65 / medium 75 / high 85 and the guidance to "use high confidence patterns with low counts, say five to 10, and low confidence patterns with higher counts, say 20 or more" — [sensitive information types](https://learn.microsoft.com/en-us/purview/sit-sensitive-information-type-learn-about).
* **Column names are context.** Macie treats a keyword in the column name or in any element of the JSON path as proximity; Google SDP: "for tabular data, the context includes the column name" ([InspectConfig](https://docs.cloud.google.com/sensitive-data-protection/docs/reference/rest/v2/InspectConfig)); Sentra raises certainty when "the column is named credit card number" or an expiry/CVV column sits next to it ([Sentra](https://www.sentra.io/blog/building-a-better-dspm)).
* **Discrete confidence.** Google SDP POSSIBLE ("signals can include passing checksums; lack of a strong contextual clue") / LIKELY / VERY_LIKELY, minimum POSSIBLE by default ([likelihood](https://docs.cloud.google.com/sensitive-data-protection/docs/likelihood)); Nightfall's "Possible is triggered by the appearance of the token without considering context", recommended minimum Likely ([Nightfall](https://help.nightfall.ai/detection_platform/faq/confidence_levels)); Wiz reports "classification confidence levels for each finding" with configurable thresholds ([Wiz DSPM Q&A](https://www.securityscientist.net/blog/12-questions-and-answers-about-wiz-dspm-wiz/)).
* **Counts and density decide.** Orca: "a single, random nine-digit number in a file is unlikely to be a real Social Security number versus a file containing many"; custom identifiers carry count/density thresholds and column-name allow/deny lists ([Orca](https://orca.security/resources/blog/custom-data-detection/)). Sentra: "if 50% of values are valid credit card numbers, the whole column is labelled as such". Nightfall: minimum number of findings per detector "within the same message or file". presidio-structured picks a column's entity as the most common one across sampled cells.
* **Negative evidence.** Google exclusion rules (dictionary, regex, exclude-if-another-infoType, exclude-by-hotword "allows you to exclude an entire column"), Macie ignore words and allow lists, Varonis negative keywords ([Varonis](https://www.varonis.com/blog/data-classification-deep-dive)), Gitleaks stopwords / allowlists, TruffleHog verified-vs-unverified results.
* **Sampling to confidence.** Wiz: "statistical sampling of a sufficient number of records provides high-confidence classification results … incrementally expanding the sample until statistical confidence is reached", metadata-only for logs, full content for unstructured files ([Wiz](https://www.wiz.io/blog/wiz-data-classification)). Macie samples representative objects per bucket/prefix/type breadth-first and never re-analyses unchanged objects ([Macie automated discovery](https://docs.aws.amazon.com/macie/latest/user/discovery-asdd-how-it-works.html)). Cyera clones database snapshots and clusters similar files, sampling each cluster ([Cyera](https://www.cyera.com/blog/advancing-sensitive-data-classification-in-the-age-of-ai)).
* **Identity context.** Cyera enriches classifications with data-subject role, region and identifiability and uses NER to tell SSNs from employee ids ([Cyera](https://www.cyera.com/blog/understanding-data-in-context-an-llm-driven-approach-to-data-classification)); Purview's example SIT requires an SSN to sit within 250 characters of a Name, DateOfBirth or AccountNumber.
* **One pipeline, many sources.** Wiz scans S3, Azure Blob, GCS, RDS, BigQuery, DynamoDB and Snowflake through the same classifier library with "structural analysis and content sampling"; Macie applies one keyword model with three proximity rules — columnar, record-based, unstructured — which is exactly the `Record` (columnar / record shape) vs `TextBlob` split here.

Not copied (deliberately): LLM verification of matches (Cyera, Varonis "only for ambiguous content") and API-level secret verification (TruffleHog) — both call out of the scanner with customer data.

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
