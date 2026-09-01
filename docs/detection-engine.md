# Detection engine

How a cell, document field or file chunk becomes a finding. Code lives in `src/engine/`.

```
scanner ──(text, field_name)──▶ DetectionEngine.scan_text
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │ 1. layers (raw matches, each with a score)                │
        │    scan_pii · scan_credentials · scan_financial           │
        │    scan_healthcare · scan_regional · scan_generic         │
        │    scan_entropy · _scan_encoded (base64 → rescan)         │
        └─────────────────────────────┬─────────────────────────────┘
                                      ▼
        2. field-name suppression   (identifier / counter fields, unless corroborated)
        2b. engine policies         (bare checksum-only matches need context; epochs, private IPs → 0.3)
        3. placeholder demotion     (111-22-3333, 1234-5678… → 0.3)
        4. score > threshold        (0.8)
        5. overlap resolution       (one finding per span, most specific detector wins)
        6. value_hash               (sha256 prefix for correlation)
                                      ▼
        [{detector, category, severity, value, score, start, end, value_hash, …}]
```

Everything below is the detail of those boxes.

---

## 1. Inputs: text + field name

`DetectionEngine.scan_text(text, field_name=None)` is the only entry point. Every scanner passes the **name of the container** the text came from:

| Scanner | `field_name` |
|---|---|
| SQL (`scanners/db/sql.py`) | column name |
| Mongo (`scanners/db/mongo.py`) | dotted path with array indices (`api_event.http.request.headers.authorization`, `items[3].email`) |
| DynamoDB (`scanners/aws/ddb.py`) | attribute name (nested values are JSON-dumped) |
| S3 CSV / Parquet / Excel | column header |
| S3 JSON | ijson prefix (`item.user.email`) |
| S3 XML | element tag |
| S3 text / PDF / DOCX / OCR | none |

The field name is **never mixed into the scanned text** (the previous engine prefixed `column: value`, which put column names into reported values and into keyword windows). It is context only: it drives entity hints, credential/identifier classification and suppression (section 6).

---

## 2. Layers

Each `scan_*` function in `layers.py` returns raw matches: `{detector, category, severity, value, score, start, end, …extras}`. Nothing is filtered at this stage.

### PII — `scan_pii`
| Detector | How |
|---|---|
| Email | regex → `validate_email`: TLD must be in the bundled IANA list (`data/tlds.txt`), no digit-only domain labels (`python3-libs@3.9.25-2.el9` is a package@version), no demo domains (`example.com`, `.test`, `localhost`…), automated senders (`noreply@`, `mailer-daemon@`, `*[bot]`) score 0.6, everything else 0.85 (0.95 with an email-named field) |
| Phone Number | `phonenumbers`. International format (`+…`) always; national formats only when the field or nearby words say phone/mobile/tel, parsed with the `phone_regions` (default = `enabled_regions`). Texts with fewer than 7 digits skip the library entirely |
| Date of Birth | ISO/slash date in 1930–2012 **and** a birth/dob context word or field |
| Address | three routes: (a) structured `<number> <Name words> <street type>` with the street type as a whole word — `broadcast`, `roadmap`, `BlockRootUser` no longer trigger; abbreviations (`St`, `Rd`) need context; (b) key/value pairs in JSON-ish text (`"street": …`, `zipCode=…`) with non-postal keys (`ip_address`, `mac_address`, `--advertise-address`) excluded and values that must contain letters; (c) the field itself is an address column. Reported span is capped at 200 chars |
| PII.PersonName | only where a field or JSON key names a person (`full_name`, `first_name`, `customer_name`…) and the value looks like a name (2–4 alphabetic tokens, a vowel, not `kkkkkk`/`admin`/`null`) |

### Credentials — `scan_credentials`
| Detector | How |
|---|---|
| Password Pattern | `password/passwd/pwd/passphrase = value` assignments. Dropped: placeholders (`${VAR}`, `<password>`, `!Ref`, `process.env.X`, `***`), code fragments, variable names (`currPassword`), algorithm names (`PBKDF2`), single prose words (`Reenter`), values under 6 chars. Well-known example passwords (`hunter2`, `P@ssw0rd`) score 0.7 in free text but count in a password-named column |
| Secret.PasswordHash | bcrypt / argon2 / crypt(3) / PBKDF2 / LDAP `{SSHA}` / scrypt anywhere; bare hex/base64 digests only in password-named fields |
| API Key / Bearer Token / OAuth Token | explicit `api_key=`, `secret:`, `token=`, `access_token=` assignments (≥16 chars, shape-checked: paths, dates, word-built names and k8s-style slugs are not keys); `Bearer <token>` needs a digit or token punctuation, so prose like "Bearer authorization header" is ignored |
| JWT Token | `eyJ….….…`; header is base64-decoded and must parse as JSON with `alg`/`typ` (0.95, else 0.6). Claims are scanned: an `email` claim yields an Email finding, a `password` claim a password/hash finding, anchored on the token |
| AWS Access Key | `AKIA`/`ASIA` + 16; documented examples (`AKIAIOSFODNN7EXAMPLE`) score 0.3 |
| AWS Secret Access Key | 40 base64 chars, mixed case + digits, not hex, ≤3 slashes, no word-built segments (`Authorization/policyAssignments/…`). 0.9 when corroborated (an access key in the same text, a secret/aws keyword, a credential-named field), 0.85 when structurally random and not in an identifier field, else 0.5 |
| Private Key Header | `-----BEGIN … PRIVATE KEY-----` needs a base64 body within 400 chars (0.95); a bare header in prose scores 0.5. Starred (redacted) keys are skipped |
| 30 vendor formats | GitHub, GitLab, Slack (+ webhooks), Google API/OAuth, OpenAI, Anthropic, Stripe, SendGrid, Twilio, Mailchimp, Mailgun, Vault, Docker Hub, npm, PyPI, Azure Storage/SAS, Shopify, Square, Telegram, Databricks, Atlassian, Grafana, Postman, Hugging Face, age, Discord, Heroku — prefix/format regexes from `tokens.VENDOR_TOKEN_RULES`, 0.95 |
| Credentials in URL | `scheme://user:password@host` with a non-placeholder password |
| Basic Auth Credentials | `Basic <base64>` that decodes to `user:password` |
| field-based | a **credential-named field** (`token`, `secret_key`, `authorization`, `cookie`, `webhook_url`, `header_value`…) holding one opaque value is reported as Password Pattern / API Key / Bearer Token / OAuth Token by field kind, whatever its entropy; `Salted__` blobs there become `Encrypted Secret`. Cookie-style `name=value` is judged on the value part; e-mails and probe strings (`x-liveness-probe`) in such fields are never re-typed as tokens |

### Financial — `scan_financial`
| Detector | How |
|---|---|
| Credit Card | canonical groupings only (`4-4-4-4[-3]`, `4-6-5`, or 13–19 contiguous digits, never inside a UUID or hyphenated id); Luhn **and** issuer prefix/length; separated numbers 0.85, contiguous 0.6 + 0.35 with card context or a card-named field; documented test cards 0.3 |
| IBAN | the per-country rule from the recognizer packs (76 countries, structure + mod-97); falls back to a generic regex + mod-97 |
| SWIFT/BIC | 8/11 uppercase, chars 5–6 must be an ISO-3166 country code, blacklist of English words, and `swift`/`bic`/`iban` context or field required (0.5 → 0.85) |
| Bank Account | 8–18 digits with specific context (`account number`, `acct`, `ifsc`, `routing`, `sort code`…) and no cloud-account context (`arn`, `subscription`, `account id`) |

### Healthcare — `scan_healthcare`
Three or more distinct PHI keywords (`patient`, `diagnosis`, `prescription`, `icd-10`, …) in one text → `Healthcare Data Detection` on the whole span.

### Recognizer packs — `scan_regional`, `scan_generic`
`src/engine/recognizers/` holds 90 `Rule` objects (section 5): 84 country-specific ones across 18 region packs (`US` 15, `DE` 13, `ZA` 10, `GB` 6, `IN` 6, `IT` 5, `KR` 5, `AU` 4, `PH` 4, `ES` 3, `CA`/`TR`/`SE`/`SG`/`NG` 2 each, `FI`/`PL`/`TH` 1) and 6 generic ones (IBAN, crypto wallet, IPv4/IPv6, MAC; `URL` and `UUID` shipped disabled). Only packs in `enabled_regions` run.

### Entropy — `scan_entropy`
Candidates are runs of 20+ token characters. Each is classified by **shape** (section 4) before any entropy is computed; then:

| verdict | outcome |
|---|---|
| `jwt` | left to the JWT detector |
| `pem` (base64 `-----BEGIN`) | decoded; `PRIVATE KEY` → Private Key Header, certificates ignored |
| `salted` (base64 `Salted__`) | `Encrypted Secret` (Medium) |
| `path`, `uuid`, `date`, `slug`, `hash`, `identifier` | never a secret |
| `assignment` (`key=value`) | the value part is re-classified |
| `secret_like` | Shannon entropy ≥ 4.5 (hex: ≥ 3.0 and 32+ chars), then **evidence**: credential-named field or an inline `token:`/`secret=`/`api_key=` keyword within 48 chars → `High Entropy Secret` 0.9; no evidence → dropped, or `Secret.TokenLikeValue` (Medium) when `entropy_report_uncorroborated` is on |

### Encoded content — `_scan_encoded`
Base64 blobs of 40+ chars that decode to printable text are scanned again with the credential and PII layers (e.g. base64 JSON bodies). Findings are anchored on the encoded span and flagged `encoded: "base64"` so overlap resolution never drops them.

---

## 3. Scoring

One scale for every detector; `DetectionEngine` reports findings with `score > score_threshold` (0.8).

| Score | Meaning | Examples |
|---|---|---|
| 0.95 – 1.0 | self-validating **and** corroborated | JWT with decodable header; checksum-valid Aadhaar next to "aadhaar"; `ghp_…`; opaque value in a `secret_key` column |
| 0.85 | self-validating alone | valid email; card with separators + Luhn + issuer; `42 Baker Street`; `Salted__` blob |
| 0.6 | plausible shape, needs evidence | contiguous 16 digits; 8-letter BIC-shaped word; header-only private key; automated-sender email |
| 0.5 | weak shape, needs field evidence | recognizer patterns without context; uncorroborated 40-char base64 in a prose field |
| 0.3 | documented example / placeholder | `AKIAIOSFODNN7EXAMPLE`, `4111 1111 1111 1111`, `111-22-3333` |

Consequence: a weak shape is reported only when a checksum, a specific context word or the field name vouches for it. Lowering the threshold to ~0.55 brings back plausible-but-unverified shapes; raising it to 0.9 keeps only corroborated findings.

---

## 4. Token shape analysis — `tokens.py`

Shannon entropy cannot separate `subscriptions/69e37648-…/resourceGroups/TTB` (4.68) from a real AWS secret (4.66). Shape can. `analyze_token(token)` returns a kind:

1. cheap structural checks in order: length, JWT, PEM/`Salted__` prefix, UUID, date, hash prefix (`sha256-…`), slug (`lowercase-words-with-dashes-0`), 2+ slashes → `path`, one slash or inner `=` next to a word → `path`/`assignment`;
2. otherwise the token is split on delimiters and letter/digit boundaries and each chunk is tested for **word-likeness**: CamelCase/lowercase/ALLCAPS components with a natural vowel ratio, no 5-consonant runs, no stray single letters (`resourceGroups`, `MASS_ASSIGNMENT`, `windowsComplianceSTIG` are words; `BoYddPrCb`, `szmegnOj`, `MDDXnEjDoga` are not);
3. `identifier` when ≥ 60 % of the letters sit in word-like chunks (or ≥ 40 % and the whole token is not random-looking); `secret_like` when the whole token is random-looking (letters and digits interleaved, ≥ 3 letter↔digit transitions, no word-like letter run of 5+) or random segments cover ≥ 60 % of it.

The same module holds the vendor token formats, the documented-example allowlists (`EXAMPLE_SECRETS`, `TEST_CARD_NUMBERS`, `EXAMPLE_PASSWORDS`), the placeholder regex (`${…}`, `{{…}}`, `<…>`, `!Ref`, `process.env.*`, `[REDACTED]`, …), base64 decoding and JWT parsing.

---

## 5. Rule engine — `rules.py` and `recognizers/`

A `Rule` is a detector name plus:

- `patterns`: regexes with individual scores (`Pattern(name, regex, score)`), compiled with `IGNORECASE | MULTILINE | DOTALL` unless overridden;
- `context`: words that raise confidence when found as whole words near the match (5 before / 3 after) or in the field name (compound field names such as `socialsecurity` are matched too);
- `validator` / `invalidator`: checksum or structure callables — `True` → score 1.0, `False` → match dropped, `None` → unchanged;
- `field_hint`: a regex over the lower-cased field name that lifts the score to 0.85;
- `region`, `enabled`, `examples`.

`run_rule` applies exactly that: pattern score → validator → context boost (+0.35, floored at 0.4, capped at 1.0) → field hint → containment de-duplication. `run_rules` adds two cost cuts that change nothing in the output: a combined gate regex per rule set (one C-level search decides whether any pattern can match) and `Rule.can_reach(threshold, …)`, which skips rules that cannot score above the threshold for this text (no validator, weak pattern, no context word or field hint present).

Region packs live in `recognizers/{us_ca, gb_es_it_tr, de_se_fi_pl, in_sg_au_kr_th, za_ng_ph_generic}.py`; `recognizers/__init__.py` loads them lazily (`load_all`, `get_rule`) and rejects duplicate names. Detector names are the keys of `fixtures/findings-mapping.json` (the CSPM rates findings by that name).

---

## 6. Field-name rules — `context.py`

Field names are tokenised (`api_event.http.request.headers.authorization` → `api event http request headers authorization`, `customerSSN` → `customer ssn`) and classified:

| Class | Examples | Effect |
|---|---|---|
| credential | `token`, `secret_key`, `password`, `authorization`, `cookie`, `set-cookie`, `webhook_url`, `header_value`, `connection_string`, `otp` | a bare opaque value is reported as a credential; entropy findings are corroborated |
| identifier | `*_id`, `uuid`, `arn`, `hash`, `etag`, `if-none-match`, `x-request-id`, `path`, `url`, `references`, `source`, `description`, `name`, `version`, `commit`, … | token detectors (`High Entropy Secret`, `Secret.TokenLikeValue`, `AWS Secret Access Key`) are suppressed |
| numeric id | `*_id`, `port`, `timestamp`, `created`, `version`, `count`, `offset`, `seq`, `serial`, … | digit-run detectors (`Credit Card`, `Bank Account`, `IN Aadhaar`, `US SSN`, `CA SIN`, `Phone Number`) are suppressed |

When a path carries both kinds of word (`token_name`, `auth.request_id`) the right-most one wins — the leaf names what the value is. Per-detector `FIELD_HINTS` (`email`, `mobile`, `dob`, `zip_code`, `full_name`, `card_number`, `iban`, `swift`, …) raise scores; an explicit hint always beats suppression, and findings that carry `evidence` (keyword, neighbouring access key, self-describing format) are never suppressed.

---

## 7. Post-processing — `detector.py`

1. **Field suppression** (section 6), skipped for corroborated findings. Any bare short value (a 10-digit number, a 9-char alphanumeric) in an id / hash / timestamp field is suppressed whatever recognizer matched it.
2. **Engine policies** (`_apply_engine_policies`): a checksum alone is weak evidence — mod-10/mod-11 passes ~10 % of random numbers — so a bare, separator-free match of a checksum-only recognizer (NPI, NHS, ABA, DEA, Aadhaar…) is capped at 0.75 unless a context word or field hint is present; epoch timestamps (10 digits 2011–2039, or 13-digit milliseconds) drop to 0.3; private / loopback / link-local IPs drop to 0.3 unless `report_private_ips`.
3. **Placeholder demotion**: national ids / financial numbers whose digit groups are single repeated digits or a straight run (`111-22-3333`, `1234 5678 9012 3456`) drop to 0.3.
4. **Threshold** filter; `disabled_detectors` removed.
5. **Overlap resolution** (`resolve_overlaps`): findings are ordered by `DETECTOR_PRIORITY` (Private Key 100 › JWT / AWS Access Key / vendor tokens 95 › Credentials in URL 92 › AWS Secret 88 › Password Hash 85 › Password 84 › API Key / OAuth 82 › Bearer 78 › Credit Card / IBAN 72 › Email 66 › DOB 62 › Phone 60 › regional & generic rules 60 › Bank Account 52 › SWIFT 45 › Encrypted Secret 35 › High Entropy 20 › TokenLikeValue 15 › Address / PersonName 10). A finding is dropped when a kept finding of strictly higher priority contains it (or covers ≥ 80 % of it), or when the same detector already covers the span. So a JWT is not also a Bearer token and two entropy blobs, a card number is not also a bank account, a BIC inside an IBAN disappears. Findings extracted from encoded payloads (`encoded: jwt|base64`) are exempt.
6. **`value_hash`**: first 16 hex of sha256(value), for correlating a value across scans and tables.

The scanner then formats findings (`BaseScanner.format_finding`), de-duplicates per relation and aggregates a (detector, column) pair that fires on ≥ `aggregation_threshold` rows into one column-level finding — unchanged from before.

---

## 8. Configuration

Engine config (`DetectionEngine(config)`; master mode passes the payload's `config`, worker mode builds it from `settings.py`):

| Key | Default | Worker env var | Meaning |
|---|---|---|---|
| `enabled_regions` | `[]` (worker: `US,IN,GB`) | `ENABLED_REGIONS` | region packs; `UK` → `GB` |
| `phone_regions` | `enabled_regions` | – | regions for national-format phone parsing |
| `score_threshold` | `0.8` | `SCORE_THRESHOLD` | minimum score reported |
| `entropy_min_length` / `entropy_min_entropy` | `24` / `4.5` | – | entropy candidate length and Shannon threshold (hex uses 3.0) |
| `entropy_report_uncorroborated` | `false` | `REPORT_TOKEN_LIKE_VALUES` | report unevidenced random tokens as `Secret.TokenLikeValue` |
| `field_suppression` | `true` | – | structural field-name suppression |
| `decode_base64` | `true` | – | decode-and-rescan base64 blobs |
| `disabled_detectors` | `[]` | – | detector names never reported |
| `report_private_ips` | `false` | – | report RFC 1918 / loopback / link-local addresses as `PII.IPAddress` |
| `column_suppression` | id/hash rule | – | scanner-level per-detector column regexes on top of the engine rules |

`LOG_QUERIES` is always on in worker mode.

---

## 9. Performance

Measured on a realistic cell mix (JSON blobs, advisory prose, emails, Azure paths, timestamps, ids, tokens, URLs): ~2.9k cells/s with the default three packs, ~2.4k with all eighteen. The gates and `can_reach` pruning keep the 90 recognizer rules from running on cells they cannot match; `phonenumbers` (the single most expensive component) is skipped on texts with fewer than 7 digits; vendor-token regexes sit behind one prefix gate; the healthcare keyword loop is a single regex.

---

## 10. Tests

| File | Guards |
|---|---|
| `tests/test_engine.py` | layer behaviour, tuning cases (documented examples not reported, no card from ids, no address from `"state": "running"`, …) |
| `tests/test_recognizers_*.py` | every recognizer against its upstream test vectors: valid inputs at the expected score/span, invalid inputs silent, field hint ≥ 0.85 |
| `tests/test_detector_names.py` | every emittable detector name has a mapping entry; rule sets load without duplicates and each rule matches its own example |
| `tests/test_regression_corpus.py` | `tests/fixtures/detection_corpus.json`: 533 anonymised samples from real Postgres/Mongo scans — 373 reviewed false positives must stay silent, 160 true positives (incl. synthetic recall cases) must stay detected |
| `tests/test_scanners.py`, `tests/test_worker_handler.py` | scanners pass field names; output layout, aggregation, error reporting |

Run everything with `python run_tests.py` (auto-discovers `tests/test_*.py`; pass a substring to select modules).

---

## 11. Extending

**A new pattern detector**: add a `Rule` to the right `recognizers/*.py` (or a new module listed in `recognizers/__init__.py:MODULES`) with patterns, context words, a validator if a checksum exists, a `field_hint`, one or two `examples`, and the `region`. Add the detector name to `fixtures/findings-mapping.json`. Write a test with valid/invalid vectors. `test_detector_names.py` fails until the mapping entry exists.

**A new vendor token**: one line in `tokens.VENDOR_TOKEN_RULES` (plus its prefix in `VENDOR_GATE_RE`), a mapping entry, and a priority in `detector.DETECTOR_PRIORITY` if 95 is not right.

**Tuning noise**: prefer (in this order) a checksum, a specific context word, a field hint, a structural filter in `tokens.py`; avoid generic context words — `code`, `state`, `number`, `identity`, `key` were the main false-positive driver of the previous engine. Every reviewed false positive should become a `fp` sample in the corpus so it cannot come back.
