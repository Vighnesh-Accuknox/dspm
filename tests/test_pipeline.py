"""
The connector-independent pipeline (src/pipeline): the statistical half of
classification that every connector shares, the file parsers, and the
connector contract a new scanner has to satisfy.
"""
import json
import os
import random
import tempfile
import zipfile

from src.engine import tokens as tk
from src.engine.detector import DetectionEngine
from src.engine.entropy import calculate_entropy
from src.pipeline import Cell, Record, TextBlob, UnitClassifier, collapse_indices, document_record, flatten
from src.scanners.base import BaseScanner
from src.scanners.files import iter_units


def _engine(**cfg):
    return DetectionEngine({"enabled_regions": ["US", "IN", "GB"], **cfg})


def _luhn_complete(prefix: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(prefix)):
        n = int(ch)
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return prefix + str((10 - total % 10) % 10)


def _visa_numbers(n: int, seed: int = 7):
    rng = random.Random(seed)
    out = []
    while len(out) < n:
        number = _luhn_complete("4" + "".join(rng.choice("0123456789") for _ in range(14)))
        if number not in tk.TEST_CARD_NUMBERS and number not in out:
            out.append(number)
    return out


def _ssn_shaped(i: int) -> str:
    return f"{200 + i}-{10 + i % 80:02d}-{1000 + i}"


def _random_tokens(n: int, seed: int = 3):
    rng = random.Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    out = []
    while len(out) < n:
        token = "".join(rng.choice(alphabet) for _ in range(32))
        if tk.analyze_token(token, 24).kind == "secret_like" and calculate_entropy(token) >= 4.6:
            out.append(token)
    return out


# --------------------------------------------------------------------------- column verdicts

def test_column_density_classifies_headerless_column():
    # Each cell alone is only `possible` (SSN-shaped, no context); 40 distinct ones under a
    # meaningless header classify the column (Sentra's column rule, Orca's statistical scan)
    clf = UnitClassifier(_engine(), "unit://t", location_fn=lambda col, n: f"Column '{col}' ({n} matches)")
    for i in range(40):
        clf.feed(Record([Cell(_ssn_shaped(i), "ref", f"Row {i}, Column 'ref'")]))
    out = clf.finish()
    assert len(out) == 1
    f = out[0]
    assert f["detector"] == "US SSN" and f["confidence"] == "likely" and f["aggregated"] is True
    assert f["occurrences"] == 40 and f["column"] == "ref" and f["column_ratio"] == 1.0
    assert "column:1.00" in f["evidence"] and f["location"] == "Column 'ref' (40 matches)"


def test_isolated_possible_hit_is_not_reported():
    # one SSN-shaped value among 200 free-text notes is noise at the default tier...
    def feed(clf):
        clf.feed(Record([Cell("ticket 219-09-9999 escalated", "notes", "Row 0")]))
        for i in range(200):
            clf.feed(Record([Cell(f"customer called about invoice {i}", "notes", f"Row {i + 1}")]))

    clf = UnitClassifier(_engine(), "unit://t")
    feed(clf)
    assert clf.finish() == []
    # ...and visible, tagged `possible`, when the reporting tier asks for everything
    clf = UnitClassifier(_engine(), "unit://t", config={"min_confidence": "possible"})
    feed(clf)
    out = clf.finish()
    assert [(f["detector"], f["confidence"]) for f in out] == [("US SSN", "possible")]


def test_record_level_identity_corroboration():
    # Purview's proximity model: an SSN-shaped value next to a name and an e-mail is a likely SSN
    record = Record([
        Cell("Priya Sharma", "full_name", "Row 0, Column 'full_name'"),
        Cell("priya.sharma@acme-corp.io", "email", "Row 0, Column 'email'"),
        Cell("219-09-9999", "ref", "Row 0, Column 'ref'"),
    ])
    clf = UnitClassifier(_engine(), "unit://t")
    clf.feed(record)
    ssn = [f for f in clf.finish() if f["detector"] == "US SSN"]
    assert ssn and ssn[0]["confidence"] == "likely" and "record:identity" in ssn[0]["evidence"]

    # the same value without identity context in the record stays hidden
    clf = UnitClassifier(_engine(), "unit://t")
    clf.feed(Record([Cell("219-09-9999", "ref", "Row 0, Column 'ref'")]))
    assert clf.finish() == []


def test_context_required_caps_uncorroborated_tokens():
    engine = _engine(entropy_report_uncorroborated=True)
    token = "3f9KqL2mXv8Rt5Yw1Zb7Nc4Hs6Pj0Dg"
    # the engine alone reports the random token (score 0.85)...
    assert [f["detector"] for f in engine.scan_text(token, field_name="misc")] == ["Secret.TokenLikeValue"]
    # ...the pipeline caps it at `possible`: shape without corroboration (Macie keyword requirement)
    clf = UnitClassifier(engine, "unit://t")
    clf.feed(Record([Cell(token, "misc", "Row 0")]))
    assert clf.finish() == []
    # a column that is mostly random tokens is a token column
    clf = UnitClassifier(engine, "unit://t")
    for i, value in enumerate(_random_tokens(30)):
        clf.feed(Record([Cell(value, "misc", f"Row {i}")]))
    out = clf.finish()
    assert len(out) == 1 and out[0]["detector"] == "Secret.TokenLikeValue" and out[0]["aggregated"] is True
    assert out[0]["confidence"] == "likely"


def test_unstructured_min_count_promotes_possible_hits():
    cards = _visa_numbers(10)
    # ten distinct bare card-shaped Luhn-valid numbers in one document: "a file containing many"
    clf = UnitClassifier(_engine(), "unit://doc")
    clf.feed(TextBlob("\n".join(cards), location="PDF Page 1"))
    out = clf.finish()
    assert len(out) == 10 and {f["detector"] for f in out} == {"Credit Card"}
    assert all(f["confidence"] == "likely" and "count:10" in f["evidence"] for f in out)
    # three alone stay `possible`
    clf = UnitClassifier(_engine(), "unit://doc")
    clf.feed(TextBlob("\n".join(cards[:3]), location="PDF Page 1"))
    assert clf.finish() == []


def test_count_promotion_is_off_for_word_shaped_patterns():
    words = [f"CORP{cc}XX" for cc in ("DE", "FR", "GB", "US", "IN", "IT", "ES", "NL", "BE", "CH", "AT", "SE", "DK", "NO", "FI")]
    clf = UnitClassifier(_engine(), "unit://doc")
    clf.feed(TextBlob(" ".join(words), location="Page 1"))
    assert clf.finish() == []  # 15 BIC-shaped upper-case words are what any document looks like
    clf = UnitClassifier(_engine(), "unit://doc")
    clf.feed(TextBlob("swift code: CORPDEXX", location="Page 1"))
    out = clf.finish()
    assert [(f["detector"], f["confidence"]) for f in out] == [("SWIFT/BIC", "likely")]


def test_checksum_alone_is_possible():
    engine = _engine()
    nhs = "943 476 5919"  # mod-11 valid, the shape of a phone number
    assert engine.scan_text(nhs, field_name="misc") == []
    found = engine.scan_text(nhs, field_name="misc", min_confidence="possible")
    assert [(f["detector"], f["confidence"]) for f in found] == [("UK_NHS", "possible")]
    assert "needs_context" in found[0]["evidence"]
    assert [(f["detector"], f["confidence"]) for f in engine.scan_text(f"NHS number {nhs}")] == [("UK_NHS", "very_likely")]
    assert [f["confidence"] for f in engine.scan_text(nhs, field_name="nhs_number")] == ["very_likely"]


def test_phone_named_column_with_unparsed_numbers():
    # French numbers under a US/IN/GB configuration: the column name is the keyword
    engine = _engine()
    assert engine.scan_text("12 34 56 78", field_name="misc", min_confidence="possible") == []
    hinted = engine.scan_text("12 34 56 78", field_name="telephone", min_confidence="possible")
    assert [(f["detector"], f["confidence"]) for f in hinted] == [("Phone Number", "possible")] and "field" in hinted[0]["evidence"]
    assert engine.scan_text("12 34 56 78", field_name="telephone") == []  # a lone unparsed number is not reported
    clf = UnitClassifier(engine, "unit://t")
    for i in range(40):
        clf.feed(Record([Cell(f"01.38.64.{10 + i:02d}.{40 + i:02d}", "telephone", f"Row {i}")]))
    out = clf.finish()
    assert len(out) == 1 and out[0]["detector"] == "Phone Number" and out[0]["aggregated"] is True
    assert out[0]["confidence"] in ("likely", "very_likely") and out[0]["column_ratio"] == 1.0


def test_adaptive_sampling_settles():
    clf = UnitClassifier(_engine(), "unit://t", config={"adaptive_sampling": True, "settle_min_records": 50, "settle_window": 20})
    fed = 0
    for i in range(500):
        clf.feed(Record([Cell(f"user{i}@acme-corp.io", "email", f"Row {i}")]))
        fed += 1
        if clf.settled:
            break
    assert clf.settled and 50 <= fed < 500
    assert not UnitClassifier(_engine(), "unit://t").settled  # off by default


def test_allow_list_and_negative_field_names():
    engine = _engine()
    clf = UnitClassifier(engine, "unit://t", config={"allow_list": ["support@acme-corp.io"], "allow_regex": [r"@partner\.example$"]})
    clf.feed(Record([Cell("support@acme-corp.io", "email", "r0"), Cell("bob@partner.example", "email", "r0"), Cell("carol@acme-corp.io", "email", "r0")]))
    assert [f["value"] for f in clf.finish()] == ["carol@acme-corp.io"]

    card = _visa_numbers(1)[0]
    spaced = " ".join(card[i:i + 4] for i in range(0, 16, 4))
    clf = UnitClassifier(engine, "unit://t")
    clf.feed(Record([Cell(spaced, "invoice_number", "r0"), Cell(spaced, "card_number", "r0")]))
    out = clf.finish()
    assert [f["location"] for f in out] == ["r0"] and out[0]["confidence"] == "very_likely"
    clf = UnitClassifier(engine, "unit://t")
    clf.feed(Record([Cell(spaced, "invoice_number", "r0")]))
    assert clf.finish() == []


def test_aggregation_threshold_and_findings_schema():
    clf = UnitClassifier(_engine(), "unit://t", config={"aggregation_threshold": 0})
    for i in range(30):
        clf.feed(Record([Cell(f"user{i}@acme-corp.io", "email", f"Row {i}")]))
    out = clf.finish()
    assert len(out) == 30
    required = {"resource_id", "detector", "category", "severity", "value", "location", "confidence", "evidence", "value_hash"}
    assert all(required <= set(f) for f in out)
    assert all(f["confidence"] == "very_likely" for f in out)  # column density lifts self-validating cells


def test_unit_name_is_context():
    # Macie's path rule: a bare card number in a collection named credit_cards is likely; in events it is nothing
    card = _visa_numbers(1)[0]
    clf = UnitClassifier(_engine(), "mongodb://h/db/credit_cards", unit_name="credit_cards")
    clf.feed(Record([Cell(card, "number", "r0")]))
    out = clf.finish()
    assert [(f["detector"], f["confidence"]) for f in out] == [("Credit Card", "likely")]
    assert "unit:credit_cards" in out[0]["evidence"]
    clf = UnitClassifier(_engine(), "mongodb://h/db/events", unit_name="events")
    clf.feed(Record([Cell(card, "number", "r0")]))
    assert clf.finish() == []
    # recognizer field hints count too: an SSN-shaped value in a sheet named ssn_export
    clf = UnitClassifier(_engine(), "s3://b/hr.xlsx [ssn_export]", unit_name="hr.xlsx [ssn_export]")
    clf.feed(Record([Cell("219-09-9999", "ref", "r0")]))
    assert [(f["detector"], f["confidence"]) for f in clf.finish()] == [("US SSN", "likely")]
    # only `possible` candidates are lifted: a very weak pattern (Indian passport, 0.1) still needs its column name
    clf = UnitClassifier(_engine(), "s3://b/hr.xlsx [passports]", unit_name="hr.xlsx [passports]")
    clf.feed(Record([Cell("A2096457", "ref", "r0")]))
    assert clf.finish() == []


def test_sibling_columns_raise_certainty():
    # Sentra: an expiry and a CVV column next to bare card numbers make the card column certain
    cards = _visa_numbers(5)

    def rows(with_siblings):
        for i, card in enumerate(cards):
            cells = [Cell(card, "number", f"Row {i}")]
            if with_siblings:
                cells += [Cell("12/27", "expiry", f"Row {i}"), Cell("123", "cvv", f"Row {i}")]
            yield Record(cells)

    clf = UnitClassifier(_engine(), "unit://t")
    for r in rows(True):
        clf.feed(r)
    out = clf.finish()
    assert {f["confidence"] for f in out} == {"very_likely"} and len(out) == 5
    assert all("siblings:cvv,expiry" in f["evidence"] and "column:1.00" in f["evidence"] for f in out)
    clf = UnitClassifier(_engine(), "unit://t")
    for r in rows(False):
        clf.feed(r)
    assert {f["confidence"] for f in clf.finish()} == {"likely"}


def test_classified_column_is_exclusive():
    # a phone column where one bare number happens to pass the NHS mod-11 check, in rows with identity
    # context (name + e-mail promote it): the phone verdict owns the column, the NHS coincidence is dropped
    engine = _engine()
    nhs_shaped = "9434765919"  # mod-11 valid
    clf = UnitClassifier(engine, "unit://customers", unit_name="customers")
    for i in range(20):
        phone = nhs_shaped if i == 0 else f"+91 98{i:03d}0 {10000 + i}"
        clf.feed(
            Record([
                Cell("Priya Sharma", "full_name", f"Row {i}, Column 'full_name'"),
                Cell(f"user{i}@acme-corp.io", "email", f"Row {i}, Column 'email'"),
                Cell(phone, "phone", f"Row {i}, Column 'phone'"),
            ]),
        )
    out = clf.finish()
    phone_detectors = {f["detector"] for f in out if "Column 'phone'" in f["location"]}
    assert phone_detectors == {"Phone Number"}, phone_detectors
    # the same coincidence in a column that has no verdict of its own is still promoted by the record
    clf = UnitClassifier(engine, "unit://customers", unit_name="customers")
    clf.feed(
        Record([
            Cell("Priya Sharma", "full_name", "Row 0, Column 'full_name'"),
            Cell("user@acme-corp.io", "email", "Row 0, Column 'email'"),
            Cell(nhs_shaped, "ref", "Row 0, Column 'ref'"),
        ]),
    )
    assert {f["detector"] for f in clf.finish() if "Column 'ref'" in f["location"]} == {"UK_NHS"}


# --------------------------------------------------------------------------- records

def test_flatten_and_document_record():
    doc = {"a": {"b": [1, {"c": "x"}]}, "d": None, "e": b"bytes", "f": True}
    assert list(flatten(doc)) == [("a.b[0]", "b", "1"), ("a.b[1].c", "c", "x"), ("e", "e", "bytes")]
    assert collapse_indices("orders[3].items[0].sku") == "orders[].items[].sku"
    record = document_record(doc, lambda path: f"Field '{path}'")
    assert [(c.field, c.key, c.location) for c in record.cells][1] == ("a.b[1].c", "a.b[].c", "Field 'a.b[1].c'")
    assert record.cells[1].leaf == "c" and record.shape == "record"


# --------------------------------------------------------------------------- parsers

def test_file_parsers_yield_records_and_blobs():
    root = tempfile.mkdtemp()

    csv_path = os.path.join(root, "people.csv")
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("name,email,notes\nAlice,alice@acme-corp.io,hello\nBob,,x\n")
    units = list(iter_units(csv_path, "res://people.csv"))
    assert [u[0] for u in units] == ["res://people.csv"]
    records = list(units[0][1])
    assert len(records) == 2 and records[0].shape == "columnar"
    assert [(c.field, c.value) for c in records[0].cells] == [("name", "Alice"), ("email", "alice@acme-corp.io"), ("notes", "hello")]
    assert records[1].cells[0].location == "Chunk 0, Row 1, Column 'name'"

    json_path = os.path.join(root, "people.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump([{"email": "a@acme-corp.io", "profile": {"phone": "+1 555 123 4567"}}], f)
    (_, stream), = iter_units(json_path, "res://people.json")
    records = list(stream)
    assert len(records) == 1 and [c.field for c in records[0].cells] == ["email", "profile.phone"]
    assert records[0].cells[1].location == "JSON Path 'item[0].profile.phone'"

    obj_path = os.path.join(root, "config.json")
    with open(obj_path, "w", encoding="utf-8") as f:
        json.dump({"db": {"password": "SuperSecret123!"}, "tags": ["a", "b"]}, f)
    (_, stream), = iter_units(obj_path, "res://config.json")
    cells = [c for r in list(stream) for c in r.cells]
    assert [(c.field, c.key) for c in cells] == [("db.password", "db.password"), ("tags.item", "tags[]"), ("tags.item", "tags[]")]

    jsonl_path = os.path.join(root, "events.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        f.write('{"user": {"email": "x@acme-corp.io"}}\n\n{"user": {"email": "y@acme-corp.io"}}\n')
    (_, stream), = iter_units(jsonl_path, "res://events.jsonl")
    records = list(stream)
    assert [r.cells[0].location for r in records] == ["Line 1, Path 'user.email'", "Line 3, Path 'user.email'"]

    txt_path = os.path.join(root, "notes.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("first line\nkey AKIA1234567890ABCDEF here\n")
    (_, stream), = iter_units(txt_path, "res://notes.txt")
    blobs = list(stream)
    assert len(blobs) == 1 and isinstance(blobs[0], TextBlob)
    start = blobs[0].text.index("AKIA")
    assert blobs[0].location_for(start, start + 20) == "Line 2, Column 5-25"

    zip_path = os.path.join(root, "bundle.zip")
    with zipfile.ZipFile(zip_path, "w") as z:
        z.write(csv_path, "people.csv")
        z.write(txt_path, "docs/notes.txt")
    seen = {}
    for unit_id, stream in iter_units(zip_path, "res://bundle.zip"):
        seen[unit_id] = len(list(stream))  # each stream is consumed before the archive generator advances
    assert seen == {"res://bundle.zip#people.csv": 2, "res://bundle.zip#docs/notes.txt": 1}


# --------------------------------------------------------------------------- connector contract

class _ListScanner(BaseScanner):
    """A connector in a dozen lines: enumerate units, stream records, let the pipeline judge."""

    def __init__(self, engine, tables, config=None):
        super().__init__(engine, config)
        self.tables = tables
        self.stats = {"tables_scanned": 0, "errors": 0}

    def iter_scan(self, target):
        for name, rows in self.tables.items():
            resource_id = f"list://{target['store']}/{name}"
            findings = self.classify(resource_id, self._records(rows), location_fn=lambda c, n: f"Column '{c}' ({n} matches)")
            self.stats["tables_scanned"] += 1
            yield resource_id, name, self.dedup_findings(findings)

    def scan(self, target):
        return self.collect(target)

    @staticmethod
    def _records(rows):
        for idx, row in enumerate(rows):
            if row is None:
                raise RuntimeError("connection lost")
            yield Record([Cell(str(v), k, f"Row {idx}, Column '{k}'") for k, v in row.items() if v])


def test_new_connector_gets_the_whole_pipeline_for_free():
    tables = {
        "users": [{"id": i, "email": f"user{i}@acme-corp.io", "password": "SuperSecret123!"} for i in range(30)],
        "settings": [{"id": 1, "flag": "on"}],
    }
    scanner = _ListScanner(_engine(), tables)
    units = {name: findings for _, name, findings in scanner.iter_scan({"store": "demo"})}
    assert set(units) == {"users", "settings"} and units["settings"] == []
    by_detector = {f["detector"]: f for f in units["users"]}
    assert set(by_detector) == {"Email", "Password Pattern"}
    assert by_detector["Email"]["aggregated"] is True and by_detector["Email"]["occurrences"] == 30
    assert by_detector["Email"]["resource_id"] == "list://demo/users"
    assert by_detector["Password Pattern"]["confidence"] == "very_likely"
    assert len(scanner.scan({"store": "demo"})) == 2 and scanner.stats["tables_scanned"] == 4


def test_connector_stream_errors_keep_partial_findings():
    rows = [{"email": "a@acme-corp.io"}, {"email": "b@acme-corp.io"}, None, {"email": "c@acme-corp.io"}]
    scanner = _ListScanner(_engine(), {"t": rows})
    findings = scanner.scan({"store": "demo"})
    assert sorted(f["value"] for f in findings) == ["a@acme-corp.io", "b@acme-corp.io"]
    assert scanner.stats["errors"] == 1 and scanner.stats["error_details"][0].startswith("list://demo/t: connection lost")
