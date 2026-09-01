"""
Builds sample_data/all_detectors.jsonl and sample_data/all_detectors.txt: one
synthetic example per detector the engine can emit, in the shape that lets
each detector fire - a JSON Lines document per detector whose field name
carries the detector's column hint, and a text line "keyword: value" for the
unstructured path. Values come from the recognizer examples and the mapping's
sample values (all synthetic); documented examples the engine deliberately
ignores (AWS AKIAIOSFODNN7EXAMPLE, test card numbers, hunter2) are replaced by
detectable synthetic values.

    python -m tests.sample_dataset_builder          # rewrite both files, print coverage
    python -m tests.sample_dataset_builder --check  # scan the files, list detectors not found

tests/test_sample_dataset.py asserts the checked-in files still cover every
detector they list.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.engine import tokens as tk  # noqa: E402
from src.engine.detector import DetectionEngine  # noqa: E402
from src.engine.recognizers import load_all, regions  # noqa: E402

OUT_JSONL = ROOT / "sample_data" / "all_detectors.jsonl"
OUT_TXT = ROOT / "sample_data" / "all_detectors.txt"

# Layer detectors (src/engine/layers.py): field name + value that make each one fire on its own
LAYER_SAMPLES = {
    "Email": ("email", "priya.sharma@acme-corp.io"),
    "Phone Number": ("phone", "+91 98765 43210"),
    "Date of Birth": ("date_of_birth", "1985-07-30"),
    "Address": ("street_address", "221B Baker Street, London"),
    "PII.PersonName": ("full_name", "Priya Sharma"),
    "Password Pattern": ("config", "password=Tr0ub4dor&3xF!9"),
    "Secret.PasswordHash": ("password_hash", "$2b$12$KIXQ4l1h9vN2k7XpQ8wY5uJ3m6R1sT0aB4cD5eF6gH7iJ8kL9mN0o"),
    "API Key": ("api_key", "k9J2x7Qw4Zt1Lp8Vb3Nc6Hs5Yd0Rf2Mg4Ta7"),
    "Bearer Token": ("authorization", "Bearer k9J2x7Qw4Zt1Lp8Vb3Nc6Hs5Yd0Rf2Mg4T"),
    "OAuth Token": ("oauth", "access_token=k9J2x7Qw4Zt1Lp8Vb3Nc6Hs5Yd0Rf2Mg"),
    "JWT Token": ("session", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
    "AWS Access Key": ("aws_access_key_id", "AKIAK9J2X7QW4ZT1LP8V"),
    "AWS Secret Access Key": ("aws_secret_access_key", "k9J2x7Qw4Zt1Lp8Vb3Nc6Hs5Yd0Rf2Mg4Ta7Ue9W"),
    "Private Key Header": ("private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAk9J2x7Qw4Zt1Lp8Vb3Nc6Hs5Yd0Rf2Mg4Ta7Ue9WkJ2x7Qw4Zt1Lp8Vb3Nc6H\n-----END RSA PRIVATE KEY-----"),
    "Credentials in URL": ("database_url", "postgresql://scanner:Tr0ub4dor3xF@db.internal:5432/appdb"),
    "Basic Auth Credentials": ("authorization_header", "Basic c2Nhbm5lcjpUcjB1YjRkb3IzeEY="),
    "Credit Card": ("card_number", "4539 1488 0343 6467"),
    "IBAN": ("iban", "DE89 3704 0044 0532 0130 00"),
    "SWIFT/BIC": ("swift_code", "DEUTDEFF500"),
    "Bank Account": ("bank_account_number", "5023918476"),
    "Healthcare Data Detection": ("clinical_notes", "patient admitted to hospital; diagnosis confirmed; prescription issued by physician"),
    "High Entropy Secret": ("secret", "k9J2x7Qw4Zt1Lp8Vb3Nc6Hs5Yd0Rf2Mg4Ta7Ue9WkJ2x7Qw4Z"),
    "Encrypted Secret": ("payload", "U2FsdGVkX1+k9J2x7Qw4Zt1Lp8Vb3Nc6Hs5Yd0Rf2Mg4Ta7Ue9WkJ2x7Qw4Zt1Lp8Vb3Nc6H"),
}
# Mapping entries without a producing detector, or detectors that need a whole column / are disabled
NOT_REPRODUCIBLE = {
    "Secret.TokenLikeValue": "reported only for a column that is mostly random tokens (REPORT_TOKEN_LIKE_VALUES=true)",
    "PII.UserIdentifier": "mapping entry without a detector",
    "Secret.ActivationOrAuthKey": "mapping entry without a detector",
    "URL": "recognizer shipped disabled",
    "UUID": "recognizer shipped disabled",
}


# Rule examples that the engine drops by design (private IPs) or that need a specific field to fire
RULE_OVERRIDES = {
    "PII.IPAddress": ("public_ip", "8.8.8.8"),
    "MAC_ADDRESS": ("device_mac", "3C:52:82:4F:9A:1B"),
    "US_PRIOR_AUTHORIZATION_NUMBER": ("preauthorization_number", "PA-204815937"),
    "US_HEALTH_INSURANCE_MEMBER_ID": ("member_id", "HPN70482A9"),
    "US_CLAIM_NUMBER": ("claim_number", "CLM402817365"),
    "US_PRESCRIPTION_NUMBER": ("prescription_number", "RX702948135"),
    "US_REFERRAL_NUMBER": ("referral_number", "REF204815"),
    "US_ALIEN_REGISTRATION": ("alien_number", "A20481537"),
}
# Detectors the generic layers shadow on the same value (overlap resolution keeps the generic one)
NOT_REPRODUCIBLE.update({
    "PH_MOBILE_NUMBER": "reported as Phone Number (the generic phone layer parses the number)",
    "ZA_MOBILE_NUMBER": "reported as Phone Number (the generic phone layer parses the number)",
    "ZA_TELEPHONE_NUMBER": "reported as Phone Number (the generic phone layer parses the number)",
})

_CREDENTIAL_WORDS = ("auth", "token", "secret", "key", "password", "session", "cookie")


def field_for_rule(rule, used) -> str:
    """
    A field name the rule's own hint recognises - region + context word, with
    number/id suffixes tried when the bare word is not enough - unique per
    detector so every detector owns its own column (a shared `passport` column
    would be classified once, for one country).
    """
    from src.engine.context import is_credential_field, is_identifier_field, is_numeric_id_field

    region = (rule.region or "").lower()
    words = [w.replace(" ", "_").replace("-", "_").replace(".", "").replace("'", "") for w in rule.context[:4]] or [rule.name.lower()]
    candidates = []
    for word in words:
        for shape in (f"{region}_{word}", f"{region}_{word}_number", f"{region}_{word}_no", f"{word}_number", f"{region}_{word}_id", word):
            candidates.append(shape.strip("_"))
    candidates.append(rule.name.lower().replace(" ", "_").replace("/", "_").replace(".", "_"))
    hint = rule._field_hint_re
    chosen = None
    for field in candidates:
        if any(w in field for w in _CREDENTIAL_WORDS) and is_credential_field(field):
            continue
        if hint is not None and not hint.search(field):
            continue
        if is_identifier_field(field) or is_numeric_id_field(field):
            continue
        chosen = field
        break
    if chosen is None:
        chosen = candidates[0]
    if chosen in used:
        chosen = f"{chosen}_{rule.name.lower().replace(' ', '_').replace('/', '_').replace('.', '_')}"
    used.add(chosen)
    return chosen


def detectable_example(engine, rule, field) -> str:
    """
    The rule's example, or a digit-mutated variant of it, that the engine reports
    for this field: rule examples such as 12CB34567 are placeholder-shaped by
    construction and the engine ignores placeholders on purpose.
    """
    import random

    from src.engine.rules import run_rule

    rng = random.Random(rule.name)

    def detected(value):
        return any(f["detector"] == rule.name for f in engine.scan_text(value, field_name=field, min_confidence="possible"))

    for example in rule.examples:
        if detected(example):
            return example
    example = rule.examples[0]
    positions = [i for i, c in enumerate(example) if c.isdigit()]
    for _ in range(400):
        chars = list(example)
        for pos in positions:
            chars[pos] = rng.choice("0123456789")
        candidate = "".join(chars)
        results = run_rule(rule, candidate)
        if not results or (rule.validator is not None and not any(r["validated"] for r in results if r["value"] == candidate)):
            continue
        if detected(candidate):
            return candidate
    return example


def build():
    mapping = json.loads((ROOT / "fixtures" / "findings-mapping.json").read_text())[0]
    rows = []
    used = set()
    engine = DetectionEngine({"enabled_regions": regions(), "ner": False})
    for rule in load_all():
        if not rule.enabled or rule.name in NOT_REPRODUCIBLE:
            continue
        if rule.name in RULE_OVERRIDES:
            field, value = RULE_OVERRIDES[rule.name]
            used.add(field)
        else:
            field = field_for_rule(rule, used)
            value = detectable_example(engine, rule, field)
        rows.append({"_detector": rule.name, "_region": rule.region or "generic", field: value})
    for name, (field, value) in LAYER_SAMPLES.items():
        rows.append({"_detector": name, "_region": "layer", field: value})
    seen = set()
    for name, _ in tk.VENDOR_TOKEN_RULES:
        if name in seen:
            continue
        seen.add(name)
        rows.append({"_detector": name, "_region": "secret", "value": mapping[name]["sample_value"]})
    covered = {r["_detector"] for r in rows}
    missing = sorted(n for n in mapping if n not in covered and n not in NOT_REPRODUCIBLE)
    return rows, missing


def write(rows):
    OUT_JSONL.parent.mkdir(exist_ok=True)
    with OUT_JSONL.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    with OUT_TXT.open("w", encoding="utf-8") as fh:
        fh.write("# One synthetic example per detector; the keyword before each value gives the unstructured path its context.\n")
        for row in rows:
            field, value = next((k, v) for k, v in row.items() if not k.startswith("_"))
            fh.write(f"{field.replace('_', ' ')}: {value}\n")


def scan_files():
    from src.scanners.aws.s3 import S3Scanner

    engine = DetectionEngine({"enabled_regions": regions(), "entropy_report_uncorroborated": False})
    scanner = S3Scanner(engine)
    jsonl = {f["detector"] for f in scanner.scan_local_file(str(OUT_JSONL), "sample://all_detectors.jsonl")}
    text = {f["detector"] for f in scanner.scan_local_file(str(OUT_TXT), "sample://all_detectors.txt")}
    return jsonl, text


def expected_detectors():
    with OUT_JSONL.open(encoding="utf-8") as fh:
        return {json.loads(line)["_detector"] for line in fh if line.strip()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="scan the checked-in files and report detectors not found")
    args = ap.parse_args()
    rows, missing = build()
    if not args.check:
        write(rows)
        print(f"wrote {OUT_JSONL.relative_to(ROOT)} and {OUT_TXT.relative_to(ROOT)}: {len(rows)} detectors")
    if missing:
        print("mapping entries without a sample:", missing)
    if args.check:
        jsonl, text = scan_files()
        expected = expected_detectors()
        print("not detected in JSONL:", sorted(expected - jsonl) or "none")
        print("not detected in text:", sorted(expected - text) or "none")
        return 1 if expected - jsonl else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
