"""
The extended recognizer packs (europe_extra, americas, asia_pacific,
middle_east_africa, identifiers): every rule's examples validate, bool
validators reject mutated check digits, packs are region-gated, and the
generic identifiers stay silent without context.
"""
import importlib
import json
from pathlib import Path

from src.engine.detector import DetectionEngine
from src.engine.layers import scan_regional
from src.engine.recognizers import load_all, regions
from src.engine.rules import run_rule
from src.pipeline import Cell, Record, UnitClassifier

NEW_MODULES = ("europe_extra", "americas", "asia_pacific", "middle_east_africa", "identifiers")
# validators that return None on failure (or validate a date only): a mutated digit is not proof of invalidity
SOFT_VALIDATORS = {"DK_CPR", "LV_PERSONAS_KODS", "GB_UTR", "MX_RFC", "ID_NIK", "MY_MYKAD", "LK_NIC", "EG_NATIONAL_ID", "NZ_NHI", "PASSPORT_MRZ", "GEO_COORDINATES"}


def _new_rules():
    out = []
    for name in NEW_MODULES:
        out.extend(importlib.import_module(f"src.engine.recognizers.{name}").RULES)
    return out


def _mutations(example):
    positions = [i for i, c in enumerate(example) if c.isdigit()]
    for pos in positions[-4:]:
        for d in "0123456789":
            if d != example[pos]:
                yield example[:pos] + d + example[pos + 1:]


def test_examples_validate_and_mutations_are_rejected():
    for rule in _new_rules():
        assert rule.examples, rule.name
        for example in rule.examples:
            results = [r for r in run_rule(rule, example) if r["value"] == example] or run_rule(rule, example)
            assert results, (rule.name, example)
            if rule.validator is not None and rule.name not in SOFT_VALIDATORS:
                assert any(r["validated"] for r in results), (rule.name, example)
        if rule.validator is not None and rule.name not in SOFT_VALIDATORS:
            muts = list(_mutations(rule.examples[0]))
            rejected = sum(1 for m in muts if rule.validator(m) is False)
            assert rejected / len(muts) >= 0.6, (rule.name, rejected, len(muts))


def test_packs_are_region_gated_and_mapped():
    mapping = json.loads((Path(__file__).resolve().parent.parent / "fixtures" / "findings-mapping.json").read_text())[0]
    names = {r.name for r in load_all()}
    assert len(names) == len(load_all()) and len(regions()) >= 60
    for rule in _new_rules():
        assert rule.name in mapping, rule.name
        text = f"{rule.context[0]}: {rule.examples[0]}"
        if rule.region:
            found = {f["detector"] for f in scan_regional(text, [rule.region])}
            assert rule.name in found, (rule.name, text)
            other = "US" if rule.region != "US" else "GB"
            assert rule.name not in {f["detector"] for f in scan_regional(text, [other])}, rule.name


def test_checksum_ids_report_with_context_or_column():
    engine = DetectionEngine({"enabled_regions": ["BR", "NL", "CN", "AE", "FR"]})
    cases = {
        "BR_CPF": ("CPF", "823.855.915-45"), "NL_BSN": ("BSN", "327440430"), "CN_RESIDENT_ID": ("身份证", "110105194912315912"),
        "AE_EMIRATES_ID": ("Emirates ID", "784-1990-1311311-5"), "FR_NIR": ("NIR", "1 85 05 78 006 084 91"),
    }
    for detector, (keyword, value) in cases.items():
        assert [f["detector"] for f in engine.scan_text(f"{keyword}: {value}")] == [detector], detector
        assert [f["detector"] for f in engine.scan_text(value, field_name=keyword.lower().replace(" ", "_"))] == [detector], detector
    # a bare checksum-valid number with no context is only `possible`
    assert engine.scan_text("327440430", field_name="ref") == []
    assert [f["confidence"] for f in engine.scan_text("327440430", field_name="ref", min_confidence="possible")] == ["possible"]


def test_generic_identifiers_need_context_and_do_not_fire_on_technical_values():
    engine = DetectionEngine({"enabled_regions": regions()})
    assert engine.scan_text("352318504122227", field_name="misc") == []
    assert [f["detector"] for f in engine.scan_text("352318504122227", field_name="device_imei")] == ["IMEI"]
    assert [f["detector"] for f in engine.scan_text("imei 35-845422-110932-2")] == ["IMEI"]
    assert [f["detector"] for f in engine.scan_text("12.9716, 77.5946", field_name="gps_location")] == ["GEO_COORDINATES"]
    assert engine.scan_text("12.9716, 77.5946", field_name="misc") == []
    assert [f["detector"] for f in engine.scan_text("L898902C36UTO7408122F1204159ZE184226B<<<<<10")] == ["PASSPORT_MRZ"]
    assert [f["detector"] for f in engine.scan_text("E11.9", field_name="diagnosis_code")] == ["ICD10_CODE"]
    assert engine.scan_text("E11.9", field_name="status") == []
    for text, field in (
        ("2026-09-01T18:39:38Z", "created_at"), ("v2.14.3-rc1", "app_version"), ("arn:aws:iam::123456789012:role/scanner", "role"),
        ("i-0abc123def4567890", "instance_id"), ("sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "digest"),
        ("Order 3782164509 shipped", "notes"), ("1723456789", "epoch"), ("192.168.10.24", "host"),
    ):
        assert engine.scan_text(text, field_name=field) == [], (text, field)


def test_column_of_national_ids_classifies_with_every_pack():
    import random
    from src.engine.recognizers.americas import _validate_br_cpf

    rng = random.Random(5)
    values = set()
    while len(values) < 12:
        candidate = "".join(rng.choice("0123456789") for _ in range(11))
        if _validate_br_cpf(candidate):
            values.add(f"{candidate[:3]}.{candidate[3:6]}.{candidate[6:9]}-{candidate[9:]}")
    engine = DetectionEngine({"enabled_regions": regions()})
    for column in ("document", "national_id"):
        clf = UnitClassifier(engine, "unit://kyc", unit_name="kyc")
        for i, value in enumerate(sorted(values)):
            clf.feed(Record([Cell(value, column, f"Row {i}")]))
        out = clf.finish()
        # with all 62 packs enabled - and a column name several packs hint on - coincidental checksum
        # passes and shape-only matches from other packs are dropped by column exclusivity
        assert {f["detector"] for f in out} == {"BR_CPF"}, (column, {(f["detector"], f["confidence"]) for f in out})
        assert out[0]["confidence"] in ("likely", "very_likely")


def test_new_vendor_secret_formats():
    from src.engine import tokens as tk
    mapping = json.loads((Path(__file__).resolve().parent.parent / "fixtures" / "findings-mapping.json").read_text())[0]
    engine = DetectionEngine()
    checked = 0
    for name in (
        "Groq API Key", "Replicate Token", "Perplexity API Key", "Pinecone API Key", "Buildkite Token", "RubyGems API Key",
        "Render Token", "Contentful Token", "Razorpay Key", "HubSpot Token", "SonarQube Token", "Brevo API Key",
        "Discord Webhook", "Neon Database Password", "Laravel App Key", "Netrc Credentials", "Bitcoin Private Key", "Alibaba Access Key",
    ):
        sample = mapping[name]["sample_value"]
        found = engine.scan_text(f"value = {sample}")
        assert name in [f["detector"] for f in found], (name, found)
        assert all(f["confidence"] == "very_likely" for f in found if f["detector"] == name)
        checked += 1
    assert checked == 18 and len({n for n, _ in tk.VENDOR_TOKEN_RULES}) >= 100


def test_every_vendor_format_passes_its_prefilter():
    from src.engine import tokens as tk
    mapping = json.loads((Path(__file__).resolve().parent.parent / "fixtures" / "findings-mapping.json").read_text())[0]
    misses = []
    for name in {n for n, _ in tk.VENDOR_TOKEN_RULES}:
        hits = {d for d, *_ in tk.find_vendor_tokens("x = " + mapping[name]["sample_value"])}
        if name not in hits:
            misses.append(name)
    assert not misses, misses
