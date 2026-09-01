"""Confidence tiers (src/engine/confidence.py) and detector policies (src/engine/policy.py)."""
import json
from pathlib import Path

from src.engine import confidence as conf
from src.engine.detector import DetectionEngine
from src.engine.policy import CATEGORY_DEFAULTS, POLICIES, DetectorPolicy, policy_for, register
from src.engine.recognizers import load_all

ROOT = Path(__file__).resolve().parent.parent


def test_tier_boundaries_and_normalisation():
    assert conf.tier_for(1.0) == "very_likely" and conf.tier_for(0.9) == "very_likely"
    assert conf.tier_for(0.85) == "likely" and conf.tier_for(0.8) == "likely"
    assert conf.tier_for(0.6) == "possible" and conf.tier_for(0.5) == "possible"
    assert conf.tier_for(0.3) is None
    assert conf.normalize(None) == "likely" and conf.normalize("") == "likely"
    assert conf.normalize(0.9) == "very_likely" and conf.normalize("0.8") == "likely" and conf.normalize(0.5) == "possible"
    assert conf.normalize("Very Likely") == "very_likely" and conf.normalize("HIGH") == "very_likely"
    assert conf.promote("possible") == "likely" and conf.promote("very_likely") == "very_likely"
    assert conf.demote("possible") == "possible" and conf.max_tier([None, "possible", "likely"]) == "likely"
    assert conf.at_least("likely", "possible") and not conf.at_least("possible", "likely")
    try:
        conf.normalize("maybe")
        raise AssertionError("unknown tier accepted")
    except ValueError:
        pass


def test_evidence_conventions():
    assert conf.evidence_of({"score": 0.85}) == ["format"]
    assert conf.evidence_of({"score": 0.85, "evidence": None}) == ["shape"]
    assert conf.evidence_of({"score": 0.6, "evidence": None}) == ["shape"]
    assert conf.evidence_of({"score": 1.0, "validated": True, "context_word": "ssn", "field_hint": True}) == ["checksum", "context:ssn", "field"]
    assert conf.evidence_of({"score": 0.9, "evidence": "inline", "entropy": 4.7}) == ["context:inline"]
    assert conf.has_context(["context:ssn"]) and conf.has_context(["field"]) and not conf.has_context(["shape", "checksum"])
    assert conf.has_validation(["checksum"]) and conf.has_validation(["format"]) and not conf.has_validation(["shape"])


def test_engine_reporting_tier_and_legacy_threshold():
    # the legacy float threshold maps to a tier; 0.9-scored findings are reported at 0.9 (tier floors are inclusive)
    engine = DetectionEngine({"score_threshold": 0.9})
    assert engine.min_confidence == "very_likely" and engine.threshold == 0.9
    found = engine.scan_text("SuperSecret123!", field_name="password")
    assert [(f["detector"], f["confidence"]) for f in found] == [("Password Pattern", "very_likely")]
    assert DetectionEngine().min_confidence == "likely"
    assert DetectionEngine({"min_confidence": "possible"}).threshold == 0.5
    # a per-call override yields candidates without touching the engine's tier
    engine = DetectionEngine({"enabled_regions": ["US"]})
    assert engine.scan_text("219-09-9999") == []
    assert [f["confidence"] for f in engine.scan_text("219-09-9999", min_confidence="possible")] == ["possible"]
    assert engine.min_confidence == "likely"
    for f in engine.scan_text("ssn 219-09-9999 email carol@acme-corp.io"):
        assert f["confidence"] in conf.TIERS and isinstance(f["evidence"], list) and f["value_hash"]


def test_every_detector_resolves_to_a_policy():
    mapping = json.loads((ROOT / "fixtures" / "findings-mapping.json").read_text())
    mapping = mapping[0] if isinstance(mapping, list) else mapping
    for name, entry in mapping.items():
        policy = policy_for(name, entry["category"])
        assert isinstance(policy, DetectorPolicy), name
        assert policy.context in ("required", "boost", "none")
        assert 0 < policy.column_ratio <= 1.0 and policy.column_min_matches >= 1 and policy.min_count >= 1
    for rule in load_all():
        assert isinstance(policy_for(rule.name, rule.category), DetectorPolicy)
    # regional identifiers need context; self-identifying formats do not
    assert policy_for("US SSN", "Regional Compliance").context == "required"
    assert policy_for("IN Aadhaar", "Regional Compliance").identity_corroboration
    assert policy_for("JWT Token", "Credentials and Secrets").context == "none"
    assert policy_for("Email", "PII").identity and policy_for("Email", "PII").context == "none"
    assert not policy_for("SWIFT/BIC", "Financial Data").count_promotion
    assert not policy_for("High Entropy Secret", "Entropy-Based Secret Detection").column_classify
    assert policy_for("Unknown Detector", "Nowhere") == DetectorPolicy()
    assert set(CATEGORY_DEFAULTS) >= {entry["category"] for entry in mapping.values()}


def test_policy_registration_and_field_veto():
    original = POLICIES.get("Phone Number")
    try:
        policy = register("Phone Number", min_count=3)
        assert policy.min_count == 3 and policy.identity is True
        assert policy.vetoed_by_field("port") and not policy.vetoed_by_field("mobile")
    finally:
        POLICIES["Phone Number"] = original
    try:
        DetectorPolicy(context="maybe")
        raise AssertionError("invalid context accepted")
    except ValueError:
        pass


def test_new_vendor_token_formats():
    from src.engine import tokens as tk
    samples = {
        "DigitalOcean Token": "dop_v1_" + "7c3e1a9f5b2d4e6a" * 4,
        "Google OAuth Client Secret": "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",
        "Linear API Key": "lin_api_" + "k9J2x7Qw4Zt1Lp8Vb3Nc6Hs5Yd0Rf2Mg4Ta7Ue9W",
        "New Relic Key": "NRAK-K7J2X9QW4ZT1LP8VB3NC6HS5YD0",
        "Supabase Key": "sbp_" + "7c3e1a9f" * 5,
        "Pulumi Token": "pul-" + "5b2d9e7a" * 5,
        "Netlify Token": "nfp_" + "k9J2x7Qw4Zt1Lp8Vb3Nc6Hs5Yd0Rf2Mg4Ta7",
        "Airtable Token": "patK9J2x7Qw4Zt1Lp." + "7c3e1a9f" * 8,
    }
    engine = DetectionEngine()
    for detector, value in samples.items():
        found = engine.scan_text(f"token = {value}")
        assert [f["detector"] for f in found] == [detector], (detector, found)
        assert found[0]["confidence"] == "very_likely"
    assert all(name in {n for n, _ in tk.VENDOR_TOKEN_RULES} for name in samples)


def test_vendor_formats_reject_degenerate_values():
    from src.engine import tokens as tk

    engine = DetectionEngine()
    for value in ("A" * 400, "sl." + "A" * 140, "M" + "A" * 30 + ".AAAAAA." + "A" * 30, "xoxb-" + "1" * 12 + "-" + "1" * 12 + "-" + "x" * 24):
        assert tk.is_degenerate(value), value[:40]
        assert engine.scan_text(value, field_name="content") == [], value[:40]
    real = "AAAAAAAAAAAAAAAAAAAAA" + "k9J2x7Qw4Zt1Lp8Vb3Nc6Hs5Yd0Rf2Mg4Ta7Ue9W%3D" * 3
    assert not tk.is_degenerate(real)
    assert [f["detector"] for f in engine.scan_text(real)] == ["Twitter Bearer Token"]
