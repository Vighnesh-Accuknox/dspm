"""
Every detector name the engine can emit must have an entry in
fixtures/findings-mapping.json, otherwise the CSPM backend cannot rate it.
"""
import json
import re
from pathlib import Path

from src.engine import layers, tokens
from src.engine.recognizers import load_all

ROOT = Path(__file__).resolve().parent.parent


def _mapping():
    data = json.loads((ROOT / "fixtures" / "findings-mapping.json").read_text())
    return data[0] if isinstance(data, list) else data


def _layer_detector_names():
    src = (ROOT / "src" / "engine" / "layers.py").read_text()
    names = set(re.findall(r'_finding\(\s*"([^"]+)"', src))
    names |= set(re.findall(r'\badd\("([^"]+)"', src))
    names |= set(re.findall(r'\bdet = "([^"]+)" if', src))
    names |= {"Secret.PasswordHash", "Password Pattern", "Bearer Token", "API Key", "OAuth Token"}
    return names


def test_every_detector_name_is_mapped():
    mapping = _mapping()
    names = _layer_detector_names()
    names |= {name for name, _ in tokens.VENDOR_TOKEN_RULES}
    names |= {rule.name for rule in load_all()}
    names |= {"Secret.TokenLikeValue", "Encrypted Secret", "PII.PersonName"}
    missing = sorted(n for n in names if n not in mapping)
    assert not missing, f"detector names without a mapping entry: {missing}"


def test_mapping_entries_are_well_formed():
    mapping = _mapping()
    required = {"finding_name", "risk_factor", "category", "sensitivity", "final_risk_factor", "description", "remediation_advice"}
    for name, entry in mapping.items():
        assert required <= set(entry), (name, required - set(entry))
        assert entry["final_risk_factor"] in {"Critical", "High", "Medium", "Low", "Lowest"}, name


def test_rule_sets_load_without_duplicates():
    rules = load_all()
    names = [r.name for r in rules]
    assert len(names) == len(set(names))
    assert len(rules) >= 85
    assert {"US SSN", "IN Aadhaar", "GB NINO", "CA SIN", "IN PAN", "IBAN", "PII.IPAddress"} <= set(names)
    # every rule ships a valid example that its own patterns match
    from src.engine.rules import run_rule
    for rule in rules:
        assert rule.examples, rule.name
        assert run_rule(rule, rule.examples[0]), (rule.name, rule.examples[0])
    assert layers.CONTEXT_WORDS  # layer context words exist
