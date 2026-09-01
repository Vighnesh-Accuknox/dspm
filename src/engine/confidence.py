"""
Confidence tiers.

Every classification engine we studied reports a discrete confidence rather than
a raw score - Google Sensitive Data Protection (POSSIBLE / LIKELY / VERY_LIKELY,
minimum POSSIBLE by default), Microsoft Purview (low 65 / medium 75 / high 85),
Nightfall (Possible / Likely / Very Likely, "Possible is triggered by the
appearance of the token without considering context"), Wiz (per-finding
confidence with configurable alert thresholds). The engine's scores already
encode evidence tiers (see the layers.py docstring); this module names them so
callers and the findings JSON can reason about confidence without knowing the
arithmetic:

    very_likely  score >= 0.90  validated shape AND corroboration: checksum plus a
                                context word, a credential in a credential-named
                                field, a self-identifying vendor format, a JWT
                                with a decodable header
    likely       score >= 0.80  one strong signal: a self-validating shape alone
                                (valid e-mail, Luhn + issuer prefix with
                                separators, mod-97 IBAN) or a plausible shape
                                backed by its column name / a context word
    possible     score >= 0.50  a plausible shape only. Never reported on its own;
                                src/pipeline reports it when the column or file
                                makes it statistically credible (Orca's
                                statistical scan, Sentra's column rule)

Anything below `possible` (very weak patterns, documented examples,
placeholders) is dropped by the engine.
"""
from typing import Any, Dict, Iterable, List, Optional

TIERS = ("possible", "likely", "very_likely")
FLOORS = {"possible": 0.5, "likely": 0.8, "very_likely": 0.9}
DEFAULT_MIN_CONFIDENCE = "likely"

_RANK = {tier: index for index, tier in enumerate(TIERS)}
_ALIASES = {
    "very likely": "very_likely", "very-likely": "very_likely", "verylikely": "very_likely", "high": "very_likely",
    "medium": "likely", "low": "possible",
}


def tier_for(score: float) -> Optional[str]:
    """Tier a score falls into, None below the `possible` floor."""
    tier = None
    for name in TIERS:
        if score >= FLOORS[name]:
            tier = name
    return tier


def floor_for(tier: str) -> float:
    return FLOORS[normalize(tier)]


def normalize(value: Any, default: str = DEFAULT_MIN_CONFIDENCE) -> str:
    """
    Accepts a tier name (any case, 'very likely' / 'high' aliases), a legacy
    float score threshold (0.9 -> very_likely, 0.8 -> likely, else possible) or
    None (-> default) and returns a canonical tier name.
    """
    if value is None or value == "":
        return default
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return tier_for(float(value)) or "possible"
    text = str(value).strip().lower()
    text = _ALIASES.get(text, text)
    if text in _RANK:
        return text
    try:
        return normalize(float(text), default)
    except ValueError:
        raise ValueError(f"unknown confidence tier {value!r}; expected one of {TIERS}")


def rank(tier: str) -> int:
    return _RANK[normalize(tier)]


def at_least(tier: str, minimum: str) -> bool:
    return rank(tier) >= rank(minimum)


def promote(tier: str, steps: int = 1) -> str:
    return TIERS[min(len(TIERS) - 1, rank(tier) + steps)]


def demote(tier: str, steps: int = 1) -> str:
    return TIERS[max(0, rank(tier) - steps)]


def max_tier(tiers: Iterable[str]) -> Optional[str]:
    best = None
    for tier in tiers:
        if tier and (best is None or rank(tier) > rank(best)):
            best = tier
    return best


def has_context(evidence: Iterable[str]) -> bool:
    """True when the evidence carries corroboration beyond the value's own shape."""
    return any(e.startswith(("context:", "field", "key:", "record:", "column:")) or e in ("body", "jwt_header") for e in evidence)


def has_validation(evidence: Iterable[str]) -> bool:
    return any(e in ("checksum", "format") for e in evidence)


_ENTROPY_EVIDENCE = {
    "field": "field",
    "inline": "context:inline",
    "access_key": "context:access_key",
    "keyword": "context:keyword",
    "format": "format",
}


def evidence_of(finding: Dict[str, Any]) -> List[str]:
    """
    Compact, ordered list of the evidence a raw finding carries, derived from the
    extras the detection layers attach:

        checksum          a validator accepted the value
        format            the value is self-validating by shape (e-mail, IBAN, vendor token)
        context:<word>    a detector-specific keyword next to the value
        field             the column / field name names the entity
        key:<name>        the value is assigned to a credential keyword or field
        body|jwt_header   structural corroboration (private key body, decodable JWT)
        encoded:<kind>    found inside a base64 / JWT payload
        shape             random-looking token or key-shaped value with no corroboration
        needs_context     bare checksum-only number, capped at `possible`
        placeholder|test_card|private_ip|example   negative evidence
    """
    out: List[str] = []

    def add(item: str) -> None:
        if item and item not in out:
            out.append(item)

    if finding.get("validated"):
        add("checksum")
    if finding.get("context_word"):
        add(f"context:{finding['context_word']}")
    if finding.get("field_hint"):
        add("field")
    raw = finding.get("evidence")
    if isinstance(raw, str):
        add(_ENTROPY_EVIDENCE.get(raw, f"context:{raw}"))
    elif isinstance(raw, (list, tuple)):
        for item in raw:
            add(str(item))
    elif "evidence" in finding and raw is None:
        add("shape")  # the layer looked for corroboration and found none: shape only
    if finding.get("key"):
        add(f"key:{finding['key']}")
    if finding.get("has_body"):
        add("body")
    if finding.get("jwt_alg"):
        add("jwt_header")
    if finding.get("encoded"):
        add(f"encoded:{finding['encoded']}")
    if finding.get("region"):
        add(f"region:{finding['region']}")
    if finding.get("username"):
        add("credential_pair")
    if finding.get("needs_context"):
        add("needs_context")
    if finding.get("placeholder"):
        add("placeholder")
    if finding.get("test_card"):
        add("test_card")
    if finding.get("private_ip"):
        add("private_ip")
    if finding.get("example"):
        add("example")
    if not out and finding.get("score", 0.0) >= FLOORS["likely"]:
        add("format")
    return out
