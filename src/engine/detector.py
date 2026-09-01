"""
DetectionEngine: runs the detection layers on one text blob and turns their raw
matches into findings with a confidence tier.

    raw layers  ->  field-name suppression  ->  engine policies  ->  confidence
    floor  ->  overlap resolution (one finding per span, most specific detector
    wins)  ->  confidence tier + evidence + fingerprint

The engine judges one value at a time. Column density, record-level
corroboration and minimum counts - the statistical half of classification -
live in src/pipeline and consume the engine's `possible` candidates.

Configuration keys (all optional):
    enabled_regions               regional packs, e.g. ["US", "IN", "GB"]  (UK -> GB)
    phone_regions                 regions for national-format phone parsing (default: enabled_regions)
    min_confidence                lowest tier reported: possible | likely | very_likely (default likely);
                                  a legacy float score_threshold is accepted and mapped to a tier
    entropy_min_length            entropy candidate length (default 24)
    entropy_min_entropy           Shannon threshold for base64-ish tokens (default 4.5; hex uses 3.0)
    entropy_report_uncorroborated report random-looking tokens with no field/keyword evidence as
                                  Secret.TokenLikeValue (default False: dropped)
    field_suppression             drop token detectors in id/hash/etag fields etc. (default True)
    decode_base64                 decode base64 blobs and rescan the plaintext (default True)
    disabled_detectors            list of detector names never reported
    report_private_ips            report RFC1918 / loopback / link-local addresses as PII.IPAddress (default False)
    ner                           person names in prose via the optional spaCy model when installed (default True)
"""
import hashlib
import ipaddress
import re
from typing import Any, Dict, List, Optional

from src.engine import tokens as tk
from src.engine.confidence import evidence_of, floor_for, normalize, tier_for
from src.engine.context import is_suppressed_by_field
from src.engine.layers import (
    scan_credentials,
    scan_entropy,
    scan_financial,
    scan_generic,
    scan_healthcare,
    scan_pii,
    scan_regional,
)

# Higher wins when spans overlap: a JWT is not also a bearer token, two entropy
# blobs and a base64 payload; a card number is not also a bank account.
DETECTOR_PRIORITY = {
    "Private Key Header": 100,
    "JWT Token": 95,
    "AWS Access Key": 95,
    "Credentials in URL": 92,
    "Basic Auth Credentials": 92,
    "AWS Secret Access Key": 88,
    "Secret.PasswordHash": 85,
    "Password Pattern": 84,
    "API Key": 82,
    "OAuth Token": 82,
    "Bearer Token": 78,
    "Credit Card": 72,
    "IBAN": 72,
    "Email": 66,
    "Date of Birth": 62,
    "Phone Number": 60,
    "Bank Account": 52,
    "SWIFT/BIC": 45,
    "Encrypted Secret": 35,
    "PII.IPAddress": 32,
    "MAC_ADDRESS": 32,
    "CRYPTO": 40,
    "UUID": 25,
    "URL": 25,
    "High Entropy Secret": 20,
    "Secret.TokenLikeValue": 15,
    "Address": 10,
    "PII.PersonName": 10,
    "Healthcare Data Detection": 0,
}
_CATEGORY_PRIORITY = {
    "Credentials and Secrets": 80,
    "Financial Data": 60,
    "Regional Compliance": 60,
    "Healthcare Data (PHI)": 58,
    "PII": 50,
    "Entropy-Based Secret Detection": 20,
    "Technical Identifier": 25,
}
# Vendor token detectors are as certain as an AWS access key
for _name, _ in tk.VENDOR_TOKEN_RULES:
    DETECTOR_PRIORITY.setdefault(_name, 95)

_REGION_ALIASES = {"UK": "GB"}


def priority_of(finding: Dict[str, Any]) -> int:
    p = DETECTOR_PRIORITY.get(finding.get("detector"))
    if p is None:
        p = _CATEGORY_PRIORITY.get(finding.get("category"), 50)
    return p


def resolve_overlaps(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Keeps one finding per overlapping span: a finding is dropped when a kept
    finding of strictly higher priority contains it (or covers 80% of it).
    Same-detector duplicates on one span collapse to the best score. Findings
    extracted from an encoded payload (encoded=jwt/base64) are never suppressed
    by their container.
    """
    ordered = sorted(findings, key=lambda f: (-priority_of(f), -f.get("score", 0), -(f["end"] - f["start"]), f["start"]))
    kept: List[Dict[str, Any]] = []
    for f in ordered:
        length = max(1, f["end"] - f["start"])
        drop = False
        for k in kept:
            same = k["detector"] == f["detector"]
            if same and k["start"] <= f["start"] and f["end"] <= k["end"]:
                drop = True  # duplicate or nested match of the same detector
                break
            if f.get("encoded"):
                continue
            if priority_of(k) <= priority_of(f):
                continue
            overlap = min(k["end"], f["end"]) - max(k["start"], f["start"])
            if overlap > 0 and (k["start"] <= f["start"] and f["end"] <= k["end"] or overlap / length >= 0.8):
                drop = True
                break
        if not drop:
            kept.append(f)
    kept.sort(key=lambda f: (f["start"], -priority_of(f)))
    return kept


def _placeholder_number(value: str) -> bool:
    """111-22-3333, 000-00-0000, 1234 5678 9012 3456: every digit group one repeated digit or a straight run."""
    groups = [g for g in re.split(r"\D+", str(value)) if g]
    digits = "".join(groups)
    if len(digits) < 6:
        return False
    if all(len(set(g)) == 1 for g in groups):
        return True
    straight = "01234567890123456789"
    return digits in straight or digits in straight[::-1]


def _bare_number(value: str) -> bool:
    """Digits (or 1-2 letters + digits) with no separators, 6-20 digits: an id, a timestamp, a counter."""
    return re.fullmatch(r"[A-Za-z]{0,2}\d{6,20}", value) is not None


def _digit_groups(value: str) -> bool:
    """Digit groups joined by spaces / dots / dashes with 6-16 digits: 943 476 5919, 1234-567-893."""
    if re.fullmatch(r"[A-Za-z]{0,2}\d[\d .-]*\d", value) is None or not re.search(r"[ .-]", value):
        return False
    return 6 <= sum(c.isdigit() for c in value) <= 16


def _looks_like_epoch(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if digits != value.strip():
        return False
    if len(digits) == 10:
        return 1_300_000_000 <= int(digits) <= 2_200_000_000     # 2011 .. 2039 in seconds
    if len(digits) == 13:
        return 1_300_000_000_000 <= int(digits) <= 2_200_000_000_000  # same range in milliseconds
    return False


def _is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified


def fingerprint(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", errors="ignore")).hexdigest()[:16]


class DetectionEngine:
    """Coordinates detection layers and executes scans on text blobs."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        regions = self.config.get("enabled_regions") or []
        self.enabled_regions = [_REGION_ALIASES.get(str(r).upper(), str(r).upper()) for r in regions]
        self.phone_regions = [str(r).upper() for r in (self.config.get("phone_regions") or self.enabled_regions)]
        minimum = self.config.get("min_confidence")
        if minimum is None:
            minimum = self.config.get("score_threshold")  # legacy float threshold
        self.min_confidence = normalize(minimum)
        self.threshold = floor_for(self.min_confidence)  # score floor of the reporting tier
        self.entropy_min_length = int(self.config.get("entropy_min_length", 24))
        self.entropy_min_entropy = float(self.config.get("entropy_min_entropy", 4.5))
        self.report_uncorroborated = bool(self.config.get("entropy_report_uncorroborated", False))
        self.field_suppression = bool(self.config.get("field_suppression", True))
        self.decode_base64 = bool(self.config.get("decode_base64", True))
        self.disabled = set(self.config.get("disabled_detectors") or [])
        self.report_private_ips = bool(self.config.get("report_private_ips", False))
        self.use_ner = bool(self.config.get("ner", True))

    # ------------------------------------------------------------------
    def scan_text(
        self, text: str, field_name: Optional[str] = None, min_confidence: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Runs all layers on text. field_name is the column / document key /
        CSV header the text came from, when the caller has one; it drives
        context scoring and structural suppression. min_confidence overrides
        the engine's reporting tier for this call (the pipeline asks for
        `possible` candidates and applies column / count policies itself).
        Every finding carries `confidence` (tier) and `evidence` (list).
        """
        if not text or not isinstance(text, str):
            return []
        floor = floor_for(min_confidence) if min_confidence is not None else self.threshold

        findings: List[Dict[str, Any]] = []
        findings.extend(scan_pii(text, field_name, self.phone_regions, use_ner=self.use_ner))
        findings.extend(scan_credentials(text, field_name))
        findings.extend(scan_financial(text, field_name))
        findings.extend(scan_healthcare(text, field_name))
        findings.extend(scan_regional(text, self.enabled_regions, field_name, floor))
        findings.extend(scan_generic(text, field_name, floor))
        findings.extend(
            scan_entropy(
                text, self.entropy_min_length, self.entropy_min_entropy, field_name, self.report_uncorroborated,
            ),
        )
        if self.decode_base64:
            findings.extend(self._scan_encoded(text, field_name, floor))

        if self.field_suppression and field_name:
            # corroborated findings (keyword, neighbouring access key, self-describing format) and
            # recognizers whose own field hint matched the column (national_id, tax_id) are exempt
            findings = [
                f for f in findings
                if f.get("evidence") or f.get("field_hint") or not is_suppressed_by_field(f["detector"], field_name, f.get("value"))
            ]
        for f in findings:
            self._apply_engine_policies(f)
        if self.disabled:
            findings = [f for f in findings if f["detector"] not in self.disabled]
        for f in findings:
            if f["category"] in ("Regional Compliance", "Financial Data") and _placeholder_number(f["value"]):
                f["score"] = min(f["score"], 0.3)
                f["placeholder"] = True
        findings = [f for f in findings if f.get("score", 0.0) >= floor]
        findings = resolve_overlaps(findings)

        for f in findings:
            f["confidence"] = tier_for(f["score"])
            f["evidence"] = evidence_of(f)
            f["value_hash"] = fingerprint(f["value"])  # stable id for correlating a value across scans
            f.pop("masked", None)
        return findings

    # ------------------------------------------------------------------
    def _apply_engine_policies(self, f: Dict[str, Any]) -> None:
        """
        Engine-level judgement on top of the recognizer semantics:
          * a checksum alone is weak evidence for a number - mod-10/mod-11
            passes ~10% of random ids, phone numbers and timestamps. A bare
            separator-free match, or a checksum-validated run of digit groups
            (a US phone number is a mod-11-valid NHS number one time in ten),
            is `possible` until a context word, a field hint or column density
            vouches for it. Google SDP defines POSSIBLE the same way: "signals
            can include passing checksums; lack of a strong contextual clue";
          * epoch timestamps are never identifiers;
          * private / loopback / link-local IPs are infrastructure, not PII.
        """
        value = str(f.get("value", ""))
        if f.get("pattern") is not None and not f.get("context_word") and not f.get("field_hint"):
            if _bare_number(value) or (f.get("validated") and _digit_groups(value)):
                f["score"] = min(f["score"], 0.75)
                f["needs_context"] = True
        hinted_id = f.get("validated") and f.get("field_hint")
        if f["category"] in ("Regional Compliance", "Financial Data", "Healthcare Data (PHI)") and _looks_like_epoch(value) and not hinted_id:
            # 10- and 13-digit numbers in the epoch range are timestamps - a keyword in prose does
            # not change that - unless a checksum holds AND the column itself names the identifier
            # (a column of 1985 Romanian CNPs is 1.85e12 each)
            f["score"] = min(f["score"], 0.3)
            f["placeholder"] = "epoch"
        if f["detector"] == "PII.IPAddress" and not self.report_private_ips and _is_private_ip(value):
            f["score"] = min(f["score"], 0.3)
            f["private_ip"] = True

    _B64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9_-]{40,}={0,2})(?![A-Za-z0-9+/=_-])")

    def _scan_encoded(self, text: str, field_name: Optional[str], floor: float) -> List[Dict[str, Any]]:
        """
        Base64 blobs are decoded once and their plaintext scanned with the
        credential and PII layers (Authorization: Basic ..., base64 JSON bodies,
        PEM blocks). Findings are anchored on the encoded span.
        """
        out: List[Dict[str, Any]] = []
        for match in self._B64_BLOB_RE.finditer(text):
            blob = match.group(0)
            if tk.JWT_RE.match(blob) or blob.startswith(tk.B64_SALTED_PREFIX):
                continue
            decoded = tk.decode_base64(blob)
            if not decoded or len(decoded) < 8:
                continue
            inner: List[Dict[str, Any]] = []
            inner.extend(scan_credentials(decoded, None))
            inner.extend(scan_pii(decoded, None, self.phone_regions, use_ner=False))
            for f in inner:
                if f.get("score", 0.0) < floor:
                    continue
                f["start"], f["end"] = match.start(), match.end()
                f["encoded"] = "base64"
                out.append(f)
        return out
