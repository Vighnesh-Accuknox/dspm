"""
Detection layers.

Every scan_* function returns raw findings (dicts with detector, category,
severity, value, score, start, end and optional extras) for a text blob and,
when the caller has one, the name of the column / document field the text came
from. Scores follow one scheme:

  0.95  self-validating with corroboration (checksum + context, JWT with a
        decodable header, vendor-prefixed token, credential-named field)
  0.85  self-validating alone (valid email, Luhn + issuer prefix with
        separators, structured street address, vendor token)
  0.6   plausible shape that needs context (contiguous digit runs, 8-letter
        BIC-shaped words, header-only private keys, example values)
  0.5   weak shape, needs field-name evidence
  0.3   documented example / test value (never real)

DetectionEngine maps scores to confidence tiers (very_likely >= 0.9, likely >=
0.8, possible >= 0.5; src/engine/confidence.py) and reports `likely` and above
by default, so a weak shape is reported only when a context word, the field
name, a checksum or - through src/pipeline - its column or file vouches for it.
"""
import re
from typing import Any, Dict, List, Optional, Sequence

# pyrefly: ignore [missing-import]
import phonenumbers

from src.engine import ner
from src.engine import tokens as tk
from src.engine.context import (
    credential_detector_for_field,
    field_hints,
    is_credential_field,
    is_identifier_field,
)
from src.engine.data import load_tlds
from src.engine.entropy import calculate_entropy
from src.engine.luhn import luhn_check
from src.engine.rules import run_rules, tokenize_field_name
from src.engine.validators import ISO3166_ALPHA2, digits_only, iban_mod97

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_CATEGORY_PII = "PII"
_CATEGORY_CREDS = "Credentials and Secrets"
_CATEGORY_FIN = "Financial Data"
_CATEGORY_PHI = "Healthcare Data (PHI)"
_CATEGORY_ENTROPY = "Entropy-Based Secret Detection"

_TOKEN_SPLIT_RE = re.compile(r"[^\w']+")
_CAMEL_SPLIT_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
MAX_REPORTED_VALUE = 200


def _finding(
    detector: str, category: str, severity: str, value: str, score: float,
    start: int, end: int, **extra: Any,
) -> Dict[str, Any]:
    f = {
        "detector": detector,
        "category": category,
        "severity": severity,
        "value": value,
        "score": round(min(1.0, max(0.0, score)), 4),
        "start": start,
        "end": end,
    }
    f.update(extra)
    return f


def _window_tokens(text: str, start: int, end: int, before: int = 120, after: int = 60) -> List[str]:
    window = text[max(0, start - before):start] + " " + text[end:end + after]
    out = []
    for raw in _TOKEN_SPLIT_RE.split(window):
        for part in _CAMEL_SPLIT_RE.split(raw):
            if part:
                out.append(part.lower())
    return out


def near(
    text: str, start: int, end: int, keywords: Sequence[str], field_name: Optional[str] = None,
    before: int = 120, after: int = 60,
) -> Optional[str]:
    """
    First keyword found as a whole word (or, for keywords of 4+ letters, as a
    word prefix: 'card' matches 'cardnumber') around the match or in the field
    name. Multi-word keywords are searched as phrases.
    """
    toks = _window_tokens(text, start, end, before, after)
    toks_field = tokenize_field_name(field_name)
    joined = " " + " ".join(toks) + " "
    joined_field = " " + " ".join(toks_field) + " "
    for kw in keywords:
        kw_l = kw.lower()
        if " " in kw_l:
            if f" {kw_l} " in joined or f" {kw_l} " in joined_field or kw_l.replace(" ", "") in joined_field.replace(" ", ""):
                return kw
            continue
        for t in toks + toks_field:
            if t == kw_l or (len(kw_l) >= 4 and t.startswith(kw_l)):
                return kw
    return None


def calculate_match_score(
    text: str, start: int, end: int, base_score: float, detector_name: str,
    field_name: Optional[str] = None,
) -> float:
    """Context-boosted score (kept for backward compatibility with older callers)."""
    keywords = CONTEXT_WORDS.get(detector_name)
    if not keywords:
        return base_score
    if near(text, start, end, keywords, field_name) or field_hints(detector_name, field_name):
        return min(1.0, base_score + 0.35)
    return base_score


# Detector -> specific context words (generic words like 'code', 'state',
# 'number', 'identity', 'key' were the main false-positive driver and are gone)
CONTEXT_WORDS = {
    "Email": ["email", "e-mail", "mail", "contact"],
    "Phone Number": ["phone", "mobile", "cell", "telephone", "tel", "whatsapp", "fax", "msisdn", "call", "contact"],
    "Date of Birth": ["birth", "born", "dob", "birthday", "birthdate"],
    "Address": ["address", "street", "city", "zip", "zipcode", "postal", "postcode", "pincode", "shipping", "billing", "residence", "resides"],
    "Password Pattern": ["password", "passwd", "pwd", "passphrase", "credentials"],
    "API Key": ["api", "apikey", "secret", "token", "credentials"],
    "Bearer Token": ["bearer", "authorization", "token"],
    "OAuth Token": ["oauth", "token"],
    "IBAN": ["iban", "bank", "account", "wire", "transfer", "beneficiary"],
    "SWIFT/BIC": ["swift", "bic", "iban", "bank identifier", "swift code", "bic code", "bank code"],
    "Bank Account": ["account number", "account no", "acct", "acc no", "a/c", "bank account", "iban", "routing", "beneficiary", "ifsc", "sort code", "bank"],
    "Credit Card": ["card", "credit", "visa", "mastercard", "amex", "cc", "cvv", "cvc", "expiry", "expiration", "debit", "pan", "cardholder", "payment"],
    "Healthcare Data Detection": ["patient", "diagnosis", "medical"],
}

# ---------------------------------------------------------------------------
# Layer 1: PII
# ---------------------------------------------------------------------------

EMAIL_REGEX = re.compile(
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![A-Za-z0-9])",
)
DEMO_DOMAINS = frozenset({
    "example.com", "example.org", "example.net", "example.edu", "example.co.uk", "test.com", "domain.com",
    "yourdomain.com", "yourcompany.com", "mydomain.com", "mycompany.com", "company.com",
    "sample.com", "foo.com", "bar.com", "foo.bar", "abc.com", "xyz.com", "test.test", "tempuri.org",
    "localhost", "localhost.localdomain", "domain.tld", "email.tld", "host.com", "site.com", "server.com",
    "e.mail", "no.reply", "noreply.com", "nowhere.com", "nothing.com", "fake.com", "dummy.com",
    "placeholder.com", "invalid.com", "none.com", "null.com", "changeme.com", "mailinator.com",
})
DEMO_DOMAIN_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".local", ".internal", ".lan", ".example.com", ".example.org")
ROLE_LOCAL_PARTS = re.compile(
    r"^(?:no-?reply\w*|do-?not-?reply\w*|donotreply\w*|mailer-daemon|bounces?(?:[+-].*)?|devnull|nobody|postmaster|"
    r"notifications?|alerts?|newsletter|\w+\[bot\]|\w+-bot|github-actions|dependabot|renovate|"
    r"firstname\.lastname|first\.last|your\.?email|your\.?name|name@example|email|e-mail)$",
    re.IGNORECASE,
)
_MESSAGE_ID_LOCAL_RE = re.compile(r"^[A-Za-z0-9+=_-]{20,}$")


def is_demo_email(email: str) -> bool:
    """True for placeholder addresses (example.com, .test, localhost...)."""
    parts = email.lower().rsplit("@", 1)
    if len(parts) != 2:
        return True
    domain = parts[1]
    if domain in DEMO_DOMAINS or domain.endswith(DEMO_DOMAIN_SUFFIXES):
        return True
    return any(domain == d or domain.endswith("." + d) for d in ("example.com", "example.org", "example.net"))


def validate_email(email: str) -> Optional[str]:
    """
    None when the address is structurally a real address, else the reason it
    is not: 'demo', 'tld', 'numeric-label', 'no-letter', 'role', 'message-id'.
    """
    local, _, domain = email.rpartition("@")
    if not local or not domain:
        return "malformed"
    if is_demo_email(email):
        return "demo"
    labels = domain.split(".")
    tlds = load_tlds()
    if tlds and labels[-1].upper() not in tlds:
        return "tld"
    if any(re.fullmatch(r"[\d-]+", label) for label in labels[:-1]):
        return "numeric-label"  # python3-libs@3.9.25-2.el9 style package@version strings
    if not any(c.isalpha() for c in local):
        return "no-letter"
    if ".." in local or local.startswith(".") or local.endswith("."):
        return "malformed"
    if ROLE_LOCAL_PARTS.match(local):
        return "role"
    if _MESSAGE_ID_LOCAL_RE.match(local) and "." not in local and any(c.isdigit() for c in local) and any(c.isupper() for c in local):
        return "message-id"
    return None


LOOSE_PHONE_RE = re.compile(r"\+?\(?\d[\d\s().\-/]{5,22}\d")
DOB_REGEX = re.compile(r"\b(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b")
DOB_MIN_YEAR = 1930
DOB_MAX_YEAR = 2012

# Street addresses: "<number> <Name words> <street type>[, more]" - the street
# type must be a whole word, so 'broadcast', 'roadmap' and 'BlockRootUser' never trigger
STREET_TYPES = (
    "street|st|road|rd|avenue|ave|lane|ln|boulevard|blvd|drive|dr|court|ct|place|pl|square|sq|terrace|ter|"
    "way|highway|hwy|parkway|pkwy|circle|cir|crescent|cres|close|trail|trl|sector|apartment|apt|suite|ste|"
    "floor|fl|marg|nagar|colony|layout|enclave|vihar|chowk|gali|main road|road no|cross|bypass|expressway|"
    "alley|row|walk|grove|gardens|park|estate|heights|hill|hills|mews|quay|wharf|plaza|strasse|straße|str|"
    "allee|platz|weg|gasse|rue|avenida|calle|via|piazza|corso"
)
STRONG_STREET_TYPES = frozenset({
    "street", "road", "avenue", "lane", "boulevard", "drive", "sector", "apartment", "suite", "highway",
    "parkway", "crescent", "terrace", "nagar", "marg", "colony", "enclave", "vihar", "expressway", "bypass",
    "strasse", "straße", "avenida", "calle", "piazza", "corso", "gardens", "estate", "heights",
})
STREET_ADDRESS_RE = re.compile(
    r"(?<![\w/.-])(?P<num>\d{1,6}[A-Za-z]?(?:[/-]\d{1,5})?)[ \t,]+"
    r"(?P<name>(?:[A-Za-z][A-Za-z'.-]*[ \t]+){0,4}?)"
    r"(?P<type>" + STREET_TYPES + r")\b\.?"
    r"(?P<rest>(?:[ \t,]+(?:[A-Za-z][A-Za-z'.-]*|#\s?\d+|\d{3,10}))*)",
    re.IGNORECASE,
)
# "Sector 15", "Flat 4B", "Plot 22": only reported next to another address signal
UNIT_ADDRESS_RE = re.compile(
    r"\b(?:sector|block|plot|flat|house|h\.?\s?no|apartment|apt|suite|unit|floor|phase|pocket|door no|shop no)\.?\s?(?:no\.?\s?)?#?\s?\d{1,5}[A-Za-z]?\b",
    re.IGNORECASE,
)
POSTAL_CODE_RE = re.compile(
    r"\b(?:\d{5}(?:-\d{4})?|\d{6}|[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}|[A-Z]\d[A-Z]\s?\d[A-Z]\d)\b",
)
ADDRESS_KEYS = (
    r"street(?:_?address|_?name)?|street_?\d|address_?line_?\d?|addr(?:ess)?(?:_?\d)?|shipping_?address|"
    r"billing_?address|home_?address|postal_?address|mailing_?address|residential_?address|"
    r"zip_?code|zip|postal_?code|post_?code|pincode|pin_?code"
)
ADDRESS_KV_RE = re.compile(
    r"(?P<pre>^|[^A-Za-z0-9_])[\"']?(?P<key>" + ADDRESS_KEYS + r")[\"']?\s*[:=]\s*[\"']?(?P<val>[^\"'\n,;}{\]\[]{2,120})",
    re.IGNORECASE,
)
NON_POSTAL_ADDRESS_PREFIX = re.compile(
    r"(?:advertise|api|secure|insecure|tls|etcd|master|cert|metrics|health|admin|external|loopback|http|https|"
    r"ip|ipv4|ipv6|mac|e-?mail|wallet|contract|memory|server|host|remote|client|bind|listen|local|public|"
    r"private|elastic|network|gateway|dns|url|web|site|proxy|source|dest|destination|sender|receiver|from|to|"
    r"reply|return|origin|target|endpoint|peer|node|cluster|service|pod|container|virtual|physical|base|"
    r"start|end|load|stack|heap|bus|register|io|i/o|hex|byte|block|sector|ldap|smtp|ntp|ip_?addr)[_ .-]?$",
    re.IGNORECASE,
)
PERSON_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z'.-]{1,30}(?:\s+[A-Za-z][A-Za-z'.-]{0,30}){0,3}$")
NAME_KEYS_RE = re.compile(
    r"(?P<pre>^|[^A-Za-z0-9_])[\"']?(?P<key>full_?name|first_?name|last_?name|sur_?name|given_?name|"
    r"family_?name|middle_?name|customer_?name|employee_?name|person_?name|display_?name|contact_?name|"
    r"holder_?name|patient_?name|legal_?name|real_?name|applicant_?name|cardholder_?name|owner_?name)"
    r"[\"']?\s*[:=]\s*[\"'](?P<val>[^\"'\n]{2,80})[\"']",
    re.IGNORECASE,
)


def looks_like_person_name(value: str) -> bool:
    v = value.strip()
    if not PERSON_NAME_RE.match(v) or len(v) > 80:
        return False
    toks = v.split()
    if not any(any(c in tk.VOWELS for c in t) for t in toks):
        return False
    if re.search(r"(.)\1{3,}", v):  # kkkkkk
        return False
    if v.lower() in {"null", "none", "test", "admin", "user", "unknown", "n/a", "na", "root", "guest", "anonymous", "default", "system", "name", "desc", "string", "value", "true", "false", "undefined"}:
        return False
    return True


def _mask_name(value: str) -> str:
    return " ".join(t[0] + "*" * (len(t) - 1) if len(t) > 1 else t for t in value.split())


def scan_pii(
    text: str, field_name: Optional[str] = None, phone_regions: Optional[Sequence[str]] = None, use_ner: bool = True,
) -> list:
    findings = []

    # 1. Emails: self-validating (TLD, domain labels, demo/role/message-id filters)
    for match in EMAIL_REGEX.finditer(text):
        val = match.group(0).strip(".")
        reason = validate_email(val)
        if reason in ("demo", "tld", "numeric-label", "no-letter", "malformed"):
            continue
        score = 0.85 if reason is None else 0.6
        if reason is None and (field_hints("Email", field_name) or near(text, match.start(), match.end(), CONTEXT_WORDS["Email"])):
            score = 0.95
        findings.append(_finding("Email", _CATEGORY_PII, "Medium", val, score, match.start(), match.end(), reason=reason))

    # 2. Phone numbers: international format stands alone; national formats need
    #    a phone-ish field or context word and a region to parse with
    seen_spans = set()
    phone_context = field_hints("Phone Number", field_name)
    digit_count = sum(c.isdigit() for c in text)
    if digit_count < 7:
        phone_regions = None
    try:
        for match in (phonenumbers.PhoneNumberMatcher(text, None) if digit_count >= 7 else ()):
            raw = match.raw_string
            seen_spans.add((match.start, match.end))
            score = 0.85 if raw.lstrip().startswith(("+", "00")) else 0.5
            if phone_context or near(text, match.start, match.end, CONTEXT_WORDS["Phone Number"]):
                score = max(score, 0.85)
            findings.append(_finding("Phone Number", _CATEGORY_PII, "Medium", raw, score, match.start, match.end))
    except Exception:
        pass
    if phone_regions and (phone_context or near(text, 0, min(len(text), 200), CONTEXT_WORDS["Phone Number"])):
        for region in phone_regions:
            try:
                for match in phonenumbers.PhoneNumberMatcher(text, region.upper(), leniency=phonenumbers.Leniency.VALID):
                    if (match.start, match.end) in seen_spans:
                        continue
                    seen_spans.add((match.start, match.end))
                    findings.append(_finding("Phone Number", _CATEGORY_PII, "Medium", match.raw_string, 0.85, match.start, match.end, region=region.upper()))
            except Exception:
                continue
    #    A phone-named column whose value is phone-shaped but does not parse for the
    #    enabled regions (a French number under a US/IN/GB configuration) is a
    #    `possible` phone: the column name is the keyword (Macie counts a keyword
    #    in the column name as proximity) and column density decides the rest.
    if phone_context and not seen_spans:
        candidate = text.strip()
        digits = sum(c.isdigit() for c in candidate)
        if 7 <= digits <= 15 and LOOSE_PHONE_RE.fullmatch(candidate) and len({c for c in candidate if c.isdigit()}) > 2:
            findings.append(_finding("Phone Number", _CATEGORY_PII, "Medium", candidate, 0.6, 0, len(text), field_hint=True))

    # 3. Dates of birth: plausible year range + birth context or field
    for match in DOB_REGEX.finditer(text):
        year = int(match.group(0)[:4])
        if not (DOB_MIN_YEAR <= year <= DOB_MAX_YEAR):
            continue
        score = 0.4
        if field_hints("Date of Birth", field_name) or near(text, match.start(), match.end(), CONTEXT_WORDS["Date of Birth"]):
            score = 0.85
        findings.append(_finding("Date of Birth", _CATEGORY_PII, "Medium", match.group(0), score, match.start(), match.end()))

    # 4. Addresses
    findings.extend(scan_addresses(text, field_name))

    # 5. Person names: where a field/key says it is a name, and inside prose with the
    #    optional NER model (Macie NAME / Purview named entities): `possible` unless
    #    a context word or an honorific stands next to the name
    findings.extend(scan_person_names(text, field_name))
    if use_ner and ner.looks_like_prose(text) and not is_credential_field(field_name):
        taken = [(f["start"], f["end"]) for f in findings if f["detector"] == "PII.PersonName"]
        for start, end, name, context in ner.person_names(text):
            if any(s <= start and end <= e for s, e in taken):
                continue
            score = 0.85 if context else 0.6
            findings.append(_finding("PII.PersonName", _CATEGORY_PII, "Low", name, score, start, end, ner=True, context_word=context))

    return findings


def scan_addresses(text: str, field_name: Optional[str] = None) -> list:
    findings = []
    address_field = field_hints("Address", field_name)
    lower = text.lower()

    # a) structured "number + name + street type"
    for match in STREET_ADDRESS_RE.finditer(text):
        street_type = match.group("type").lower()
        name = match.group("name").strip()
        rest = match.group("rest") or ""
        strong = street_type in STRONG_STREET_TYPES
        if not name and not strong:
            continue
        if not name and strong and not rest.strip(" ,"):
            continue
        # "port 8080 is used for ..." shapes: the number must not be a port/version/count
        before = lower[max(0, match.start() - 24):match.start()]
        if re.search(r"(?:port|version|line|page|chapter|section|step|error|status|code|level|v|http|tcp|udp|id|no\.?|number|#|size|count|total|x)\s*$", before):
            continue
        score = 0.85 if (strong and name) else 0.6
        if address_field or near(text, match.start(), match.end(), CONTEXT_WORDS["Address"]) or POSTAL_CODE_RE.search(text[match.end():match.end() + 80]):
            score = max(score, 0.85)
        value = match.group(0).strip(" ,")[:MAX_REPORTED_VALUE]
        findings.append(_finding("Address", _CATEGORY_PII, "Medium", value, score, match.start(), match.end()))

    # b) key/value pairs in JSON-ish or form text: "street": "..." / zipCode=...
    for match in ADDRESS_KV_RE.finditer(text):
        key = match.group("key")
        key_start = match.start("key")
        prefix = text[max(0, key_start - 14):key_start]
        if NON_POSTAL_ADDRESS_PREFIX.search(prefix):
            continue
        val = match.group("val").strip()
        if tk.is_placeholder(val):
            continue
        key_l = key.lower()
        if key_l.startswith(("zip", "postal", "post", "pin")):
            if not re.fullmatch(r"[A-Za-z0-9 -]{3,10}", val) or not any(c.isdigit() for c in val):
                continue
        else:
            if len(val) < 4 or (not any(c.isdigit() for c in val) and len(val.split()) < 2):
                continue
            if not any(c.isalpha() for c in val) or val.startswith(("http", "0x", "/", "arn:", "--")) or "://" in val:
                continue  # IPs, flags, paths
        span_start, span_end = match.start("key"), match.end("val")
        value = f"{key}: {val}"[:MAX_REPORTED_VALUE]
        findings.append(_finding("Address", _CATEGORY_PII, "Medium", value, 0.85, span_start, span_end, key=key))

    # c) the field itself is an address column
    if address_field and not findings and 4 <= len(text.strip()) <= MAX_REPORTED_VALUE:
        val = text.strip()
        if not tk.is_placeholder(val) and "://" not in val and not val.startswith(("{", "[")):
            if any(c.isdigit() for c in val) or "," in val or len(val.split()) >= 3:
                findings.append(_finding("Address", _CATEGORY_PII, "Medium", val, 0.85, 0, len(text), key=field_name))

    # d) a lone unit/sector reference counts only next to another address signal
    if findings:
        for match in UNIT_ADDRESS_RE.finditer(text):
            if any(f["start"] <= match.start() and match.end() <= f["end"] for f in findings):
                continue
            if any(abs(f["start"] - match.start()) < 80 for f in findings):
                findings.append(_finding("Address", _CATEGORY_PII, "Medium", match.group(0), 0.85, match.start(), match.end()))
    return findings


_SINGLE_NAME_FIELD_RE = re.compile(r"\b(?:first|last|given|family|middle|sur) ?name\b")


def scan_person_names(text: str, field_name: Optional[str] = None) -> list:
    findings = []
    if field_hints("PII.PersonName", field_name) and not is_credential_field(field_name):
        value = text.strip()
        single_ok = _SINGLE_NAME_FIELD_RE.search(" ".join(tokenize_field_name(field_name))) is not None
        if looks_like_person_name(value) and (single_ok or len(value.split()) >= 2):
            findings.append(_finding("PII.PersonName", _CATEGORY_PII, "Low", value, 0.85, 0, len(text), masked=_mask_name(value)))
            return findings
    for match in NAME_KEYS_RE.finditer(text):
        val = match.group("val").strip()
        key_single = _SINGLE_NAME_FIELD_RE.search(match.group("key").lower().replace("_", " ")) is not None
        if looks_like_person_name(val) and (key_single or len(val.split()) >= 2):
            findings.append(_finding("PII.PersonName", _CATEGORY_PII, "Low", val, 0.85, match.start("val"), match.end("val"), masked=_mask_name(val), key=match.group("key")))
    return findings


# ---------------------------------------------------------------------------
# Layer 2: Credentials and Secrets
# ---------------------------------------------------------------------------

PASSWORD_REGEX = re.compile(
    r"(?i)(?<![A-Za-z])(password|passwd|passwort|passphrase|passcode|pwd|pswd|db_?pass|admin_?pass|user_?pass|root_?pass)s?(?![A-Za-z])"
    r"\s*[:=>]+\s*[\"']?([^\s\"',;]{1,128})",
)
API_KEY_REGEX = re.compile(
    r"(?i)(?<![A-Za-z])(api[_-]?key|apikey|x-api-key|api[_-]?secret|app[_-]?key|app[_-]?secret|consumer[_-]?key|consumer[_-]?secret|"
    r"client[_-]?secret|secret[_-]?key|auth[_-]?key|access[_-]?key[_-]?secret|signing[_-]?key|encryption[_-]?key|master[_-]?key|"
    r"license[_-]?key|private[_-]?key|secret|auth[_-]?token|session[_-]?token|api[_-]?token|token)s?(?![A-Za-z])"
    r"\s*[:=>]+\s*[\"']?([A-Za-z0-9_\-./+=~]{16,})",
)
BEARER_TOKEN_REGEX = re.compile(r"(?<![A-Za-z])[Bb]earer\s+([A-Za-z0-9\-._~+/]{16,}=*)")
JWT_REGEX = tk.JWT_RE
OAUTH_TOKEN_REGEX = re.compile(
    r"(?i)(?<![A-Za-z])(access_token|refresh_token|id_token|oauth_token|bearer_token)s?(?![A-Za-z])\s*[:=>]+\s*[\"']?([A-Za-z0-9\-._~+/]{16,}=*)",
)
AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
AWS_SECRET_KEY_REGEX = re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])")
AWS_SECRET_CONTEXT = ["aws", "secret", "secret_access_key", "secretaccesskey", "aws_secret", "secret key", "credentials"]
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")
PRIVATE_KEY_BODY_RE = re.compile(r"^(?:\\r?\\n|\s|\\n)*(?:[A-Za-z]+:[^\n\\]*(?:\\n|\n))*(?:\\r?\\n|\s)*([A-Za-z0-9+/=]{40,})")
HEX_ONLY_REGEX = re.compile(r"[0-9a-fA-F]+")
URL_CREDENTIALS_RE = re.compile(r"\b([a-z][a-z0-9+.-]{1,20})://([^\s:/@\"']{1,64}):([^\s@/\"']{3,128})@([^\s/\"'?#]+)", re.IGNORECASE)
BASIC_AUTH_RE = re.compile(r"(?<![A-Za-z])Basic\s+([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")
PASSWORD_HASH_RE = re.compile(
    r"(?<![A-Za-z0-9./$])(?:"
    r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}|"                     # bcrypt
    r"\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+|"  # argon2
    r"\$(?:1|5|6|7|y|gy|sha1|md5)\$[^\s$]{1,32}\$[./A-Za-z0-9]{20,}|"  # crypt(3) family
    r"pbkdf2(?:[_:$-]sha\d+)?\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+|"    # Django/Werkzeug PBKDF2
    r"\{S?SHA\d{0,3}\}[A-Za-z0-9+/=]{20,}|"                      # LDAP
    r"scrypt:\d+:\d+:\d+\$[A-Za-z0-9]+\$[a-f0-9]{64,}"           # Werkzeug scrypt
    r")(?![A-Za-z0-9./$])",
)
BARE_HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==|[A-Za-z0-9+/]{22}==)$")


def is_starred_private_key(text: str, start: int) -> bool:
    """True if the private key body consists only of stars (*), i.e. is redacted."""
    sub_text = text[start:start + 1000]
    footer_pattern = re.compile(r"(-----END [A-Z ]+PRIVATE KEY(?: BLOCK)?-----|------? ?END [A-Z ]+KEY------?)")
    footer_match = footer_pattern.search(sub_text)
    if footer_match:
        header_end_match = re.search(r"(-----BEGIN [A-Z ]+PRIVATE KEY(?: BLOCK)?-----|------? ?BEGIN [A-Z ]+KEY------?)", sub_text)
        if header_end_match:
            between = sub_text[header_end_match.end():footer_match.start()].strip()
            cleaned = re.sub(r"[\s\-]", "", between)
            if not cleaned or set(cleaned) == {"*"}:
                return True
    return False


_PASSWORD_WORD_RE = re.compile(r"(?i)pass(?:word|wd|phrase|code)|pwd|secret|credential")
_ALGO_NAME_RE = re.compile(r"(?i)^(?:pbkdf2|bcrypt|scrypt|argon2(?:id?|d)?|sha-?\d{1,3}|md5|aes-?\d{0,3}(?:-?[a-z]{3})?|hmac(?:-?sha\d*)?|rsa-?\d{0,4}|ecdsa|ed25519|tls(?:v?1(?:\.\d)?)?|ssl(?:v\d)?|des|3des|blowfish|chacha20|x25519)$")


def _password_value_ok(value: str, min_length: int, inline: bool = True) -> Optional[str]:
    """None when value can be a password; else the reason it is not."""
    v = value.strip().strip("\"'`").rstrip(",.;:)")
    if len(v) < min_length:
        return "short"
    if inline:
        if _PASSWORD_WORD_RE.search(v) and not any(c in "!@#$%^&*" for c in v):
            return "reference"  # currPassword, newPassword, user_password: a variable, not a value
        if _ALGO_NAME_RE.match(v):
            return "algorithm"
        if v.isalpha() and (v.islower() or v[0].isupper() and v[1:].islower()):
            return "prose"  # "password: Reenter", "password: required"
    if tk.is_placeholder(v):
        return "placeholder"
    if tk.looks_like_code(v):
        return "code"
    if v.startswith(("http://", "https://")) or "://" in v:
        return "url"
    if not any(c.isalnum() for c in v):
        return "punctuation"
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z0-9_.]+", v) and v.count(".") >= 1 and "." in v and v.lower() == v:
        return "reference"  # settings.db_password, config.secret
    return None



def _credential_value_shape_ok(value: str) -> bool:
    """
    Can this value be a secret assigned to an explicit credential key/field?
    Paths, dates, PEM and word-built identifiers are not; slugs only when a
    segment looks machine-generated (sk_live_4eC39HqLyjWDarjtT1zdp7dc yes,
    db-credentials-prod no).
    """
    info = tk.analyze_token(value, 8)
    if info.kind in ("path", "date", "pem"):
        return False
    if info.kind == "slug":
        segments = re.split(r"[-_.]+", value)
        return any(tk.is_random_looking(seg) or sum(c.isdigit() for c in seg) >= 6 for seg in segments)
    if info.kind == "identifier" and tk.identifier_word_share(value) >= 0.6 and not any(c.isdigit() for c in value):
        return False
    return True

def _classify_password_like(value: str) -> str:
    """'hash' when the value is a password hash rather than a password."""
    v = value.strip().strip("\"'`")
    if PASSWORD_HASH_RE.fullmatch(v) or BARE_HASH_RE.fullmatch(v):
        return "hash"
    return "password"


def scan_credentials(text: str, field_name: Optional[str] = None) -> list:
    findings = []

    def add(detector, value, start, end, score, **extra):
        findings.append(_finding(detector, _CATEGORY_CREDS, "Critical", value, score, start, end, **extra))

    # Passwords assigned inline: password=..., "pwd": "..."
    for match in PASSWORD_REGEX.finditer(text):
        value = match.group(2).rstrip(",.;:)")
        reason = _password_value_ok(value, 6)
        if reason:
            continue
        if _classify_password_like(value) == "hash":
            findings.append(_finding("Secret.PasswordHash", _CATEGORY_CREDS, "High", value, 0.9, match.start(2), match.start(2) + len(value)))
            continue
        score = 0.9
        if tk.is_example_password(value) and not field_hints("Password Pattern", field_name):
            score = 0.7  # hunter2 / P@ssw0rd in advisory text
        add("Password Pattern", value, match.start(2), match.start(2) + len(value), score)

    # Password hashes anywhere (bcrypt/argon2/crypt/pbkdf2/ldap are self-describing)
    for match in PASSWORD_HASH_RE.finditer(text):
        if any(f["start"] <= match.start() and match.end() <= f["end"] for f in findings):
            continue
        findings.append(_finding("Secret.PasswordHash", _CATEGORY_CREDS, "High", match.group(0), 0.9, match.start(), match.end()))

    # OAuth first (its keys contain 'token', which the generic assignment regex also matches)
    for match in OAUTH_TOKEN_REGEX.finditer(text):
        value = match.group(2).rstrip(".,;")
        if tk.is_placeholder(value) or not _credential_value_shape_ok(value):
            continue
        add("OAuth Token", value, match.start(2), match.start(2) + len(value), 0.9)

    # Generic secret assignments: api_key=..., "secret": "...", token: ...
    for match in API_KEY_REGEX.finditer(text):
        key = match.group(1).lower()
        value = match.group(2).rstrip(".,;")
        if tk.is_placeholder(value) or "://" in value:
            continue
        if tk.analyze_token(value, 16).kind == "salted" or not _credential_value_shape_ok(value):
            continue
        detector = "Bearer Token" if "token" in key and "api" not in key else "API Key"
        add(detector, value, match.start(2), match.start(2) + len(value), 0.9, key=key)

    for match in BEARER_TOKEN_REGEX.finditer(text):
        value = match.group(1).rstrip(".")
        has_digit = any(c.isdigit() for c in value)
        has_punct = any(c in "._-+/" for c in value)
        if not has_digit and (not has_punct or tk.has_word(value)) and not JWT_REGEX.match(value):
            continue  # "Bearer authorization", "Bearer header." in prose
        add("Bearer Token", value, match.start(1), match.start(1) + len(value), 0.9)

    for match in JWT_REGEX.finditer(text):
        parts = tk.jwt_parts(match.group(0))
        score = 0.95 if parts else 0.6
        add("JWT Token", match.group(0), match.start(), match.end(), score, jwt_alg=(parts[0].get("alg") if parts else None))
        if parts:
            # PII inside the claims is data too (juice-shop style tokens carry emails and hashes)
            for key, val in parts[1].items() if isinstance(parts[1], dict) else []:
                if isinstance(val, dict):
                    items = val.items()
                else:
                    items = [(key, val)]
                for k, v in items:
                    if isinstance(v, str) and "@" in v and EMAIL_REGEX.fullmatch(v) and validate_email(v) is None:
                        findings.append(_finding("Email", _CATEGORY_PII, "Medium", v, 0.85, match.start(), match.end(), encoded="jwt", claim=k))
                    elif isinstance(v, str) and str(k).lower() in ("password", "passwd", "pwd", "password_hash") and v:
                        det = "Secret.PasswordHash" if _classify_password_like(v) == "hash" else "Password Pattern"
                        findings.append(_finding(det, _CATEGORY_CREDS, "High", v, 0.85, match.start(), match.end(), encoded="jwt", claim=k))

    for match in AWS_ACCESS_KEY.finditer(text):
        value = match.group(0)
        score = 0.3 if tk.is_example_secret(value) else 0.95
        add("AWS Access Key", value, match.start(), match.end(), score)

    has_access_key = AWS_ACCESS_KEY.search(text) is not None
    for match in AWS_SECRET_KEY_REGEX.finditer(text):
        val = match.group(0)
        if HEX_ONLY_REGEX.fullmatch(val):
            continue
        if not (any(c.isupper() for c in val) and any(c.islower() for c in val) and any(c.isdigit() for c in val)):
            continue
        if len(set(val)) <= 4 or "//" in val or val.count("/") > 3:
            continue
        if tk.is_example_secret(val):
            add("AWS Secret Access Key", val, match.start(), match.end(), 0.3, example=True)
            continue
        corroborated = has_access_key or field_hints("AWS Secret Access Key", field_name) or is_credential_field(field_name) \
            or near(text, match.start(), match.end(), AWS_SECRET_CONTEXT, before=160)
        wordy = tk.has_word(val, 6)  # Authorization/policyAssignments/5f5af5be, KeyVault/vaults/...
        if wordy and not corroborated:
            continue
        if corroborated:
            score = 0.9
        elif tk.analyze_token(val, 40).kind == "secret_like" and not is_identifier_field(field_name):
            score = 0.85
        else:
            score = 0.5
        add(
            "AWS Secret Access Key", val, match.start(), match.end(), score,
            evidence=("access_key" if has_access_key else "keyword") if corroborated else None,
        )

    for match in PRIVATE_KEY_REGEX.finditer(text):
        if is_starred_private_key(text, match.start()):
            continue
        tail = text[match.end():match.end() + 400]
        has_body = PRIVATE_KEY_BODY_RE.match(tail) is not None
        add("Private Key Header", match.group(0), match.start(), match.end(), 0.95 if has_body else 0.5, has_body=has_body)

    for detector, start, end, value in tk.find_vendor_tokens(text):
        add(detector, value, start, end, 0.95)

    for match in URL_CREDENTIALS_RE.finditer(text):
        password = match.group(3)
        if tk.is_placeholder(password) or password.lower() in ("password", "pass", "pwd", "secret", "xxx", "xxxx", "*", "**", "***", "****"):
            continue
        add("Credentials in URL", match.group(0), match.start(), match.end(), 0.9, username=match.group(2))

    for match in BASIC_AUTH_RE.finditer(text):
        decoded = tk.decode_base64(match.group(1))
        if decoded and ":" in decoded and 3 <= len(decoded) <= 200 and "\n" not in decoded:
            user, _, pwd = decoded.partition(":")
            if user and pwd and not tk.is_placeholder(pwd):
                add("Basic Auth Credentials", match.group(0), match.start(), match.end(), 0.9, username=user)

    # A credential-named field holding an opaque value is a credential whatever its shape
    if field_name and is_credential_field(field_name) and not any(f["category"] == _CATEGORY_CREDS for f in findings):
        value = text.strip()
        if EMAIL_REGEX.fullmatch(value) or ("@" in value and "." in value and " " not in value and validate_email(value) in (None, "role")):
            return findings  # an e-mail in a cookie/authorization field is PII, not a token
        detector = credential_detector_for_field(field_name)
        if detector and 4 <= len(value) <= 4096 and " " not in value and "\n" not in value \
                and not tk.is_placeholder(value) and "://" not in value and not value.startswith(("{", "[", "<")):
            info = tk.analyze_token(value, 8)
            if info.kind == "assignment":
                # cookie / header style "name=value": judge the value part
                head, tail = info.parts
                value = tail.split(";")[0]
                info = tk.analyze_token(value, 8)
                if info.kind in ("slug", "identifier", "short") and not tk.is_random_looking(value):
                    return findings
            if detector == "Password Pattern":
                if _password_value_ok(value, 4, inline=False) is None:
                    if _classify_password_like(value) == "hash":
                        findings.append(_finding("Secret.PasswordHash", _CATEGORY_CREDS, "High", value, 0.9, 0, len(text), key=field_name))
                    else:
                        add("Password Pattern", value, 0, len(text), 0.9, key=field_name)
            elif info.kind == "salted":
                findings.append(_finding("Encrypted Secret", _CATEGORY_CREDS, "Medium", value, 0.85, 0, len(text), key=field_name))
            elif len(value) >= 8 and _credential_value_shape_ok(value):
                add(detector, value, 0, len(text), 0.9, key=field_name)

    return findings


# ---------------------------------------------------------------------------
# Layer 3: Financial Data
# ---------------------------------------------------------------------------

CREDIT_CARD_REGEX = re.compile(
    r"(?<![\d-])(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}(?:[ -]\d{3})?|\d{4}[ -]\d{6}[ -]\d{5}|\d{4}[ -]\d{4}[ -]\d{5}|\d{13,19})(?![\d-])",
)
IBAN_REGEX = re.compile(r"\b[A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,4})?\b")
SWIFT_REGEX = re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")
BANK_ACCOUNT_REGEX = re.compile(r"(?<![\d-])\d{8,18}(?![\d-])")
BANK_ACCOUNT_KEYWORDS = CONTEXT_WORDS["Bank Account"]
BANK_NEGATIVE_KEYWORDS = ["aws", "arn", "subscription", "project", "tenant", "account id", "accountid", "customer id", "order", "invoice", "transaction id", "cluster", "namespace"]
SWIFT_BLACKLIST = {
    "CERTIFICATE", "DESCRIPTION", "AUTHORITY", "PARAMETERS", "APPLICATION", "PROPERTIES", "IDENTIFIER",
    "INFORMATION", "DEVELOPMENT", "DEPRECATED", "REQUIREMENT", "ENVIRONMENT", "TRANSACTION", "DESTINATION",
    "INSTRUCTION", "CONSTRUCTION", "METADATA", "CERT", "RESPONSE", "STANDARD", "TEMPLATE", "LANGUAGE",
    "SEQUENCE", "REGIONAL", "RESOLVED", "SOFTWARE", "STARTTLS", "MANAGERS", "POLICIES", "EXCEEDED",
    "FAKECODE", "DISCOUNT", "WELCOME", "SNAPSHOT", "REJECTED", "ACCEPTED", "FIREWALL", "REPORTED",
}


def iin_matches_network(digits: str) -> bool:
    """Issuer prefix + per-network length check."""
    n = len(digits)
    if not digits.isdigit():
        return False
    if digits[0] == "4":
        return n in (13, 16, 19)                                   # Visa
    if digits[:2] in ("34", "37"):
        return n == 15                                             # Amex
    if 51 <= int(digits[:2]) <= 55:
        return n == 16                                             # Mastercard
    if n >= 4 and 2221 <= int(digits[:4]) <= 2720:
        return n == 16                                             # Mastercard 2-series
    if digits[:4] == "6011" or digits[:2] == "65" or digits[:3] in ("644", "645", "646", "647", "648", "649"):
        return n in (16, 19)                                       # Discover
    if digits[:2] == "35":
        return n in (16, 19)                                       # JCB
    if digits[:2] in ("81", "82", "60", "50"):
        return n == 16                                             # RuPay / Maestro-ish
    if digits[:2] in ("36", "38", "39") or digits[:3] in ("300", "301", "302", "303", "304", "305"):
        return n in (14, 16, 19)                                   # Diners
    if digits[:2] == "62":
        return n in (16, 17, 18, 19)                               # UnionPay
    return False


def _iban_rule():
    try:
        from src.engine.recognizers import get_rule
        return get_rule("IBAN")
    except Exception:
        return None


def scan_financial(text: str, field_name: Optional[str] = None) -> list:
    findings = []

    # 1. Credit cards: canonical groupings only, Luhn + issuer prefix, then context
    for match in CREDIT_CARD_REGEX.finditer(text):
        candidate = match.group(0)
        cleaned = re.sub(r"[\s\-]", "", candidate)
        if not (luhn_check(cleaned) and iin_matches_network(cleaned)):
            continue
        separated = candidate != cleaned
        if tk.is_test_card(cleaned):
            score = 0.3
        else:
            score = 0.85 if separated else 0.6
            if field_hints("Credit Card", field_name) or near(text, match.start(), match.end(), CONTEXT_WORDS["Credit Card"]):
                score = 0.95
        findings.append(_finding("Credit Card", _CATEGORY_FIN, "Critical", candidate, score, match.start(), match.end(), test_card=tk.is_test_card(cleaned)))

    # 2. IBAN: the upstream recognizer's per-country rule when loaded, else generic + mod-97
    rule = _iban_rule()
    if rule is not None:
        from src.engine.rules import run_rule
        for f in run_rule(rule, text, field_name):
            findings.append(_finding("IBAN", _CATEGORY_FIN, "High", f["value"], f["score"], f["start"], f["end"]))
    else:
        for match in IBAN_REGEX.finditer(text):
            val = match.group(0)
            if not iban_mod97(val):
                continue
            score = 0.95 if (field_hints("IBAN", field_name) or near(text, match.start(), match.end(), CONTEXT_WORDS["IBAN"])) else 0.85
            findings.append(_finding("IBAN", _CATEGORY_FIN, "High", val, score, match.start(), match.end()))

    # 3. SWIFT/BIC: valid country code + explicit swift/bic context or field
    for match in SWIFT_REGEX.finditer(text):
        val = match.group(0)
        if val in SWIFT_BLACKLIST or val[4:6] not in ISO3166_ALPHA2:
            continue
        if any(f["start"] <= match.start() and match.end() <= f["end"] for f in findings):
            continue  # inside an IBAN
        score = 0.5
        if field_hints("SWIFT/BIC", field_name) or near(text, match.start(), match.end(), CONTEXT_WORDS["SWIFT/BIC"]):
            score = 0.85
        findings.append(_finding("SWIFT/BIC", _CATEGORY_FIN, "High", val, score, match.start(), match.end()))

    # 4. Bank account numbers: digit runs with bank context, not cloud account ids
    for match in BANK_ACCOUNT_REGEX.finditer(text):
        if any(f["start"] <= match.start() and match.end() <= f["end"] for f in findings):
            continue
        if near(text, match.start(), match.end(), BANK_NEGATIVE_KEYWORDS, before=60, after=30):
            continue
        keyword = near(text, match.start(), match.end(), BANK_ACCOUNT_KEYWORDS, before=80, after=40)
        hinted = field_hints("Bank Account", field_name)
        if not keyword and not hinted:
            continue
        score = 0.85 if (hinted or keyword != "bank") else 0.6
        findings.append(_finding("Bank Account", _CATEGORY_FIN, "High", match.group(0), score, match.start(), match.end()))

    return findings


# ---------------------------------------------------------------------------
# Layer 4: Healthcare
# ---------------------------------------------------------------------------

HEALTHCARE_KEYWORDS = [
    "patient", "diagnosis", "treatment", "prescription", "hospital", "medical", "doctor", "insurance", "health record",
    "icd-10", "icd10", "clinical", "medication", "dosage", "symptoms", "allergies", "blood type", "physician",
]
HEALTHCARE_KEYWORDS_RE = re.compile(r"\b(?:" + "|".join(re.escape(k) for k in HEALTHCARE_KEYWORDS) + r")\b", re.IGNORECASE)


def scan_healthcare(text: str, field_name: Optional[str] = None) -> list:
    findings = []
    matches = {m.lower() for m in HEALTHCARE_KEYWORDS_RE.findall(text)}
    if len(matches) >= 3:
        findings.append(
            _finding(
                "Healthcare Data Detection", _CATEGORY_PHI, "High",
                f"Matched PHI Keywords: {sorted(matches)}", 0.85, 0, len(text),
            ),
        )
    return findings


# ---------------------------------------------------------------------------
# Layer 5: Regional compliance + generic rules (recognizer port)
# ---------------------------------------------------------------------------

_RULES_CACHE: Dict[str, list] = {}


def _rule_sets():
    if "all" not in _RULES_CACHE:
        try:
            from src.engine.recognizers import load_all
            rules = list(load_all())
        except Exception:
            rules = []
        _RULES_CACHE["all"] = rules
        _RULES_CACHE["regional"] = [r for r in rules if r.region]
        _RULES_CACHE["generic"] = [r for r in rules if not r.region and r.name != "IBAN"]
        for r in rules:
            # a rule needs a digit in the text only when every pattern demands one explicitly
            # (\d or a bare [0-9] class); an alphanumeric class such as [a-z0-9._-] does not
            needs_digit = all(("\\d" in p.regex or "[0-9]" in p.regex or "[0123456789]" in p.regex) for p in r.patterns)
            r.__dict__["_needs_digit"] = needs_digit
    return _RULES_CACHE


def _applicable(rules, text):
    has_digit = any(c.isdigit() for c in text)
    return [r for r in rules if has_digit or not r.__dict__.get("_needs_digit")]


_GATE_CACHE: Dict[tuple, Any] = {}
_NAMED_GROUP_RE = re.compile(r"\(\?P<[^>]+>")
_INLINE_FLAGS_RE = re.compile(r"^\(\?[aiLmsux]+\)")


def _gate_for(rules) -> Dict[int, Any]:
    """
    One combined alternation per flag set over every pattern of the given rules.
    Most cells match none of the 90 patterns; a single C-level search decides
    that instead of ~30 Python-level rule invocations.
    """
    key = tuple(id(r) for r in rules)
    gates = _GATE_CACHE.get(key)
    if gates is None:
        by_flags: Dict[int, List[str]] = {}
        for rule in rules:
            for pat in rule.patterns:
                regex = _INLINE_FLAGS_RE.sub("", _NAMED_GROUP_RE.sub("(?:", pat.regex))
                if "\\1" in regex or "(?P=" in regex:
                    by_flags.setdefault(pat.flags, []).append(None)  # backreference: cannot combine
                else:
                    by_flags.setdefault(pat.flags, []).append(regex)
        gates = {}
        for flags, regexes in by_flags.items():
            if any(r is None for r in regexes):
                gates[flags] = None
                continue
            try:
                gates[flags] = re.compile("|".join(f"(?:{r})" for r in regexes), flags)
            except re.error:
                gates[flags] = None
        _GATE_CACHE[key] = gates
    return gates


def _passes_gate(rules, text) -> bool:
    gates = _gate_for(rules)
    if not gates:
        return False
    for gate in gates.values():
        if gate is None or gate.search(text):
            return True
    return False


def scan_regional(
    text: str, enabled_regions: Sequence[str], field_name: Optional[str] = None,
    threshold: Optional[float] = None,
) -> list:
    if not enabled_regions:
        return []
    regions = {r.upper() for r in enabled_regions}
    regional = [r for r in _rule_sets()["regional"] if r.enabled and r.region in regions]
    regional = _applicable(regional, text)
    if not regional or not _passes_gate(regional, text):
        return []
    return run_rules(regional, text, field_name, enabled_regions, threshold)


def scan_generic(text: str, field_name: Optional[str] = None, threshold: Optional[float] = None) -> list:
    generic = [r for r in _rule_sets()["generic"] if r.enabled]
    generic = _applicable(generic, text)
    if not generic or not _passes_gate(generic, text):
        return []
    return run_rules(generic, text, field_name, (), threshold)


# ---------------------------------------------------------------------------
# Layer 6: Entropy-based secrets (structure first, entropy second, evidence last)
# ---------------------------------------------------------------------------

ENTROPY_CANDIDATE_REGEX = re.compile(r"(?<![A-Za-z0-9/+=_\-~])[A-Za-z0-9/+=_\-~]{20,}(?![A-Za-z0-9/+=_\-~])")
ENTROPY_SLUG_REGEX = tk.SLUG_RE
INLINE_SECRET_KEYWORD_RE = re.compile(
    r"(?i)(?:secret|token|api[_-]?key|apikey|passw(?:or)?d|passwd|pwd|passphrase|auth|authorization|credential|bearer|"
    r"cookie|session|private[_-]?key|access[_-]?key|client[_-]?secret|key)s?\w{0,12}\s*[\"']?\s*[:=>]+\s*[\"']?\s*$",
)


def _corroboration(text: str, start: int, field_name: Optional[str]) -> Optional[str]:
    if field_name and is_credential_field(field_name):
        return "field"
    prefix = text[max(0, start - 48):start]
    if INLINE_SECRET_KEYWORD_RE.search(prefix):
        return "inline"
    return None


def scan_entropy(
    text: str, min_length: int = 24, min_entropy: float = 4.5, field_name: Optional[str] = None,
    report_uncorroborated: bool = False,
) -> list:
    findings = []
    for match in ENTROPY_CANDIDATE_REGEX.finditer(text):
        candidate = match.group(0)
        if len(candidate) < min(min_length, 20):
            continue
        info = tk.analyze_token(candidate, min_length)
        start = match.start()
        if info.kind == "assignment":
            head, tail = info.parts
            if len(tail) >= min_length:
                sub = tk.analyze_token(tail, min_length)
                if sub.kind == "secret_like":
                    info = sub
                    candidate = tail
                    start = match.start() + len(head) + 1
                else:
                    continue
            else:
                continue
        if info.kind == "pem":
            decoded = tk.decode_base64(candidate[:80]) if candidate.startswith(tk.B64_PEM_PREFIX) else None
            if decoded and "PRIVATE KEY" in decoded:
                findings.append(
                    _finding(
                        "Private Key Header", _CATEGORY_CREDS, "Critical", decoded.split("\n")[0][:60],
                        0.95, match.start(), match.end(), encoded="base64",
                    ),
                )
            continue
        if info.kind == "salted":
            findings.append(_finding("Encrypted Secret", _CATEGORY_CREDS, "Medium", candidate, 0.85, match.start(), match.end(), evidence="format"))
            continue
        if info.kind != "secret_like":
            continue
        if len(candidate) < min_length:
            continue
        entropy = info.entropy or calculate_entropy(candidate)
        threshold = 3.0 if info.is_hex else min_entropy
        if info.is_hex and len(candidate) < 32:
            continue
        if entropy < threshold:
            continue
        evidence = _corroboration(text, start, field_name)
        if not evidence:
            decoded = tk.decode_base64(candidate) if len(candidate) >= 40 else None
            if decoded and len(decoded) >= 16:
                continue  # base64 of printable text (a command, a message) is content, not a key
        if evidence:
            findings.append(
                _finding(
                    "High Entropy Secret", _CATEGORY_ENTROPY, "High", candidate, 0.9, start, start + len(candidate),
                    entropy=round(entropy, 2), evidence=evidence,
                ),
            )
        elif is_identifier_field(field_name):
            continue
        elif report_uncorroborated:
            findings.append(
                _finding(
                    "Secret.TokenLikeValue", _CATEGORY_ENTROPY, "Medium", candidate, 0.85, start, start + len(candidate),
                    entropy=round(entropy, 2), evidence=None,
                ),
            )
        else:
            findings.append(
                _finding(
                    "High Entropy Secret", _CATEGORY_ENTROPY, "High", candidate, 0.6, start, start + len(candidate),
                    entropy=round(entropy, 2), evidence=None,
                ),
            )
    return findings
