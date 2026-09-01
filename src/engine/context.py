"""
Field-name (column / document key / CSV header) intelligence.

In structured data the field name is the strongest signal there is: a 32-char
opaque value in `secret_key` is a credential whatever its entropy, and the same
value in `etag` or `request_id` never is. This module classifies field names and
exposes per-detector hints and suppressions used by the detection engine.
"""
import re
from typing import Optional

from src.engine.rules import tokenize_field_name

# Field names whose values are credentials by construction
CREDENTIAL_FIELD_RE = re.compile(
    r"\b(?:"
    r"tokens?|secrets?|passw(?:or)?ds?|passwd|pwd|passcode|passphrase|"
    r"api ?keys?|apikey|x api key|x auth token|access ?keys?|secret ?keys?|private ?keys?|"
    r"client ?secret|signing ?key|encryption ?key|master ?key|license ?key|"
    r"credentials?|auth|authorization|bearer|jwt|cookies?|set cookie|"
    r"session ?(?:id|token|key)?|sessid|webhook(?: url)?|header ?value|"
    r"refresh ?token|access ?token|id ?token|auth ?token|oauth|otp|cvv|cvc|"
    r"ssh ?key|pem|keyfile|connection ?string|conn ?str|dsn"
    r")\b",
)

# Field names whose values are technical identifiers, never secrets
IDENTIFIER_FIELD_RE = re.compile(
    r"\b(?:"
    r"ids?|uuid|guid|arn|sha\d*|md5|hash|digest|etag|checksum|fingerprint|"
    r"if none match|if match|sec websocket (?:accept|key)|x guploader uploadid|"
    r"x request id|request id|trace ?id|traceparent|span ?id|correlation ?id|"
    r"path|uri|url|href|link|file ?key|s3 file path|scan file|audit files|references?|"
    r"source|destination|location|labels?|summary|description|solution|message|title|name|"
    r"resource ?id|image|version|commit|revision|build ?id|run ?id|job ?id|"
    r"order ?id|txn ?id|transaction ?id|account ?id|subscription ?id|project ?(?:id|number)|"
    r"slug|namespace|hostname|host|cluster|node ?name|pod ?name|container ?id|image ?id|"
    r"layer|manifest|blob|user ?agent|referer|content type|accept|filename|file ?name"
    r")\b",
)

# Field names whose numeric values are counters / ids / timestamps, not card or ID numbers
NUMERIC_ID_FIELD_RE = re.compile(
    r"\b(?:"
    r"ids?|uuid|guid|request id|trace ?id|span ?id|order ?id|txn ?id|transaction ?id|"
    r"account ?id|subscription ?id|project ?(?:id|number)|run ?id|job ?id|build ?id|pid|port|"
    r"timestamp|epoch|created|updated|modified|expires?|ttl|version|size|bytes|count|offset|"
    r"index|seq|sequence|hash|sha\d*|etag|arn|serial|batch|chunk|page|line|row"
    r")\b",
)

# "national id", "tax id", "patient number": the qualifier makes the field a personal identifier,
# not a technical one - the generic id/number rules below must not suppress it
PERSONAL_ID_FIELD_RE = re.compile(
    r"\b(?:national|nation|tax|taxpayer|passport|patient|member|health|voter|citizen|resident|identity|personal|"
    r"government|govt|insurance|policy|licen[cs]e|driving|driver|social|aadhaar|pan|nric|emirates|iqama|civil|"
    r"registration|birth|beneficiary|medicare|medicaid|subscriber|student|employee|person|customer tax|fiscal)"
    r"\s?(?:ids?|no|number|num|nr|code)\b",
)

# Which detector a bare opaque value in a credential field should be reported as
_CREDENTIAL_KIND_RULES = (
    (re.compile(r"\b(?:passw(?:or)?ds?|passwd|pwd|passcode|passphrase)\b"), "Password Pattern"),
    (re.compile(r"\b(?:refresh ?token|access ?token|id ?token|oauth)\b"), "OAuth Token"),
    (re.compile(r"\b(?:tokens?|bearer|jwt|authorization|auth ?token|cookies?|set cookie|session ?(?:id|token|key)?|sessid|header ?value|x auth token|otp)\b"), "Bearer Token"),
    (re.compile(r"\b(?:api ?keys?|apikey|x api key|secrets?|secret ?keys?|access ?keys?|client ?secret|signing ?key|encryption ?key|master ?key|license ?key|credentials?|auth|private ?keys?|ssh ?key|pem|keyfile|webhook(?: url)?|connection ?string|conn ?str|dsn|cvv|cvc)\b"), "API Key"),
)

# Detector -> regex over the tokenised field name that names the entity
FIELD_HINTS = {
    "Email": re.compile(r"\b(?:e ?mails?|mail|email ?address)\b"),
    "Phone Number": re.compile(r"\b(?:phone|mobile|cell|tel|telephone|fax|whatsapp|msisdn|contact ?(?:number|no|num))\b"),
    "Date of Birth": re.compile(r"\b(?:dob|birth ?date|date of birth|birthday|born|birth)\b"),
    "Address": re.compile(r"\b(?:address|addr|street|city|zip ?code|zip|postal ?code|post ?code|pincode|pin ?code|locality|suburb|address ?line ?\d?)\b"),
    "PII.PersonName": re.compile(r"\b(?:full ?name|first ?name|last ?name|surname|given ?name|family ?name|middle ?name|customer ?name|employee ?name|person ?name|owner ?name|contact ?name|holder ?name|patient ?name|applicant ?name|legal ?name|real ?name)\b"),
    "Password Pattern": re.compile(r"\b(?:passw(?:or)?ds?|passwd|pwd|passcode|passphrase)\b"),
    "Secret.PasswordHash": re.compile(r"\b(?:passw(?:or)?d ?hash|hashed ?password|password ?digest|pw ?hash|pass ?hash|passw(?:or)?ds?|passwd|pwd)\b"),
    "API Key": re.compile(r"\b(?:api ?keys?|apikey|x api key|secret ?keys?|client ?secret|secrets?)\b"),
    "Bearer Token": re.compile(r"\b(?:bearer|authorization|auth ?token|tokens?|jwt|cookies?|session ?(?:id|token)?)\b"),
    "OAuth Token": re.compile(r"\b(?:access ?token|refresh ?token|id ?token|oauth)\b"),
    "AWS Access Key": re.compile(r"\b(?:aws ?access ?key|access ?key ?id|aws ?key)\b"),
    "AWS Secret Access Key": re.compile(r"\b(?:aws ?secret|secret ?access ?key|aws ?secret ?key|secret ?key)\b"),
    "Credit Card": re.compile(r"\b(?:card ?(?:number|num|no)|cc ?(?:number|num|no)|credit ?card|cardnumber|ccnum|card ?pan|primary ?account ?number|pan)\b"),
    "Bank Account": re.compile(r"\b(?:account ?(?:number|num|no)|acct ?(?:number|num|no)?|bank ?account|beneficiary ?account|iban)\b"),
    "IBAN": re.compile(r"\b(?:iban|bank ?account)\b"),
    "SWIFT/BIC": re.compile(r"\b(?:swift|bic|swift ?code|bic ?code)\b"),
    "High Entropy Secret": CREDENTIAL_FIELD_RE,
    "Healthcare Data Detection": re.compile(r"\b(?:diagnosis|icd|medical|patient|prescription|treatment|clinical)\b"),
}

# Detectors whose values are opaque tokens: suppressed in identifier fields
TOKEN_DETECTORS = frozenset({
    "High Entropy Secret", "Secret.TokenLikeValue", "AWS Secret Access Key",
})
# Detectors matching digit runs: suppressed in counter/id/timestamp fields
NUMERIC_DETECTORS = frozenset({
    "Credit Card", "Bank Account", "IN Aadhaar", "US SSN", "CA SIN", "Phone Number",
})


def _joined(field_name: Optional[str]) -> str:
    return " ".join(tokenize_field_name(field_name))


def classify_field(field_name: Optional[str]) -> Optional[str]:
    """
    'credential' | 'identifier' | None. When a field name carries both kinds of
    words ('token_name', 'auth.request_id') the right-most one wins - the leaf
    of a dotted path names what the value actually is.
    """
    joined = _joined(field_name)
    if not joined:
        return None
    cred_end = max((m.end() for m in CREDENTIAL_FIELD_RE.finditer(joined)), default=-1)
    ident_end = max((m.end() for m in IDENTIFIER_FIELD_RE.finditer(joined)), default=-1)
    if ident_end >= 0 and cred_end < ident_end and PERSONAL_ID_FIELD_RE.search(joined):
        ident_end = -1  # national_id, tax_number, patient_id: a personal identifier field
    if cred_end < 0 and ident_end < 0:
        return None
    return "credential" if cred_end >= ident_end else "identifier"


def is_credential_field(field_name: Optional[str]) -> bool:
    return classify_field(field_name) == "credential"


def is_identifier_field(field_name: Optional[str]) -> bool:
    return classify_field(field_name) == "identifier"


def is_numeric_id_field(field_name: Optional[str]) -> bool:
    joined = _joined(field_name)
    if not joined or NUMERIC_ID_FIELD_RE.search(joined) is None:
        return False
    return PERSONAL_ID_FIELD_RE.search(joined) is None


def credential_detector_for_field(field_name: Optional[str]) -> Optional[str]:
    """Detector name to use for a bare opaque value found in a credential field."""
    joined = _joined(field_name)
    if not joined or classify_field(field_name) != "credential":
        return None
    for regex, detector in _CREDENTIAL_KIND_RULES:
        if regex.search(joined):
            return detector
    return "API Key"


def field_hints(detector: str, field_name: Optional[str]) -> bool:
    """True when the field name names the entity the detector looks for."""
    regex = FIELD_HINTS.get(detector)
    if regex is None or not field_name:
        return False
    return regex.search(_joined(field_name)) is not None


_BARE_VALUE_RE = re.compile(r"^[A-Za-z0-9]{1,16}$|^\d[\d .-]{4,20}\d$")
_BARE_EXEMPT = frozenset({"Email", "Phone Number", "Address", "Date of Birth", "PII.PersonName", "Healthcare Data Detection"})


def is_suppressed_by_field(detector: str, field_name: Optional[str], value: Optional[str] = None) -> bool:
    """
    Structural suppression: opaque-token detectors never fire in identifier
    fields (etag, request_id, path...), digit-run detectors never fire in
    counter/id/timestamp fields, and any bare short value (a 10-digit number,
    a 9-char alphanumeric) is an id/timestamp/hash in those fields whatever
    recognizer matched it. Explicit hints for the detector win.
    """
    if not field_name:
        return False
    if field_hints(detector, field_name):
        return False
    if detector in TOKEN_DETECTORS and is_identifier_field(field_name):
        return True
    if detector in NUMERIC_DETECTORS and is_numeric_id_field(field_name):
        return True
    if value and detector not in _BARE_EXEMPT and _BARE_VALUE_RE.match(str(value)):
        if is_numeric_id_field(field_name) or is_identifier_field(field_name):
            return True
    return False
