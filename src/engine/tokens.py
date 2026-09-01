"""
Structural analysis of token-like strings.

Shannon entropy alone cannot tell an Azure resource id, a git commit URL or a
CloudFormation stack name from an API key: they are all long, mixed strings.
What separates secrets from identifiers is *shape* - random tokens interleave
letters and digits with no recognisable words, identifiers are words joined by
delimiters with numeric/hex suffixes, paths have slashes and words, UUIDs and
dates are UUIDs and dates. This module encodes those shapes, plus the known
vendor token formats and the well-known example/test values that must never be
reported as real.
"""
import base64
import binascii
import math
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
DATE_RE = re.compile(r"(?<!\d)(?:19|20)\d{2}[-_/.](?:0[1-9]|1[0-2])[-_/.](?:0[1-9]|[12]\d|3[01])(?!\d)")
EPOCH_PART_RE = re.compile(r"^1[5-9]\d{8}(?:\d{3})?$")  # 2017-2033 epoch seconds / millis as a whole part
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
SLUG_RE = re.compile(r"^[a-z0-9]+(?:[-_.][a-z0-9]+)+$")
HASH_PREFIX_RE = re.compile(r"^(?:sha\d{0,3}|md5|blake2b?|sha3)[-:=]", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
STRICT_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
URLSAFE_B64_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")

# Word components inside a letters-only chunk: Capitalized / lowercase / ALLCAPS
COMPONENT_RE = re.compile(r"[A-Z][a-z]+|[a-z]+|[A-Z]+(?![a-z])")
ALLCAPS_RE = re.compile(r"^[A-Z]{2,}$")
LETTER_RUN_RE = re.compile(r"[A-Za-z]{5,}")
ALPHA_CHUNK_RE = re.compile(r"[A-Za-z]+")
PART_SPLIT_RE = re.compile(r"[-_./=+~:]+")
VOWELS = frozenset("aeiouyAEIOUY")
CONSONANT_RUN_RE = re.compile(r"[^aeiouyAEIOUY]{5,}")

# base64 of "-----BEGIN" and of "Salted__" (OpenSSL enc output)
B64_PEM_PREFIX = "LS0tLS1CRUdJTi"
B64_SALTED_PREFIX = "U2FsdGVkX1"

# Values published as examples in vendor documentation - never real
EXAMPLE_SECRETS = frozenset({
    "AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE", "AKIAIOSFODNN7EXAMPLF",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",  # pragma: allowlist secret
    "AKIAJZ4GXP4HEXAMPLE", "ASIAIOSFODNN7EXAMPLE",
})
EXAMPLE_SUFFIX_RE = re.compile(r"EXAMPLE(?:KEY)?$")

# Documented test card numbers (Stripe, PayPal, Braintree, Adyen, networks' own)
TEST_CARD_NUMBERS = frozenset({
    "4111111111111111", "4012888888881881", "4222222222222", "4242424242424242", "4000000000000002",
    "4000056655665556", "4000000000000069", "4000000000000119", "4000000000000341", "4000000000009995",
    "4000000000000077", "4917610000000000", "4484070000000000", "4005519200000004", "4009348888881881",
    "5555555555554444", "5105105105105100", "5200828282828210", "5555555555554444", "2223003122003222",
    "5424000000000015", "5431111111111111", "5105105105105100",
    "378282246310005", "371449635398431", "378734493671000", "340000000000009", "370000000000002",
    "6011111111111117", "6011000990139424", "6011000000000012", "6011601160116611",
    "3530111333300000", "3566002020360505", "3530111333300000", "30569309025904", "38520000023237",
    "6200000000000005", "6205500000000000004", "6759649826438453", "6799990100000000019",
    "5019717010103742", "6331101999990016", "0000000000000000",
})

# Passwords that appear in every security advisory and tutorial
EXAMPLE_PASSWORDS = frozenset({
    "password", "passw0rd", "p@ssw0rd", "p@ssword", "password1", "password123", "password!", "pass",
    "hunter2", "secret", "s3cr3t", "s3cret", "changeme", "change_me", "changeit", "letmein", "qwerty",
    "123456", "12345678", "123456789", "admin", "admin123", "administrator", "root", "toor", "test",
    "test123", "testpass", "foobar", "foobarbaz", "foo", "bar", "baz", "example", "mypassword",
    "yourpassword", "your_password", "mysecret", "supersecret", "dummy", "sample", "welcome", "welcome1",
    "abc123", "p@$$w0rd", "p@$$w0rd1234!", "adminpassword", "adminpassword123!", "guest", "default",
    "temp", "temporary", "none", "null", "nil", "undefined", "true", "false", "xxx", "xxxx", "xxxxxxxx",
})

# Values that are references to secrets, not secrets: templating, env lookups, masks
PLACEHOLDER_RE = re.compile(
    r"^(?:"
    r"[*x#•●·]{2,}.*|[a-z]{1,2}[*]{3,}|"                       # masks: ****, Aa********
    r"\$\{.*|\$\(.*|\{\{.*|<[^>]*>|%[^%]+%|\$[A-Z_][A-Z0-9_]*|\$$|"  # ${VAR} $(cmd) {{tpl}} <placeholder> %VAR% $VAR
    r"!(?:ref|sub|getatt|join)\b.*|"                            # CloudFormation intrinsics
    r"(?:process\.env|os\.environ|env|environ|secrets?|var|local|data|module|random_string|random_password|ref|lookup|vault|ssm|kms|aws_secretsmanager_secret\w*)[.(\[:].*|"
    r"\[?(?:redacted|masked|hidden|filtered|removed|omitted|snip|censored)\]?|"
    r"\.{3,}|-{2,}|_{2,}|"
    r"(?:your|my|the|a|an|some|insert|enter|type|replace|put)[-_ ]?(?:own[-_ ]?)?(?:password|secret|key|token|value|passwd|pwd)(?:[-_ ]?here)?|"
    r"n/?a|null|none|nil|undefined|true|false|yes|no|on|off|empty|blank|unset|"
    r"todo|tbd|fixme|changeme|change[-_ ]?me|placeholder|dummy|sample|example\w*|xxx+|\?+"
    r")$",
    re.IGNORECASE,
)
CODE_CHARS = frozenset("(){}[];<>\\`|")

# Known vendor token formats (prefixes make these near-certain). Regexes derived
# from public documentation / gitleaks defaults.
VENDOR_TOKEN_RULES: List[Tuple[str, "re.Pattern"]] = [
    ("GitHub Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b")),
    ("GitHub Token", re.compile(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b")),
    ("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("GitLab Token", re.compile(r"\b(?:glptt|glrt|gldt|glft|glsoat|glcbt)-[A-Za-z0-9_-]{20,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9-]*\b")),
    ("Slack Token", re.compile(r"\bxapp-1-[A-Z0-9]+-\d+-[a-z0-9]+\b")),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Google OAuth Token", re.compile(r"\bya29\.[0-9A-Za-z_-]{30,}\b")),
    ("OpenAI API Key", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI API Key", re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-(?:admin01|api03)-[A-Za-z0-9_-]{80,}AA\b")),
    ("Stripe Key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,99}\b")),
    ("SendGrid Key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("Twilio Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("Mailchimp Key", re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b")),
    ("Mailgun Key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("HashiCorp Vault Token", re.compile(r"\bhv[sb]\.[A-Za-z0-9_-]{24,}\b")),
    ("Docker Hub Token", re.compile(r"\bdckr_pat_[A-Za-z0-9_-]{27,}\b")),
    ("npm Token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PyPI Token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b")),
    ("Azure Storage Key", re.compile(r"(?i)AccountKey=([A-Za-z0-9+/]{86}==)")),
    ("Azure SAS Token", re.compile(r"(?i)(?:\?|&)sv=\d{4}-\d{2}-\d{2}&[^\s\"']*sig=[A-Za-z0-9%+/]{20,}")),
    ("Shopify Token", re.compile(r"\bshp(?:at|ss|ca|pa)_[0-9a-fA-F]{32}\b")),
    ("Square Token", re.compile(r"\bsq0(?:atp|csp)-[0-9A-Za-z_-]{22,43}\b")),
    ("Telegram Bot Token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b")),
    ("Databricks Token", re.compile(r"\bdapi[a-h0-9]{32}\b")),
    ("Atlassian Token", re.compile(r"\bATATT3[A-Za-z0-9_=-]{150,}\b")),
    ("Grafana Token", re.compile(r"\b(?:glc_[A-Za-z0-9+/]{32,}={0,2}|glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})\b")),
    ("Postman Key", re.compile(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b")),
    ("Hugging Face Token", re.compile(r"\bhf_[A-Za-z]{34}\b")),
    ("Age Secret Key", re.compile(r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b")),
    ("Discord Bot Token", re.compile(r"\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}\b")),
    ("Heroku API Key", re.compile(r"(?i)heroku[\w\s\"':=]{0,20}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")),
]


@dataclass
class TokenInfo:
    token: str
    kind: str = ""            # secret_like | identifier | path | assignment | jwt | pem | salted | uuid | date | slug | hash | short
    entropy: float = 0.0
    is_hex: bool = False
    random_coverage: float = 0.0
    parts: Tuple[str, ...] = ()


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _vowel_ratio(text: str) -> float:
    return sum(c in VOWELS for c in text) / max(1, len(text))


def _good_component(comp: str, multi: bool) -> Optional[bool]:
    """
    Word-shaped component? True = counts as a word, False = counts against,
    None = neutral. Inside a multi-component (CamelCase) chunk short pieces are
    neutral: random mixed-case runs are full of 'Ej', 'Gup', 'MDD' fragments,
    while real identifiers carry their short words as delimited parts.
    """
    if ALLCAPS_RE.match(comp) or (len(comp) == 1 and comp.isupper()):
        if len(comp) <= 3:
            return None if multi else True
        return len(comp) < 16 and 0.2 <= _vowel_ratio(comp) <= 0.65
    if multi and len(comp) < 4:
        return None
    if len(comp) < 2 or (len(comp) == 2 and not any(c in VOWELS for c in comp)):
        return False
    if CONSONANT_RUN_RE.search(comp):
        return False
    return _vowel_ratio(comp) >= 0.25


def is_wordlike_chunk(alpha: str) -> bool:
    """
    True when a letters-only chunk reads like words: 'localhost', 'Authorization',
    'resourceGroups', 'MASS', 'windowsComplianceSTIG'. Random mixed-case runs
    ('BoYddPrCb', 'szmegnOj', 'sLaov', 'MDDXnEjDoga') fail: stray single letters,
    consonant clusters, too few vowels, only short fragments.
    """
    if len(alpha) < 2 or not alpha.isalpha():
        return False
    components = COMPONENT_RE.findall(alpha)
    if not components or any(len(c) == 1 for c in components):
        return False
    multi = len(components) > 1
    good = 0
    for comp in components:
        verdict = _good_component(comp, multi)
        if verdict:
            good += len(comp)
    return good / len(alpha) >= 0.6


def is_wordlike(part: str) -> bool:
    """
    A delimiter-separated part that reads like a word (letters only). Parts with
    digits ('cluster01', 'x9fJ2') are never words.
    """
    return part.isalpha() and is_wordlike_chunk(part)


def has_word(text: str, min_len: int = 3) -> bool:
    """Any letters-only chunk of text (split on non-letters) that reads like a word."""
    return any(len(chunk) >= min_len and is_wordlike_chunk(chunk) for chunk in ALPHA_CHUNK_RE.findall(text))


def _transitions(text: str) -> int:
    """Number of letter<->digit boundaries."""
    count = 0
    prev = None
    for ch in text:
        kind = "d" if ch.isdigit() else ("l" if ch.isalpha() else None)
        if kind and prev and kind != prev:
            count += 1
        if kind:
            prev = kind
    return count


def is_random_looking(part: str, min_len: int = 8) -> bool:
    """
    Machine-generated shape: letters and digits interleaved (or heavily mixed
    case) with no natural-language letter run.
    """
    if len(part) < min_len:
        return False
    letters = sum(c.isalpha() for c in part)
    digits = sum(c.isdigit() for c in part)
    if HEX_RE.match(part):
        return len(part) >= 32
    upper = sum(c.isupper() for c in part)
    lower = letters - upper
    mixed_case = upper >= 2 and lower >= 2
    if digits >= 2 and letters >= 2 and _transitions(part) >= 3:
        pass
    elif mixed_case and len(part) >= 12 and _case_transitions(part) >= 4:
        pass
    else:
        return False
    for run in LETTER_RUN_RE.findall(part):
        # ALL-CAPS runs of 5 letters happen in random base64 too; need 6+ to count
        if ALLCAPS_RE.match(run) and len(run) < 6:
            continue
        if is_wordlike_chunk(run):
            return False
    return True


def _case_transitions(text: str) -> int:
    count = 0
    prev = None
    for ch in text:
        if not ch.isalpha():
            continue
        kind = "u" if ch.isupper() else "l"
        if prev and kind != prev:
            count += 1
        prev = kind
    return count


def looks_like_identifier(token: str) -> bool:
    """
    Words joined by delimiters, optionally with numeric/hex suffixes:
    MASS_ASSIGNMENT_CREATE_ADMIN_ROLE-f9610e225ceaf24d, eksctl-do-1778-nodegroup-...
    """
    return identifier_word_share(token) >= 0.4


def identifier_word_share(token: str) -> float:
    """
    Share of the token's letters that sit in word-like chunks once split on
    delimiters and letter/digit boundaries. 1.0 for pure digits.
    """
    parts = [p for p in PART_SPLIT_RE.split(token) if p]
    if not parts:
        return 0.0
    letters_total = sum(sum(c.isalpha() for c in p) for p in parts)
    if letters_total == 0:
        return 1.0
    word_letters = 0
    for part in parts:
        for chunk in ALPHA_CHUNK_RE.findall(part):
            if len(chunk) >= 2 and is_wordlike_chunk(chunk):
                word_letters += len(chunk)
    share = word_letters / letters_total
    if share < 0.4 and word_letters > 0 and any(EPOCH_PART_RE.match(p) for p in parts):
        share = 0.4  # words + an epoch timestamp: a generated name
    return share


def analyze_token(token: str, min_length: int = 24) -> TokenInfo:
    """Classifies a candidate token by shape. Cheap checks first."""
    info = TokenInfo(token=token)
    if len(token) < min_length:
        info.kind = "short"
        return info
    if JWT_RE.match(token):
        info.kind = "jwt"
        return info
    if token.startswith(B64_PEM_PREFIX):
        info.kind = "pem"
        return info
    if token.startswith(B64_SALTED_PREFIX):
        info.kind = "salted"
        return info
    if "BEGIN" in token or "PRIVATE" in token:
        info.kind = "pem"
        return info
    if UUID_RE.search(token):
        info.kind = "uuid"
        return info
    if DATE_RE.search(token):
        info.kind = "date"
        return info
    if HASH_PREFIX_RE.match(token):
        info.kind = "hash"
        return info
    if SLUG_RE.match(token):
        info.kind = "slug"
        return info
    if "//" in token or token.count("/") >= 2:
        info.kind = "path"
        return info
    if "/" in token or ("=" in token.rstrip("=")):
        # one slash or an inner '=': a path/assignment unless it is one base64 blob
        head, sep, tail = (token.partition("/") if "/" in token else token.partition("="))
        if has_word(head) or (tail and has_word(tail.split("/")[0])):
            info.kind = "assignment" if sep == "=" else "path"
            info.parts = (head, tail)
            return info
    info.is_hex = bool(HEX_RE.match(token))
    info.entropy = shannon_entropy(token)
    parts = tuple(p for p in PART_SPLIT_RE.split(token) if p)
    info.parts = parts
    random_letters = sum(len(p) for p in parts if is_random_looking(p))
    info.random_coverage = random_letters / max(1, len(token))
    word_share = identifier_word_share(token)
    whole_random = is_random_looking(token, min_len=min_length)
    if word_share >= 0.6:
        info.kind = "identifier"          # mostly words: a generated name, whatever else it holds
    elif word_share >= 0.4 and not whole_random:
        info.kind = "identifier"
    elif whole_random or info.random_coverage >= 0.6:
        info.kind = "secret_like"
    else:
        info.kind = "identifier"
    return info


VENDOR_GATE_RE = re.compile(
    r"gh[poursx]_|github_pat_|gl[a-z]{2,5}-|xox[baprs]-|xapp-1-|hooks\.slack\.com|AIza|ya29\.|sk-|SG\.|\bSK[0-9a-fA-F]{32}|"
    r"-us\d{1,2}\b|key-[0-9a-zA-Z]{32}|hv[sb]\.|dckr_pat_|npm_|pypi-|AccountKey=|sv=\d{4}|shp(?:at|ss|ca|pa)_|sq0(?:atp|csp)-|"
    r"\d{8,10}:AA|dapi[a-h0-9]{32}|ATATT3|gl(?:c|sa)_|PMAK-|hf_[A-Za-z]{34}|AGE-SECRET-KEY-1|[MN][A-Za-z\d]{23,}\.|heroku",
    re.IGNORECASE,
)


def find_vendor_tokens(text: str) -> List[Tuple[str, int, int, str]]:
    """(detector, start, end, value) for every known vendor token format in text."""
    out = []
    if not VENDOR_GATE_RE.search(text):
        return out
    for name, regex in VENDOR_TOKEN_RULES:
        for m in regex.finditer(text):
            if m.groups():
                out.append((name, m.start(1), m.end(1), m.group(1)))
            else:
                out.append((name, m.start(), m.end(), m.group(0)))
    return out


def is_example_secret(value: str) -> bool:
    return value in EXAMPLE_SECRETS or EXAMPLE_SUFFIX_RE.search(value) is not None


def is_test_card(digits: str) -> bool:
    return digits in TEST_CARD_NUMBERS


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'`")
    if not v:
        return True
    if v.lower() in EXAMPLE_PASSWORDS and v.lower() in {"none", "null", "nil", "undefined", "true", "false", "n/a", "example", "placeholder", "changeme"}:
        return True
    return PLACEHOLDER_RE.match(v) is not None


def is_example_password(value: str) -> bool:
    v = value.strip().strip("\"'`").lower()
    return v in EXAMPLE_PASSWORDS or v.rstrip("!.?") in EXAMPLE_PASSWORDS


def looks_like_code(value: str) -> bool:
    return any(c in CODE_CHARS for c in value)


def decode_base64(token: str, max_len: int = 4096) -> Optional[str]:
    """
    Decodes a standard or URL-safe base64 token to text when the result is
    printable ASCII/UTF-8; None otherwise.
    """
    t = token.strip()
    if len(t) < 8 or len(t) > max_len:
        return None
    try:
        if STRICT_B64_RE.match(t):
            padded = t + "=" * (-len(t) % 4)
            raw = base64.b64decode(padded, validate=True)
        elif URLSAFE_B64_RE.match(t):
            padded = t + "=" * (-len(t) % 4)
            raw = base64.urlsafe_b64decode(padded)
        else:
            return None
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    if printable / len(text) < 0.9:
        return None
    return text


def jwt_parts(token: str) -> Optional[Tuple[dict, dict]]:
    """(header, payload) dicts when token is a well-formed JWT, else None."""
    import json

    segments = token.split(".")
    if len(segments) < 2:
        return None
    try:
        header = json.loads(decode_base64(segments[0]) or "")
        payload = json.loads(decode_base64(segments[1]) or "")
    except (ValueError, TypeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    if "alg" not in header and "typ" not in header:
        return None
    return header, payload
