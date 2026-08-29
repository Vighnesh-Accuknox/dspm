import re

# pyrefly: ignore [missing-import]
import phonenumbers

from src.engine.entropy import calculate_entropy
from src.engine.luhn import luhn_check

# Layer 1: Global PII
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
DOB_REGEX = re.compile(r"\b(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b")
ADDRESS_KEYWORDS = [
    "street",
    "road",
    "avenue",
    "postal code",
    "zip code",
    "city",
    "state",
    "country",
]

# Layer 2: Credentials and Secrets
PASSWORD_REGEX = re.compile(
    r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"]?([^\s\'"]+)[\'"]?',
)
API_KEY_REGEX = re.compile(r'(?i)(api[_-]?key)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{16,})')
BEARER_TOKEN_REGEX = re.compile(r"Bearer\s+([A-Za-z0-9\-._~+/]+=*)")
JWT_REGEX = re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+")
OAUTH_TOKEN_REGEX = re.compile(
    r'(?i)(access_token|refresh_token|id_token)\s*[:=]\s*[\'"]?([A-Za-z0-9\-._~+/]+=*)',
)
AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
AWS_SECRET_KEY_REGEX = re.compile(
    r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
)
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)?PRIVATE KEY-----")

# Layer 3: Financial Data
CREDIT_CARD_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
IBAN_REGEX = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b")
SWIFT_REGEX = re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b")
BANK_ACCOUNT_REGEX = re.compile(r"\b\d{8,20}\b")
BANK_ACCOUNT_KEYWORDS = [
    "account",
    "bank",
    "routing",
    "ifsc",
    "iban",
    "swift",
    "beneficiary",
]

# Layer 4: Healthcare Data
HEALTHCARE_KEYWORDS = [
    "patient",
    "diagnosis",
    "treatment",
    "prescription",
    "hospital",
    "medical",
    "doctor",
    "insurance",
    "health record",
]

# Layer 5: Regional Compliance
REGIONAL_REGEXES = {
    "US": {"SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b")},
    "IN": {
        "Aadhaar": re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b"),
        "PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
        "GST": re.compile(
            r"\b((?:0[1-9]|[1-3][0-7])[A-Za-z0-9]{10}[A-Za-z0-9]{1}Z[A-Za-z0-9]{1})\b",
        ),
        "PASSPORT": re.compile(r"\b[A-Z][1-9]\d\s?\d{4}[1-9]\b"),
        "VOTER ID": re.compile(
            r"\b([A-Za-z]{1}[ABCDGHJKMNPRSYabcdghjkmnprsy]{1}[A-Za-z]{1}([0-9]){7})\b",
        ),
    },
    "CA": {"SIN": re.compile(r"\b\d{3}-\d{3}-\d{3}\b")},
    "GB": {"NINO": re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]?\b")},
}

# Layer 6: Entropy Candidates
ENTROPY_CANDIDATE_REGEX = re.compile(r"\b[A-Za-z0-9/+=_\-~]{20,}\b")

# Presidio Context Mapping
CONTEXT_WORDS = {
    "Email": ["email", "e-mail", "mail", "address", "contact"],
    "Phone Number": ["phone", "mobile", "call", "telephone", "tel", "cell"],
    "Date of Birth": ["birth", "born", "dob", "date", "birthday"],
    "Address": [
        "address",
        "street",
        "road",
        "city",
        "state",
        "zip",
        "postal",
        "house",
        "number",
    ],
    "Password Pattern": ["password", "passwd", "pwd", "secret", "credentials", "key"],
    "API Key": ["api", "key", "apikey", "token", "secret"],
    "Bearer Token": ["bearer", "token", "auth", "authorization"],
    "OAuth Token": ["oauth", "token", "access", "refresh"],
    "IBAN": ["iban", "bank", "account", "wire", "transfer"],
    "SWIFT/BIC": [
        "swift",
        "bic",
        "bank",
        "routing",
        "code",
        "financial",
        "payment",
        "transfer",
    ],
    "Bank Account": [
        "account",
        "bank",
        "routing",
        "ifsc",
        "iban",
        "swift",
        "beneficiary",
    ],
    "US SSN": ["ssn", "social security", "tax", "identity"],
    "IN Aadhaar": ["aadhaar", "uidai", "identity", "card"],
    "IN GST": [
        "gstin",
        "gst",
        "goods and services tax",
        "tax identification",
        "gst number",
        "gst registration",
    ],
    "IN VOTER ID": [
        "voter",
        "epic",
        "elector photo identity card",
    ],
    "IN PASSPORT": ["passport", "indian passport", "passport number"],
    "IN PAN": ["pan", "tax", "income", "identity"],
    "CA SIN": ["sin", "social insurance", "tax"],
    "GB NINO": ["nino", "national insurance", "tax"],
}

# SWIFT/BIC false positive blacklist
SWIFT_BLACKLIST = {
    "CERTIFICATE",
    "DESCRIPTION",
    "AUTHORITY",
    "PARAMETERS",
    "APPLICATION",
    "PROPERTIES",
    "IDENTIFIER",
    "INFORMATION",
    "DEVELOPMENT",
    "DEPRECATED",
    "REQUIREMENT",
    "ENVIRONMENT",
    "TRANSACTION",
    "DESTINATION",
    "INSTRUCTION",
    "CONSTRUCTION",
    "METADATA",
    "CERT",
}


def calculate_match_score(
    text: str,
    start: int,
    end: int,
    base_score: float,
    detector_name: str,
) -> float:
    """
    Computes context-boosted score for a finding based on nearby keywords (Presidio rules).
    """
    keywords = CONTEXT_WORDS.get(detector_name)
    if not keywords:
        return base_score

    # Search in a window of 100 characters before and after the match
    window_start = max(0, start - 100)
    window_end = min(len(text), end + 100)
    context_window = text[window_start:window_end].lower()

    for kw in keywords:
        if kw in context_window:
            # Determine boost based on detector
            boost = 0.35
            if detector_name in [
                "Phone Number",
                "Date of Birth",
                "US SSN",
                "IN Aadhaar",
                "IN PAN",
                "CA SIN",
                "GB NINO",
                "IN GST",
            ]:
                boost = 0.45
            elif detector_name in ["Password Pattern"]:
                boost = 0.4
            elif detector_name in ["Email", "API Key", "Bearer Token", "OAuth Token"]:
                boost = 0.3
            elif detector_name in ["Address"]:
                boost = 0.35
            elif detector_name in ["IBAN"]:
                boost = 0.2
            elif detector_name in ["SWIFT/BIC", "Bank Account"]:
                boost = 0.35

            return min(1.0, base_score + boost)

    return base_score


def is_demo_email(email: str) -> bool:
    """
    Returns True if the email is a demo email like abc@example.com.
    """
    email_lower = email.lower()
    parts = email_lower.split("@")
    if len(parts) != 2:
        return True
    if any(term in email_lower for term in ["abc", "example", "xyz", "domain"]):
        return True
    return False


def is_starred_private_key(text: str, start: int) -> bool:
    """
    Returns True if the private key content consists only of stars (*).
    """
    sub_text = text[start : start + 1000]

    # Look for a private key footer
    footer_pattern = re.compile(
        r"(-----END [A-Z ]+PRIVATE KEY-----|------? ?END [A-Z ]+KEY------?)",
    )
    footer_match = footer_pattern.search(sub_text)
    if footer_match:
        # Extract content between header and footer
        header_end_match = re.search(
            r"(-----BEGIN [A-Z ]+PRIVATE KEY-----|------? ?BEGIN [A-Z ]+KEY------?)",
            sub_text,
        )
        if header_end_match:
            header_end = header_end_match.end()
            between = sub_text[header_end : footer_match.start()].strip()
            # Clean whitespaces and dashes
            cleaned = re.sub(r"[\s\-]", "", between)
            if not cleaned or set(cleaned) == {"*"}:
                return True
    return False


def scan_pii(text: str) -> list:
    findings = []

    # 1. Emails
    for match in EMAIL_REGEX.finditer(text):
        val = match.group(0)
        if is_demo_email(val):
            continue

        score = calculate_match_score(text, match.start(), match.end(), 0.6, "Email")
        findings.append(
            {
                "detector": "Email",
                "category": "PII",
                "severity": "Medium",
                "value": val,
                "score": score,
                "start": match.start(),
                "end": match.end(),
            },
        )

    # 2. Phone Numbers
    try:
        for match in phonenumbers.PhoneNumberMatcher(text, None):
            score = calculate_match_score(
                text,
                match.start,
                match.end,
                0.4,
                "Phone Number",
            )
            findings.append(
                {
                    "detector": "Phone Number",
                    "category": "PII",
                    "severity": "Medium",
                    "value": match.raw_string,
                    "score": score,
                    "start": match.start,
                    "end": match.end,
                },
            )
    except Exception:
        pass

    # 3. DOB
    for match in DOB_REGEX.finditer(text):
        score = calculate_match_score(
            text,
            match.start(),
            match.end(),
            0.4,
            "Date of Birth",
        )
        findings.append(
            {
                "detector": "Date of Birth",
                "category": "PII",
                "severity": "Medium",
                "value": match.group(0),
                "score": score,
                "start": match.start(),
                "end": match.end(),
            },
        )

    # 4. Addresses (Keyword scoring line by line)
    lines = text.splitlines()
    offset = 0
    for line in lines:
        lower_line = line.lower()
        matched_kws = [kw for kw in ADDRESS_KEYWORDS if kw in lower_line]
        if matched_kws:
            has_digit = any(c.isdigit() for c in line)
            if has_digit or len(matched_kws) >= 2:
                start_pos = offset
                end_pos = offset + len(line)
                score = calculate_match_score(text, start_pos, end_pos, 0.5, "Address")
                findings.append(
                    {
                        "detector": "Address",
                        "category": "PII",
                        "severity": "Medium",
                        "value": line.strip(),
                        "score": score,
                        "start": start_pos,
                        "end": end_pos,
                    },
                )
        offset += len(line) + 1  # +1 for newline character

    return findings


def scan_credentials(text: str) -> list:
    findings = []

    def add_secret(detector, value, match_obj, base_score):
        score = calculate_match_score(
            text,
            match_obj.start(),
            match_obj.end(),
            base_score,
            detector,
        )
        findings.append(
            {
                "detector": detector,
                "category": "Credentials and Secrets",
                "severity": "Critical",
                "value": value,
                "score": score,
                "start": match_obj.start(),
                "end": match_obj.end(),
            },
        )

    for match in PASSWORD_REGEX.finditer(text):
        add_secret("Password Pattern", match.group(2), match, 0.5)

    for match in API_KEY_REGEX.finditer(text):
        add_secret("API Key", match.group(2), match, 0.6)

    for match in BEARER_TOKEN_REGEX.finditer(text):
        add_secret("Bearer Token", match.group(1), match, 0.6)

    for match in JWT_REGEX.finditer(text):
        # Self-validating: score is 0.85 directly
        findings.append(
            {
                "detector": "JWT Token",
                "category": "Credentials and Secrets",
                "severity": "Critical",
                "value": match.group(0),
                "score": 0.85,
                "start": match.start(),
                "end": match.end(),
            },
        )

    for match in OAUTH_TOKEN_REGEX.finditer(text):
        add_secret("OAuth Token", match.group(2), match, 0.6)

    for match in AWS_ACCESS_KEY.finditer(text):
        # Self-validating: score is 0.85 directly
        findings.append(
            {
                "detector": "AWS Access Key",
                "category": "Credentials and Secrets",
                "severity": "Critical",
                "value": match.group(0),
                "score": 0.85,
                "start": match.start(),
                "end": match.end(),
            },
        )

    for match in AWS_SECRET_KEY_REGEX.finditer(text):
        val = match.group(0)
        if len(set(val)) > 4:
            # Self-validating: score is 0.85 directly
            findings.append(
                {
                    "detector": "AWS Secret Access Key",
                    "category": "Credentials and Secrets",
                    "severity": "Critical",
                    "value": val,
                    "score": 0.85,
                    "start": match.start(),
                    "end": match.end(),
                },
            )

    for match in PRIVATE_KEY_REGEX.finditer(text):
        if is_starred_private_key(text, match.start()):
            continue
        # Self-validating: score is 0.85 directly
        findings.append(
            {
                "detector": "Private Key Header",
                "category": "Credentials and Secrets",
                "severity": "Critical",
                "value": match.group(0),
                "score": 0.85,
                "start": match.start(),
                "end": match.end(),
            },
        )

    return findings


def scan_financial(text: str) -> list:
    findings = []

    # 1. Credit Cards with Luhn Check
    for match in CREDIT_CARD_REGEX.finditer(text):
        candidate = match.group(0)
        cleaned = re.sub(r"[\s\-]", "", candidate)
        if luhn_check(cleaned):
            # High confidence due to checksum
            findings.append(
                {
                    "detector": "Credit Card",
                    "category": "Financial Data",
                    "severity": "Critical",
                    "value": candidate,
                    "score": 0.85,
                    "start": match.start(),
                    "end": match.end(),
                },
            )

    # 2. IBAN
    for match in IBAN_REGEX.finditer(text):
        score = calculate_match_score(text, match.start(), match.end(), 0.7, "IBAN")
        findings.append(
            {
                "detector": "IBAN",
                "category": "Financial Data",
                "severity": "High",
                "value": match.group(0),
                "score": score,
                "start": match.start(),
                "end": match.end(),
            },
        )

    # 3. SWIFT/BIC
    for match in SWIFT_REGEX.finditer(text):
        val = match.group(0)
        if val.upper() in SWIFT_BLACKLIST:
            continue
        score = calculate_match_score(
            text,
            match.start(),
            match.end(),
            0.5,
            "SWIFT/BIC",
        )
        findings.append(
            {
                "detector": "SWIFT/BIC",
                "category": "Financial Data",
                "severity": "High",
                "value": val,
                "score": score,
                "start": match.start(),
                "end": match.end(),
            },
        )

    # 4. Bank Account numbers with proximity keyword scoring
    for match in BANK_ACCOUNT_REGEX.finditer(text):
        start_idx = max(0, match.start() - 100)
        end_idx = min(len(text), match.end() + 100)
        context_window = text[start_idx:end_idx].lower()

        has_keyword = any(kw in context_window for kw in BANK_ACCOUNT_KEYWORDS)
        if has_keyword:
            score = calculate_match_score(
                text,
                match.start(),
                match.end(),
                0.5,
                "Bank Account",
            )
            findings.append(
                {
                    "detector": "Bank Account",
                    "category": "Financial Data",
                    "severity": "High",
                    "value": match.group(0),
                    "score": score,
                    "start": match.start(),
                    "end": match.end(),
                },
            )

    return findings


def scan_healthcare(text: str) -> list:
    findings = []
    lower_text = text.lower()
    matches = []
    for kw in HEALTHCARE_KEYWORDS:
        matches_found = re.findall(rf"\b{kw}\b", lower_text)
        if matches_found:
            matches.extend(matches_found)

    if len(set(matches)) >= 3:
        findings.append(
            {
                "detector": "Healthcare Data Detection",
                "category": "Healthcare Data (PHI)",
                "severity": "High",
                "value": f"Matched PHI Keywords: {list(set(matches))}",
                "score": 0.85,
                "start": 0,
                "end": len(text),
            },
        )
    return findings


def scan_regional(text: str, enabled_regions: list) -> list:
    findings = []
    if not enabled_regions:
        return findings

    for region in enabled_regions:
        region_rules = REGIONAL_REGEXES.get(region.upper())
        if not region_rules:
            continue

        for name, regex in region_rules.items():
            for match in regex.finditer(text):
                detector_name = f"{region.upper()} {name}"
                score = calculate_match_score(
                    text,
                    match.start(),
                    match.end(),
                    0.5,
                    detector_name,
                )
                findings.append(
                    {
                        "detector": detector_name,
                        "category": "Regional Compliance",
                        "severity": "High",
                        "value": match.group(0),
                        "score": score,
                        "start": match.start(),
                        "end": match.end(),
                    },
                )
    return findings


def scan_entropy(text: str) -> list:
    findings = []
    for match in ENTROPY_CANDIDATE_REGEX.finditer(text):
        candidate = match.group(0)
        if "BEGIN" in candidate or "PRIVATE" in candidate:
            continue

        entropy = calculate_entropy(candidate)
        if entropy >= 4.5:
            findings.append(
                {
                    "detector": "High Entropy Secret",
                    "category": "Entropy-Based Secret Detection",
                    "severity": "High",
                    "value": candidate,
                    "entropy": round(entropy, 2),
                    "score": 0.85,
                    "start": match.start(),
                    "end": match.end(),
                },
            )
    return findings
