from src.engine.detector import DetectionEngine
from src.engine.entropy import calculate_entropy
from src.engine.layers import (
    scan_credentials,
    scan_entropy,
    scan_financial,
    scan_healthcare,
    scan_pii,
    scan_regional,
)
from src.engine.luhn import luhn_check


def test_luhn_check():
    # Valid credit cards (standard test numbers)
    assert luhn_check("4111 1111 1111 1111") is True
    assert luhn_check("4111111111111111") is True
    assert luhn_check("378282246310005") is True  # AMEX

    # Invalid credit card
    assert luhn_check("4111 1111 1111 1112") is False
    assert luhn_check("abc") is False


def test_calculate_entropy():
    # Low entropy strings (repeated characters)
    assert calculate_entropy("aaaaaaaaaaaaaaaaaaaa") == 0.0

    # High entropy strings (random sequences)
    high_entropy_str = "gP9x2K1mQ8zW0yL7aJ5s"
    assert calculate_entropy(high_entropy_str) > 4.0


def test_scan_pii():
    text = "Contact support at support@accuknox.com or call +1 555 123 4567. Born on 1990-05-15. Live on 123 Main Street, city center."

    findings = scan_pii(text)
    detectors = [f["detector"] for f in findings]

    assert "Email" in detectors
    assert "Date of Birth" in detectors
    assert "Address" in detectors

    email_val = next(f["value"] for f in findings if f["detector"] == "Email")
    assert email_val == "support@accuknox.com"


def test_scan_credentials():
    text = """
    DB_PASSWORD = "SuperSecretPassword123!"
    API_KEY = "api_key:abcdef1234567890abcdef"
    BEARER = "Bearer abcdef-12345_token"
    JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    AWS_ACCESS = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    PRIVATE = "-----BEGIN RSA PRIVATE KEY-----"
    """

    findings = scan_credentials(text)
    detectors = [f["detector"] for f in findings]

    assert "Password Pattern" in detectors
    assert "API Key" in detectors
    assert "Bearer Token" in detectors
    assert "JWT Token" in detectors
    assert "AWS Access Key" in detectors
    assert "AWS Secret Access Key" in detectors
    assert "Private Key Header" in detectors


def test_scan_financial():
    text = """
    CC: 4111-1111-1111-1111
    IBAN: DE89370400440532013000
    SWIFT: DEUTDEDDFXX
    Fake Account: 12345678
    Real Bank Account: Account number is 9876543210
    """

    findings = scan_financial(text)
    detectors = [f["detector"] for f in findings]

    assert "Credit Card" in detectors
    assert "IBAN" in detectors
    assert "SWIFT/BIC" in detectors
    # Bank Account triggers because of proximity to "Account" keyword
    assert "Bank Account" in detectors


def test_scan_healthcare():
    text_phi = "The patient was admitted to the hospital, received a diagnosis, and got a prescription."
    text_normal = "We met at the office to discuss the marketing project plans."

    assert len(scan_healthcare(text_phi)) > 0
    assert len(scan_healthcare(text_normal)) == 0


def test_scan_regional():
    text = "SSN is 000-12-3456. Aadhaar number is 9000 1234 5678. PAN: ABCDE1234F. SIN: 123-456-789. NINO: GG123456C."

    # Active all regions
    findings = scan_regional(text, ["US", "IN", "CA", "GB"])
    detectors = [f["detector"] for f in findings]

    assert "US SSN" in detectors
    assert "IN Aadhaar" in detectors
    assert "IN PAN" in detectors
    assert "CA SIN" in detectors
    assert "GB NINO" in detectors


def test_scan_entropy():
    # Long high entropy random string
    text = "Here is a secret: gP9x2K1mQ8zW0yL7aJ5s8v2nB4p9qR0s"
    findings = scan_entropy(text)

    assert len(findings) > 0
    assert findings[0]["detector"] == "High Entropy Secret"


def test_detector_tuning():
    # git SHA1 (40 lowercase hex) must not fire the AWS secret detector
    findings = scan_credentials("commit: 3f786850e387550fdab836ed7e6dc881de23001b")
    assert "AWS Secret Access Key" not in [f["detector"] for f in findings]
    # a real base64-shaped AWS secret still fires
    findings = scan_credentials('secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
    assert "AWS Secret Access Key" in [f["detector"] for f in findings]

    # cloud/machine 'state'/'city' fields are not addresses without a street word
    findings = scan_pii('"state": "running", "region": "us-east-1", "az": "us-east-1a"')
    assert "Address" not in [f["detector"] for f in findings]
    # a real street line still fires
    findings = scan_pii("Ships to 42 Baker Street, London")
    assert "Address" in [f["detector"] for f in findings]

    # operational timestamps are not birth dates
    findings = scan_pii("updated_at: 2024-05-15 sla_due_date: 2023-01-02")
    assert "Date of Birth" not in [f["detector"] for f in findings]
    findings = scan_pii("date of birth: 1990-05-15")
    dob = [f for f in findings if f["detector"] == "Date of Birth"]
    assert dob and dob[0]["score"] > 0.8

    # Luhn-passing digit runs without a card-network prefix are not credit cards
    findings = scan_financial("trace ids 9988776655443325 and 1750000000009")
    assert "Credit Card" not in [f["detector"] for f in findings]
    findings = scan_financial("card: 4111-1111-1111-1111")
    assert "Credit Card" in [f["detector"] for f in findings]

    # a bare 'account' (AWS account ids everywhere in cloud data) is not bank context
    findings = scan_financial("aws account: 123456789012 in region us-east-1")
    assert "Bank Account" not in [f["detector"] for f in findings]
    findings = scan_financial("bank account number: 9876543210")
    assert "Bank Account" in [f["detector"] for f in findings]

    # lowercase dns/slug names and short tokens are not entropy secrets
    assert scan_entropy("pod: postgres-postgres-nvk9-0aa1bb2cc3") == []
    assert scan_entropy("k: gP9x2K1mQ8zW0yL7aJ5s") == []  # 20 chars, below min_length 24


def test_detection_engine():
    engine = DetectionEngine({"enabled_regions": ["US"]})
    text = "My email is test@email.com and SSN is 123-45-6789."

    findings = engine.scan_text(text)
    detectors = [f["detector"] for f in findings]

    assert "Email" in detectors
    assert "US SSN" in detectors


def test_new_updates_and_filters():
    engine = DetectionEngine()

    # 1. Verify demo emails are ignored
    text_demo_email = "Email is abc@example.com or user@example.org or info@domain.com"
    findings_demo = engine.scan_text(text_demo_email)
    assert len(findings_demo) == 0

    # Verify non-demo email is matched
    text_real_email = "Email is contact@accuknox.com"
    findings_real = engine.scan_text(text_real_email)
    assert len(findings_real) == 1
    assert findings_real[0]["detector"] == "Email"

    # 2. Verify starred private keys are ignored
    text_starred_key = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    ***********************************
    ***********************************
    -----END OPENSSH PRIVATE KEY-----
    """
    findings_key = engine.scan_text(text_starred_key)
    assert len(findings_key) == 0

    # 3. Verify SWIFT/BIC false positive blacklist ignores 'CERTIFICATE'
    text_fp = "The status is CERTIFICATE"
    findings_fp = engine.scan_text(text_fp)
    assert len(findings_fp) == 0
