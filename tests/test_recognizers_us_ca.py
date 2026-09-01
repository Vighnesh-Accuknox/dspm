"""
Tests for the upstream US / Canada rules (src/engine/recognizers/us_ca.py).

Inputs and expectations are taken from upstream-analyzer's own tests
(tests/test_us_ssn_recognizer.py, test_ca_sin_recognizer.py, ...). the upstream recognizer's
recognizer.analyze() does not apply context enhancement, while run_rule() does:
where a upstream input contains one of the rule's context words the engine
scores +0.35 higher, and those cases assert score >= the upstream recognizer's lower bound
(hi=MAX) instead of the upstream recognizer's exact range.
"""
import json
from pathlib import Path

from src.engine.recognizers.us_ca import RULES
from src.engine.rules import run_rule

ROOT = Path(__file__).resolve().parents[1]
EPS = 1e-4
MAX = 1.0
FIELD_HINT_SCORE = 0.85

# upstream entities without an entry in fixtures/findings-mapping.json (yet)
UNMAPPED = {
    "US_HEALTH_INSURANCE_MEMBER_ID",
    "US_PRIOR_AUTHORIZATION_NUMBER",
    "US_CLAIM_NUMBER",
    "US_PRESCRIPTION_NUMBER",
    "US_REFERRAL_NUMBER",
    "US_PROVIDER_TAX_ID",
}


def _rule(name):
    for rule in RULES:
        if rule.name == name:
            return rule
    raise AssertionError(f"no rule named {name!r}")


def _found(rule, text, field_name=None):
    return sorted(run_rule(rule, text, field_name), key=lambda r: r["start"])


def _check(rule, text, expected):
    """expected: list of (start, end, min_score, max_score) in text order."""
    results = _found(rule, text)
    assert len(results) == len(expected), (rule.name, text, results)
    for res, (start, end, lo, hi) in zip(results, expected):
        assert (res["start"], res["end"]) == (start, end), (rule.name, text, res)
        assert lo - EPS <= res["score"] <= hi + EPS, (rule.name, text, res)
        assert res["value"] == text[start:end]
        assert res["detector"] == rule.name


def _none(rule, text):
    assert _found(rule, text) == [], (rule.name, text)


def _single(rule, text, value, lo, hi=None):
    """Exactly one result, equal to `value`, scored in [lo, hi]."""
    hi = lo if hi is None else hi
    start = text.index(value)
    _check(rule, text, [(start, start + len(value), lo, hi)])


def _below(rule, text, threshold):
    """Every result scores below `threshold` (the upstream recognizer's analyzer would drop it)."""
    for res in _found(rule, text):
        assert res["score"] < threshold - EPS, (rule.name, text, res)


def _field(rule, value, field_name):
    results = _found(rule, value, field_name)
    assert len(results) == 1, (rule.name, value, field_name, results)
    assert results[0]["value"] == value
    assert results[0]["score"] >= FIELD_HINT_SCORE - EPS, (rule.name, value, field_name, results)


# ---------------------------------------------------------------- metadata


def _load_mapping():
    """fixtures/findings-mapping.json: {detector: entry} (historically wrapped in a one-element list)."""
    with open(ROOT / "fixtures" / "findings-mapping.json", encoding="utf-8") as fh:
        data = json.load(fh)
    return data[0] if isinstance(data, list) else data


def test_rule_names_and_risk_match_findings_mapping():
    mapping = _load_mapping()
    assert len({r.name for r in RULES}) == len(RULES) == 17
    for rule in RULES:
        assert rule.region in ("US", "CA"), rule.name
        assert rule.field_hint, rule.name
        assert rule.description, rule.name
        assert rule.examples, rule.name
        if rule.name in UNMAPPED:
            assert rule.category == "Healthcare Data (PHI)", rule.name
            assert rule.severity == "High", rule.name
            continue
        assert rule.name in mapping, rule.name
        entry = mapping[rule.name]
        expected_severity = "Low" if entry["final_risk_factor"] == "Lowest" else entry["final_risk_factor"]
        assert rule.category == entry["category"], rule.name
        assert rule.severity == expected_severity, rule.name


def test_examples_are_detected():
    for rule in RULES:
        for example in rule.examples:
            results = _found(rule, example)
            assert len(results) == 1, (rule.name, example, results)
            assert results[0]["value"] == example, (rule.name, example, results)
            assert results[0]["score"] > 0


def test_context_lists_match_upstream():
    assert _rule("US_NPI").context == (
        "npi", "national provider", "provider", "npi number", "provider id", "provider identifier", "taxonomy",
    )
    assert _rule("US_MBI").context == ("medicare", "mbi", "beneficiary", "cms", "medicaid", "hic", "hicn")
    assert _rule("US_HEALTH_INSURANCE_MEMBER_ID").context == ("member", "subscriber", "insurance", "policy")
    assert _rule("US_PRIOR_AUTHORIZATION_NUMBER").context == ("authorization", "auth", "preauthorization", "approval")
    assert _rule("US_CLAIM_NUMBER").context == ("claim", "billing")
    assert _rule("US_PRESCRIPTION_NUMBER").context == ("prescription", "pharmacy", "medication")
    assert _rule("US_REFERRAL_NUMBER").context == ("referral", "infusion", "specialty", "referring")
    assert _rule("US_PROVIDER_TAX_ID").context == ("tax", "tin", "ein", "billing")
    assert _rule("US SSN").context == ("social", "security", "ssn", "ssns", "ssid")
    assert _rule("CA SIN").context[:5] == ("sin", "sin number", "social insurance", "social insurance number", "canada")
    member = _rule("US_HEALTH_INSURANCE_MEMBER_ID").patterns[0]
    assert (member.name, member.score) == ("Health insurance member ID (weak)", 0.1)


# ---------------------------------------------------------------- US SSN


def test_us_ssn_upstream_cases():
    rule = _rule("US SSN")
    # very weak match
    _check(rule, "078-051121 07805-1121", [(0, 10, 0.0, 0.3), (11, 21, 0.0, 0.3)])
    # weak match
    _check(rule, "078051121", [(0, 9, 0.0, 0.4)])
    # medium match
    for text in ("078-05-1123", "078.05.1123", "078 05 1123"):
        _check(rule, text, [(0, 11, 0.5, 0.6)])
    _check(rule, "abc 078 05 1123 abc", [(4, 15, 0.5, 0.6)])
    # only the canonical 987-65-4320 sample is invalidated, the rest of the family is real
    for last in "123456789":
        _check(rule, f"987-65-432{last}", [(0, 11, 0.5, 0.6)])
    _check(rule, "219-09-9999", [(0, 11, 0.5, 0.6)])


def test_us_ssn_invalid_cases():
    rule = _rule("US SSN")
    for text in (
        "0780511201", "078051120", "000000000", "666000000", "078-05-0000", "078 00 1123", "693-09.4444",
        # canonical sample SSNs
        "987-65-4320", "078-05-1120", "123-45-6789",
        # never-issued area numbers
        "000-12-3456", "666-12-3456",
    ):
        _none(rule, text)


def test_us_ssn_context_and_field_name():
    rule = _rule("US SSN")
    _single(rule, "my social security number is 219-09-9999", "219-09-9999", 0.85)
    _field(rule, "219-09-9999", "customer_ssn")
    _field(rule, "078051121", "social_security_number")
    _field(rule, "078051121", "ssNumber")


# ---------------------------------------------------------------- US ITIN


def test_us_itin_upstream_cases():
    rule = _rule("US_ITIN")
    _check(rule, "911-701234 91170-1234", [(0, 10, 0.0, 0.3), (11, 21, 0.0, 0.3)])
    _check(rule, "911701234", [(0, 9, 0.3, 0.4)])
    for text in ("911-70-1234", "911-53-1234", "911-64-1234"):
        _check(rule, text, [(0, 11, 0.5, 0.6)])
    _none(rule, "911-89-1234")
    _none(rule, "my tax id 911-89-1234")


def test_us_itin_field_name():
    rule = _rule("US_ITIN")
    _field(rule, "911701234", "itin")
    _field(rule, "911-70-1234", "taxpayer_id")


# ---------------------------------------------------------------- US passport


def test_us_passport_upstream_cases():
    rule = _rule("US_PASSPORT")
    _check(rule, "912803456", [(0, 9, 0.0, 0.1)])
    _check(rule, "Z12803456", [(0, 9, 0.0, 0.15)])
    _check(rule, "A12803456", [(0, 9, 0.0, 0.15)])
    # "travel" / "passport" are context words: upstream expects >= 0.0, the engine boosts to 0.45
    _check(rule, "my travel document is A12803456", [(22, 31, 0.0, MAX)])
    _check(rule, "my travel passport is A12803456", [(22, 31, 0.0, MAX)])
    _single(rule, "my travel passport is A12803456", "A12803456", 0.45)


def test_us_passport_field_name():
    _field(_rule("US_PASSPORT"), "912803456", "passport_number")


# ---------------------------------------------------------------- US driver license


def test_us_driver_license_upstream_cases():
    rule = _rule("US_DRIVER_LICENSE")
    _check(rule, "H12234567", [(0, 9, 0.3, 0.4)])
    _none(rule, "C12T345672")
    _check(
        rule,
        "123456789 1234567890 12345679012 123456790123 1234567901234 1234",
        [(0, 9, 0.0, 0.02), (10, 20, 0.0, 0.02), (21, 32, 0.0, 0.02), (33, 45, 0.0, 0.02), (46, 59, 0.0, 0.02)],
    )
    _none(rule, "ABCDEFG ABCDEFGH ABCDEFGHI")
    _none(rule, "ABCD ABCDEFGHIJ")


def test_us_driver_license_field_name():
    rule = _rule("US_DRIVER_LICENSE")
    _field(rule, "H12234567", "drivers_license_no")
    _field(rule, "H12234567", "dl_number")


# ---------------------------------------------------------------- US bank account


def test_us_bank_upstream_cases():
    rule = _rule("Bank Account")
    _check(rule, "945456787654", [(0, 12, 0.05, 0.05)])
    _none(rule, "1234567")


def test_us_bank_field_name():
    rule = _rule("Bank Account")
    _field(rule, "945456787654", "bank_account_number")
    _field(rule, "945456787654", "acct_no")


# ---------------------------------------------------------------- ABA routing


def test_aba_routing_upstream_cases():
    rule = _rule("ABA_ROUTING_NUMBER")
    _check(rule, "121000358", [(0, 9, 1.0, 1.0)])  # Bank of America
    _check(rule, "3222-7162-7", [(0, 11, 1.0, 1.0)])  # Chase
    _check(rule, "121042882", [(0, 9, 1.0, 1.0)])  # Wells Fargo
    _check(rule, "0711-0130-7", [(0, 11, 1.0, 1.0)])
    _none(rule, "421042111")
    _none(rule, "1234-0000-0")


def test_aba_routing_field_name():
    _field(_rule("ABA_ROUTING_NUMBER"), "121000358", "routing_number")


# ---------------------------------------------------------------- medical license (DEA)


def test_medical_license_upstream_cases():
    rule = _rule("MEDICAL_LICENSE")
    _check(rule, "GL0285191 EU4488929", [(0, 9, 1.0, 1.0), (10, 19, 1.0, 1.0)])
    _check(rule, "K92993548", [(0, 9, 1.0, 1.0)])
    _check(rule, "my certificate number is: BB1388568", [(26, 35, 1.0, 1.0)])
    _none(rule, "The DEA number is  BG8207031")  # fails the DEA check digit
    _none(rule, "123 456\n789")


def test_medical_license_field_name():
    _field(_rule("MEDICAL_LICENSE"), "GL0285191", "dea_number")


# ---------------------------------------------------------------- US NPI


def test_us_npi_upstream_cases():
    rule = _rule("US_NPI")
    for text in ("1234567893", "1245319599", "1003000126"):
        _check(rule, text, [(0, 10, MAX, MAX)])
    _check(rule, "1234-567-893", [(0, 12, MAX, MAX)])
    _check(rule, "1234 567 893", [(0, 12, MAX, MAX)])
    _check(rule, "NPI: 1234567893", [(5, 15, MAX, MAX)])
    _check(rule, "Provider identifier 1245319599", [(20, 30, MAX, MAX)])
    _check(rule, "NPI 1234567893 and NPI 1245319599", [(4, 14, MAX, MAX), (23, 33, MAX, MAX)])
    for text in ("0234567893", "3234567893", "9234567893", "123456789", "12345678934", "1111111112", "1234567890"):
        _none(rule, text)


def test_us_npi_field_name():
    _field(_rule("US_NPI"), "1234567893", "npi")


# ---------------------------------------------------------------- US MBI


def test_us_mbi_upstream_cases():
    rule = _rule("US_MBI")
    _check(rule, "1EG4-TE5-MK73", [(0, 13, 0.5, 0.6)])
    _check(rule, "1EG4TE5MK73", [(0, 11, 0.3, 0.4)])
    _check(rule, "Patient 1EG4-TE5-MK73 and 2AG9-XC4-NN22", [(8, 21, 0.5, 0.6), (26, 39, 0.5, 0.6)])
    _check(rule, "9XX9-XX9-XX99", [(0, 13, 0.5, 0.6)])
    # "medicare" / "mbi" are context words: engine boosts by 0.35
    _check(rule, "Medicare ID: 3CD5-FG7-HJ89", [(13, 26, 0.5, MAX)])
    _check(rule, "The MBI is 4EF6GH8JK12 for this patient", [(11, 22, 0.3, MAX)])
    _single(rule, "Medicare ID: 3CD5-FG7-HJ89", "3CD5-FG7-HJ89", 0.85)
    _check(rule, "1eg4-te5-mk73", [(0, 13, 0.5, 0.6)])


def test_us_mbi_invalid_cases():
    rule = _rule("US_MBI")
    for text in (
        "1SG4-TE5-MK73", "1EG4-LE5-MK73", "1EG4-TE5-OK73", "1EG4-TE5-MI73", "1BG4-TE5-MK73", "1EG4-ZE5-MK73",
        "AEG4-TE5-MK73", "12G4-TE5-MK73", "1EG4TE5MK7", "1EG4TE5MK734",
    ):
        _none(rule, text)


def test_us_mbi_field_name():
    rule = _rule("US_MBI")
    _field(rule, "1EG4TE5MK73", "medicare_id")
    _field(rule, "1EG4TE5MK73", "mbi")


# ---------------------------------------------------------------- US health insurance member ID


def test_us_health_insurance_member_id_with_context():
    rule = _rule("US_HEALTH_INSURANCE_MEMBER_ID")
    for text, spans in (
        ("Member ID ABC123456789", ((10, 22),)),
        ("member number ZX-987654321 appears on the card", ((14, 26),)),
        ("Subscriber ID HPN12345A9 is active", ((14, 24),)),
        ("Insurance ID BCBSM1234567 was verified", ((13, 25),)),
        ("Insurance plan ID UHC-12345AB covers the visit", ((18, 29),)),
        ("Plan member ID AET987654 for this policy", ((15, 24),)),
        ("Policy ID CIGNA123456 belongs to the patient", ((10, 21),)),
        ("The insurance card lists subscriber number K123456789", ((43, 53),)),
    ):
        _check(rule, text, [(s, e, 0.45, 0.45) for s, e in spans])
    # case-insensitive, trailing punctuation outside the span
    _single(rule, "member id abc123456", "abc123456", 0.45)
    _single(rule, "MeMbEr Id AbC123456", "AbC123456", 0.45)
    _single(rule, "Subscriber ID zx-987654321.", "zx-987654321", 0.45)
    # multiple IDs
    _check(rule, "Member ID ABC123456 and subscriber ID ZX-987654321.", [(10, 19, 0.45, 0.45), (38, 50, 0.45, 0.45)])
    # 6 and 20 character boundaries
    _single(rule, "Member ID A12345", "A12345", 0.45)
    _single(rule, "Member ID ABCDE-12345678901234", "ABCDE-12345678901234", 0.45)


def test_us_health_insurance_member_id_without_context():
    rule = _rule("US_HEALTH_INSURANCE_MEMBER_ID")
    # pattern-only / unrelated context: the upstream recognizer's 0.4 threshold suppresses these
    for text in (
        "ABC123456789", "Please store HPN12345A9 in the table", "Order number ABC123456789 shipped yesterday",
        "Tracking number ZX-987654321 is in transit", "Case number HPN12345A9 is pending review",
        "Claim number BCBSM1234567 was denied", "covid19", "sha256", "iphone15pro", "rfc2119", "gpt4turbo",
        "ICD10CM123", "ABC-1234567",
    ):
        _below(rule, text, 0.4)
    # implausible: numeric-only, too short, too long
    for text in ("Member ID 1234567890", "Subscriber ID A123", "Member ID ABCDE-123456789012345"):
        _none(rule, text)
    # raw pattern score
    _check(rule, "ABC123456789", [(0, 12, 0.1, 0.1)])


def test_us_health_insurance_member_id_field_name():
    rule = _rule("US_HEALTH_INSURANCE_MEMBER_ID")
    _field(rule, "ABC123456789", "member_id")
    _field(rule, "ZX-987654321", "subscriber_number")


# ---------------------------------------------------------------- US healthcare admin identifiers

_ADMIN = (
    ("US_PRIOR_AUTHORIZATION_NUMBER", "Prior authorization PA-987654321 approved for treatment.", "PA-987654321"),
    ("US_CLAIM_NUMBER", "Processed healthcare claim CLM456789123 was paid.", "CLM456789123"),
    ("US_PRESCRIPTION_NUMBER", "Prescription number RX789456123 was filled by the pharmacy.", "RX789456123"),
    ("US_REFERRAL_NUMBER", "Infusion referral number INF2025001234 is ready for scheduling.", "INF2025001234"),
    ("US_PROVIDER_TAX_ID", "Provider Tax ID 12-3456789 belongs to the billing provider.", "12-3456789"),
)


def test_healthcare_admin_id_with_context_is_detected():
    for name, text, value in _ADMIN:
        _single(_rule(name), text, value, 0.7)


def test_healthcare_admin_id_matching_is_case_insensitive():
    for name, text, value in (
        ("US_PRIOR_AUTHORIZATION_NUMBER", "pRiOr AuThOrIzAtIoN pa-123456", "pa-123456"),
        ("US_CLAIM_NUMBER", "cLaIm clm123456", "clm123456"),
        ("US_PRESCRIPTION_NUMBER", "pReScRiPtIoN rX123456", "rX123456"),
        ("US_REFERRAL_NUMBER", "rEfErRaL inf123456", "inf123456"),
        ("US_PROVIDER_TAX_ID", "bIlLiNg PrOvIdEr eIn: 12-3456789", "12-3456789"),
    ):
        _single(_rule(name), text, value, 0.7)


def test_healthcare_admin_multiple_ids_are_all_detected():
    for name, text, values in (
        ("US_PRIOR_AUTHORIZATION_NUMBER", "Prior authorization PA-123456; prior authorization PA-654321.", ["PA-123456", "PA-654321"]),
        ("US_CLAIM_NUMBER", "Claim CLM123456 and claim CLM654321.", ["CLM123456", "CLM654321"]),
        ("US_PRESCRIPTION_NUMBER", "Prescription RX123456 and prescription RX654321.", ["RX123456", "RX654321"]),
        ("US_REFERRAL_NUMBER", "Referral REF123456 and referral INF654321.", ["REF123456", "INF654321"]),
        ("US_PROVIDER_TAX_ID", "Provider EIN 12-3456789 and provider TIN 20-1234567.", ["12-3456789", "20-1234567"]),
    ):
        results = _found(_rule(name), text)
        assert [r["value"] for r in results] == values, (name, text, results)
        assert all(abs(r["score"] - 0.7) < EPS for r in results), (name, results)


def test_healthcare_admin_id_ignores_trailing_punctuation():
    for name, text, value in (
        ("US_PRIOR_AUTHORIZATION_NUMBER", "Prior authorization PA-123456.", "PA-123456"),
        ("US_CLAIM_NUMBER", "Claim CLM123456,", "CLM123456"),
        ("US_PRESCRIPTION_NUMBER", "Prescription RX123456;", "RX123456"),
        ("US_REFERRAL_NUMBER", "Referral REF123456.", "REF123456"),
        ("US_PROVIDER_TAX_ID", "Provider EIN 12-3456789.", "12-3456789"),
    ):
        _single(_rule(name), text, value, 0.7)


def test_healthcare_admin_id_length_boundaries():
    for name, text, value in (
        ("US_PRIOR_AUTHORIZATION_NUMBER", "Prior authorization PA-123456", "PA-123456"),
        ("US_PRIOR_AUTHORIZATION_NUMBER", "Prior authorization PA-123456789012", "PA-123456789012"),
        ("US_CLAIM_NUMBER", "Claim CLM123456", "CLM123456"),
        ("US_CLAIM_NUMBER", "Claim CLM123456789012345", "CLM123456789012345"),
        ("US_PRESCRIPTION_NUMBER", "Prescription RX123456", "RX123456"),
        ("US_PRESCRIPTION_NUMBER", "Prescription RX123456789012", "RX123456789012"),
        ("US_REFERRAL_NUMBER", "Referral REF123456", "REF123456"),
        ("US_REFERRAL_NUMBER", "Referral INF123456789012", "INF123456789012"),
    ):
        _single(_rule(name), text, value, 0.7)
    for name, text in (
        ("US_PRIOR_AUTHORIZATION_NUMBER", "PA-12345"),
        ("US_PRIOR_AUTHORIZATION_NUMBER", "PA-1234567890123"),
        ("US_CLAIM_NUMBER", "CLM12345"),
        ("US_CLAIM_NUMBER", "CLM1234567890123456"),
        ("US_PRESCRIPTION_NUMBER", "RX12345"),
        ("US_PRESCRIPTION_NUMBER", "RX1234567890123"),
        ("US_REFERRAL_NUMBER", "REF12345"),
        ("US_REFERRAL_NUMBER", "INF1234567890123"),
        ("US_PROVIDER_TAX_ID", "12-123456"),
        ("US_PROVIDER_TAX_ID", "12-12345678"),
    ):
        _none(_rule(name), text)


def test_healthcare_admin_label_enables_bare_numeric_id():
    for name, text, value, score in (
        ("US_PRIOR_AUTHORIZATION_NUMBER", "Prior authorization number: 987654321 approved.", "987654321", 0.7),
        ("US_CLAIM_NUMBER", "Claim number: 1234567890123 was paid.", "1234567890123", 0.7),
        ("US_CLAIM_NUMBER", "Claim ID 123456789012345 was paid.", "123456789012345", 0.7),
        ("US_PRESCRIPTION_NUMBER", "Rx #1234567", "1234567", 0.6),
        ("US_PRESCRIPTION_NUMBER", "Prescription number: 7654321", "7654321", 0.7),
        ("US_PRESCRIPTION_NUMBER", "prescription 4455667", "4455667", 0.7),
        ("US_REFERRAL_NUMBER", "Infusion referral number: 2025001234", "2025001234", 0.7),
    ):
        _single(_rule(name), text, value, score)
    # a claim label does not support a prescription number match
    _none(_rule("US_PRESCRIPTION_NUMBER"), "The claim 1234567 was paid")


def test_provider_ein_with_provider_tax_label_is_detected():
    rule = _rule("US_PROVIDER_TAX_ID")
    for text, value in (
        ("Billing provider EIN: 12-3456789", "12-3456789"),
        ("Rendering provider TIN 20-1234567", "20-1234567"),
        ("Healthcare provider tax number: 67-1234567", "67-1234567"),
        ("Billing provider: 99-1234567", "99-1234567"),
        ("Billing provider EIN No. 20-1234567", "20-1234567"),
    ):
        _single(rule, text, value, 0.7)
    # The label pattern fires (0.35); the upstream recognizer's spaCy tokeniser also splits "TIN#" and
    # finds the context word "tin" (0.7), the engine's word tokeniser keeps "tin#" whole.
    _single(rule, "Provider TIN# 12-3456789", "12-3456789", 0.35, MAX)


def test_healthcare_admin_id_without_context_stays_below_threshold():
    # pattern-only and unrelated-context matches score 0.1 / 0.45 < the upstream recognizer's 0.6 threshold
    for name, text in (
        ("US_PRIOR_AUTHORIZATION_NUMBER", "PA-987654321"),
        ("US_CLAIM_NUMBER", "CLM456789123"),
        ("US_PRESCRIPTION_NUMBER", "RX789456123"),
        ("US_REFERRAL_NUMBER", "INF2025001234"),
        ("US_PROVIDER_TAX_ID", "12-3456789"),
        ("US_PRIOR_AUTHORIZATION_NUMBER", "Order number PA-987654321 is ready."),
        ("US_CLAIM_NUMBER", "Tracking number CLM456789123 is active."),
        ("US_PRESCRIPTION_NUMBER", "Case number RX789456123 is pending."),
        ("US_REFERRAL_NUMBER", "Claim number INF2025001234 was denied."),
        ("US_PROVIDER_TAX_ID", "Invoice number 12-3456789 was posted."),
        ("US_PROVIDER_TAX_ID", "Provider phone extension 12-3456789"),
        ("US_PROVIDER_TAX_ID", "Employee tax ID 12-3456789"),
    ):
        _below(_rule(name), text, 0.6)
    _none(_rule("US_PROVIDER_TAX_ID"), "provider 00-0000000 listed")


def test_provider_ein_invalid_irs_prefix_is_not_detected():
    rule = _rule("US_PROVIDER_TAX_ID")
    for prefix in ("00", "07", "08", "09", "17", "18", "19", "28", "29", "49", "69", "70", "78", "79", "89", "96", "97"):
        _none(rule, f"Provider Tax ID {prefix}-1234567")


def test_healthcare_admin_pattern_only_score():
    for name, text in (
        ("US_PRIOR_AUTHORIZATION_NUMBER", "PA-987654321"),
        ("US_CLAIM_NUMBER", "CLM456789123"),
        ("US_PRESCRIPTION_NUMBER", "RX789456123"),
        ("US_REFERRAL_NUMBER", "INF2025001234"),
        ("US_PROVIDER_TAX_ID", "12-3456789"),
    ):
        _check(_rule(name), text, [(0, len(text), 0.1, 0.1)])


def test_healthcare_admin_field_names():
    _field(_rule("US_PRIOR_AUTHORIZATION_NUMBER"), "PA-987654321", "prior_auth_number")
    _field(_rule("US_CLAIM_NUMBER"), "CLM456789123", "claim_number")
    _field(_rule("US_PRESCRIPTION_NUMBER"), "RX789456123", "rx_number")
    _field(_rule("US_REFERRAL_NUMBER"), "INF2025001234", "referral_number")
    _field(_rule("US_PROVIDER_TAX_ID"), "12-3456789", "provider_tin")
    _field(_rule("US_PROVIDER_TAX_ID"), "12-3456789", "ein")


# ---------------------------------------------------------------- CA SIN


def test_ca_sin_upstream_cases():
    rule = _rule("CA SIN")
    for text in ("130 692 544", "435 418 165", "948 584 792", "347-677-452", "731-530-150"):
        _check(rule, text, [(0, 11, 0.5, 0.81)])
    _check(rule, "130692544", [(0, 9, 0.0, 0.3)])
    _check(rule, "550090112", [(0, 9, 0.0, 0.3)])
    # "sin" / "nas" are context words: upstream expects >= 0.5, the engine boosts to 0.85
    _check(rule, "my SIN is 130-692-544", [(10, 21, 0.5, MAX)])
    _check(rule, "mon NAS: 258 933 688", [(9, 20, 0.5, MAX)])
    _single(rule, "my SIN is 130-692-544", "130-692-544", 0.85)


def test_ca_sin_invalid_cases():
    rule = _rule("CA SIN")
    for text in (
        "130 692 545", "130692545", "435-418-166",  # checksum failure
        "046 454 286", "812 345 678",  # reserved first digit
        "111 111 111", "999 999 999",  # all same digit
        "046-454 286", "046 454-286",  # mismatched delimiters
        "13069254", "1306925440",  # wrong length
    ):
        _none(rule, text)


def test_ca_sin_field_name():
    rule = _rule("CA SIN")
    _field(rule, "130692544", "sin_number")
    _field(rule, "130692544", "social_insurance_no")


# ---------------------------------------------------------------- CA postal code


def test_ca_postal_code_upstream_cases():
    rule = _rule("CA_POSTAL_CODE")
    for text in ("K1A 0A1", "k1a 0a1", "K1a 0A1", "K0A 0A1", "K1A 1W1", "K1A 1Z1"):
        _check(rule, text, [(0, 7, 0.3, 0.3)])
    _check(rule, "K1A0A1", [(0, 6, 0.1, 0.1)])
    # "postal code" is a context phrase: upstream expects 0.3, the engine boosts to 0.65
    _check(rule, "My postal code is K1A 0A1 thanks", [(18, 25, 0.3, MAX)])
    _single(rule, "My postal code is K1A 0A1 thanks", "K1A 0A1", 0.65)
    _check(rule, "From K1A 0A1 to M5V 3A8", [(5, 12, 0.3, 0.3), (16, 23, 0.3, 0.3)])


def test_ca_postal_code_invalid_cases():
    rule = _rule("CA_POSTAL_CODE")
    for text in (
        "D1A 1A1", "F1A 1A1", "I1A 1A1", "O1A 1A1", "Q1A 1A1", "U1A 1A1", "W1A 1A1", "Z1A 1A1",
        "K1D 1A1", "K1A 1D1", "1A1 1A1", "K1A\n0A1", "XK1A0A1Y", "", "K1A  0A1",
    ):
        _none(rule, text)


def test_ca_postal_code_field_name():
    rule = _rule("CA_POSTAL_CODE")
    _field(rule, "K1A0A1", "postal_code")
    _field(rule, "K1A0A1", "zip")
