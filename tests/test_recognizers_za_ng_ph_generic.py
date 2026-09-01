"""
Tests for src/engine/recognizers/za_ng_ph_generic.py - the ZA / NG / PH and generic
(IBAN, CRYPTO, IP, MAC, URL, UUID) rules ported from upstream-analyzer.

Every valid / invalid example and the expected scores come from the upstream recognizer's own
tests (tests/test_<name>_recognizer.py). the upstream recognizer's raw recognizer tests do not
apply context enhancement, while run_rule() does, so for inputs that contain a
context word the assertions use ">= expected" (the upstream recognizer's own upper bound is
1.0 in those cases); inputs without a context word are checked exactly.
"""
import datetime
import json
import os
import time

import src.engine.recognizers.za_ng_ph_generic as za_module
from src.engine.recognizers.za_ng_ph_generic import RULES
from src.engine.rules import run_rule

FIELD_HINT_SCORE = 0.85
EPS = 1e-6
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _rule(name):
    for rule in RULES:
        if rule.name == name:
            return rule
    raise KeyError(name)


def _run(name, text, field_name=None):
    return run_rule(_rule(name), text, field_name)


def _spans(findings):
    return [(f["start"], f["end"]) for f in findings]


def _check(name, cases):
    """
    cases: iterable of (text, expected) where expected is a list of
    (start, end, min_score) tuples (empty list -> nothing may be reported).
    Every finding must sit in [min_score, 1.0].
    """
    for text, expected in cases:
        findings = _run(name, text)
        exp_spans = [(s, e) for s, e, _ in expected]
        assert _spans(findings) == exp_spans, f"{name}: {text!r} -> {_spans(findings)}, expected {exp_spans}"
        for finding, (_, _, min_score) in zip(findings, expected):
            assert finding["score"] >= min_score - EPS, f"{name}: {text!r} score {finding['score']} < {min_score}"
            assert finding["score"] <= 1.0 + EPS
            assert finding["value"] == text[finding["start"]:finding["end"]]
            assert finding["detector"] == name


def _check_exact(name, text, expected):
    """expected: list of (start, end, exact_score)."""
    findings = _run(name, text)
    assert [(f["start"], f["end"], f["score"]) for f in findings] == expected, (
        f"{name}: {text!r} -> {[(f['start'], f['end'], f['score']) for f in findings]}, expected {expected}"
    )


def _check_field_hint(name, value, field_name):
    findings = _run(name, value, field_name=field_name)
    assert len(findings) == 1, f"{name}: {value!r} with field {field_name!r} -> {findings}"
    assert findings[0]["score"] >= FIELD_HINT_SCORE - EPS, f"{name}: field {field_name!r} score {findings[0]['score']}"
    assert findings[0]["value"] == value


# ---------------------------------------------------------------------------
# Rule metadata
# ---------------------------------------------------------------------------
EXPECTED_NAMES = [
    "ZA_ID_NUMBER", "ZA_PASSPORT", "ZA_DRIVER_LICENSE", "ZA_TRAFFIC_REGISTER_NUMBER",
    "ZA_INCOME_TAX_NUMBER", "ZA_VAT_NUMBER", "ZA_COMPANY_REGISTRATION", "ZA_LICENSE_PLATE",
    "ZA_MOBILE_NUMBER", "ZA_TELEPHONE_NUMBER",
    "NG_NIN", "NG_VEHICLE_REGISTRATION",
    "PH_UMID", "PH_TIN", "PH_PASSPORT", "PH_MOBILE_NUMBER",
    "IBAN", "CRYPTO", "PII.IPAddress", "MAC_ADDRESS", "URL", "UUID",
]
# upstream entities with no entry (yet) in fixtures/findings-mapping.json
UNMAPPED = {"ZA_MOBILE_NUMBER", "ZA_TELEPHONE_NUMBER", "PH_MOBILE_NUMBER"}


def test_rule_names_and_regions():
    names = [r.name for r in RULES]
    assert names == EXPECTED_NAMES
    assert len(set(names)) == len(names)
    for rule in RULES:
        if rule.name.startswith("ZA_"):
            assert rule.region == "ZA", rule.name
        elif rule.name.startswith("NG_"):
            assert rule.region == "NG", rule.name
        elif rule.name.startswith("PH_"):
            assert rule.region == "PH", rule.name
        else:
            assert rule.region is None, rule.name
        assert rule.description
        assert rule.field_hint
        assert rule.context
        assert rule.examples
    assert _rule("URL").enabled is False
    assert _rule("UUID").enabled is False
    assert all(r.enabled for r in RULES if r.name not in ("URL", "UUID"))


def test_category_and_severity_follow_findings_mapping():
    with open(os.path.join(_ROOT, "fixtures", "findings-mapping.json")) as fh:
        mapping = json.load(fh)
    if isinstance(mapping, list):  # historical shape: a list wrapping one dict
        mapping = mapping[0]
    for rule in RULES:
        if rule.name in UNMAPPED and rule.name not in mapping:
            assert rule.category == "PII" and rule.severity == "Medium", rule.name
            continue
        assert rule.name in mapping, f"{rule.name} is not a key of fixtures/findings-mapping.json"
        entry = mapping[rule.name]
        assert rule.category == entry["category"], rule.name
        expected_severity = "Low" if entry["final_risk_factor"] == "Lowest" else entry["final_risk_factor"]
        assert rule.severity == expected_severity, rule.name


def test_examples_are_detected():
    for rule in RULES:
        for example in rule.examples:
            findings = run_rule(rule, example)
            assert findings, f"{rule.name}: example {example!r} not detected"
            assert findings[0]["value"] == example, f"{rule.name}: example {example!r} -> {findings[0]['value']!r}"


def test_field_hint_lifts_score_for_every_rule():
    cases = {
        "ZA_ID_NUMBER": ("8001015009087", "customer_id_number"),
        "ZA_PASSPORT": ("A34855903", "passport_no"),
        "ZA_DRIVER_LICENSE": ("60390002CGBV", "driver_license"),
        "ZA_TRAFFIC_REGISTER_NUMBER": ("1234567890123", "traffic_register_number"),
        "ZA_INCOME_TAX_NUMBER": ("0123456789", "income_tax_ref"),
        "ZA_VAT_NUMBER": ("4020269678", "vat_number"),
        "ZA_COMPANY_REGISTRATION": ("2009/199240/23", "company_reg_no"),
        "ZA_LICENSE_PLATE": ("KD93GKGP", "license_plate"),
        "ZA_MOBILE_NUMBER": ("0825609352", "mobile_number"),
        "ZA_TELEPHONE_NUMBER": ("0112625500", "telephone"),
        "NG_NIN": ("12345678902", "nin"),
        "NG_VEHICLE_REGISTRATION": ("APP-456CV", "vehicle_registration"),
        "PH_UMID": ("001112345678", "umid"),
        "PH_TIN": ("000123456", "tin"),
        "PH_PASSPORT": ("EB1234567", "passport_number"),  # pragma: allowlist secret
        "PH_MOBILE_NUMBER": ("09171234567", "cell_phone"),
        "IBAN": ("DE89370400440532013000", "iban"),
        "CRYPTO": ("16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ", "wallet_address"),
        "PII.IPAddress": ("192.168.0.1", "client_ip"),
        "MAC_ADDRESS": ("00:1A:2B:3C:4D:5E", "mac_addr"),
        "URL": ("microsoft.com", "website_url"),
        "UUID": ("6ba7b810-9dad-31d1-80b4-00c04fd430c8", "guid"),
    }
    assert set(cases) == set(EXPECTED_NAMES)
    for name, (value, field_name) in cases.items():
        _check_field_hint(name, value, field_name)


# ---------------------------------------------------------------------------
# South Africa
# ---------------------------------------------------------------------------
def test_za_id_number_valid():
    _check(
        "ZA_ID_NUMBER", [
            ("8001015009087", [(0, 13, 1.0)]),
            ("8001015000086", [(0, 13, 1.0)]),
            ("My South African ID is 9202201234088.", [(23, 36, 1.0)]),
            ("RSA ID: 0002294321191", [(8, 21, 1.0)]),
            ("Permanent resident number 9912316789285 is on file.", [(26, 39, 1.0)]),
            ("Refugee ID number 0001015002288 is on file.", [(18, 31, 1.0)]),
        ],
    )
    for id_number in ["8001015009087", "8001015000086", "9202201234088", "0002294321191", "9912316789285", "0001015002288"]:
        _check_exact("ZA_ID_NUMBER", id_number, [(0, 13, 1.0)])


def test_za_id_number_invalid():
    _check(
        "ZA_ID_NUMBER", [
            ("8001015009086", []),  # Luhn failure
            ("9913326789285", []),  # month 13
            ("9902294321191", []),  # 1999-02-29 does not exist
            ("8001015000076", []),  # legacy race digit 7
            ("8001015009176", []),  # legacy race digit 7
            ("1234567890123", []),
            ("ID 80010150090", []),
            ("SA ID 80010150090870", []),
            ("AB8001015009087CD", []),
            ("80010150090", []),
            ("80010150090870", []),
            ("80010150090A7", []),
        ],
    )


def test_za_id_number_birth_date_pivot_and_future_dates():
    class FixedDate(datetime.date):
        @classmethod
        def today(cls):
            return datetime.date(2025, 6, 15)

    original = za_module.date
    za_module.date = FixedDate
    try:
        assert za_module._za_id_has_valid_birth_date("251231") is False  # 2025-12-31 is in the future
        assert za_module._za_id_has_valid_birth_date("250615") is True
        assert za_module._za_id_has_valid_birth_date("260101") is True  # 26 > 25 -> 1926
    finally:
        za_module.date = original
    assert za_module._za_id_has_valid_birth_date("050101") is True
    assert za_module._za_id_has_valid_birth_date("000229") is True
    assert za_module._za_id_has_valid_birth_date("990229") is False


def test_za_passport():
    _check(
        "ZA_PASSPORT", [
            ("A34855903", [(0, 9, 1.0)]),
            ("D12345678", [(0, 9, 1.0)]),  # pragma: allowlist secret
            ("M87654321", [(0, 9, 1.0)]),
            ("T11223344", [(0, 9, 1.0)]),
            ("Passport number A19299317 on file.", [(16, 25, 1.0)]),
            ("DHA travel document T99887766", [(20, 29, 1.0)]),
            ("B12345678", []),  # pragma: allowlist secret
            ("A1234567", []),
            ("A123456789", []),  # pragma: allowlist secret
            ("X12345678", []),
        ],
    )


def test_za_driver_license():
    _check(
        "ZA_DRIVER_LICENSE", [
            ("60390002CGBV", [(0, 12, 1.0)]),
            ("4024048D4P60", [(0, 12, 1.0)]),
            ("30040008X6Z6", [(0, 12, 1.0)]),
            ("4046048YPC9T", [(0, 12, 1.0)]),
            ("Driving licence number 114500482HFF on file.", [(23, 35, 1.0)]),
            ("eNaTIS licence 40260039Y068", [(15, 27, 1.0)]),
            ("8001015009087", []),  # no letter
            ("60390002", []),  # too short
            ("ABCDEFGHIJK", []),
            ("ABC1234567890", []),  # pragma: allowlist secret
        ],
    )


def test_za_traffic_register_number():
    _check(
        "ZA_TRAFFIC_REGISTER_NUMBER", [
            ("Traffic register number 1234567890123 is on file.", [(24, 37, 1.0)]),
            ("eNaTIS TRN 6001015000076 recorded.", [(11, 24, 1.0)]),
            ("1234567890123", [(0, 13, 1.0)]),
            ("6001015000076", [(0, 13, 1.0)]),
            ("8001015009087", []),  # a valid SA ID number is not a TRN
            ("123456789012", []),
            ("12345678901234", []),
        ],
    )


def test_za_income_tax_number():
    _check(
        "ZA_INCOME_TAX_NUMBER", [
            ("0123456789", [(0, 10, 1.0)]),
            ("1234567890", [(0, 10, 1.0)]),
            ("9123456789", [(0, 10, 1.0)]),
            ("SARS tax reference 2987654321 on file.", [(19, 29, 1.0)]),
            ("4020269678", []),  # VAT range
            ("5123456789", []),
            ("012345678", []),
            ("01234567890", []),
        ],
    )


def test_za_vat_number():
    _check(
        "ZA_VAT_NUMBER", [
            ("4020269678", [(0, 10, 1.0)]),
            ("4170229407", [(0, 10, 1.0)]),
            ("VAT number 4250281542 on invoice.", [(11, 21, 1.0)]),
            ("SARS vat registration 4100168758", [(22, 32, 1.0)]),
            ("3020269678", []),
            ("402026967", []),
            ("40202696789", []),
            ("1234567890", []),
        ],
    )


def test_za_company_registration():
    _check(
        "ZA_COMPANY_REGISTRATION", [
            ("2009/199240/23", [(0, 14, 1.0)]),
            ("2014/256030/07", [(0, 14, 1.0)]),
            ("CIPC registration 2020/804826/07", [(18, 32, 1.0)]),
            ("CK2001/123456", [(0, 13, 1.0)]),
            ("Close corporation CK1998/654321 registered.", [(18, 31, 1.0)]),
            ("K2010/654321", [(0, 12, 1.0)]),
            ("99/199240/23", []),
            ("2009/19924/23", []),
            ("2009/199240/234", []),
            ("AB2001/123456", []),
            ("hello world", []),
            ("2099/123456/07", []),  # year in the future fails validation
        ],
    )


def test_za_license_plate():
    _check(
        "ZA_LICENSE_PLATE", [
            ("KD93GKGP", [(0, 8, 1.0)]),
            ("PMG017GP", [(0, 8, 1.0)]),
            ("BJ47HRZN", [(0, 8, 1.0)]),
            ("DK 28 LF GP", [(0, 11, 1.0)]),
            ("CC 75 CX ZN", [(0, 11, 1.0)]),
            ("GET 103 WP", [(0, 10, 1.0)]),
            ("015 SBZ EC", [(0, 10, 1.0)]),
            ("Licence plate MT77GJGP registered.", [(14, 22, 1.0)]),
            ("YES", []),
            ("1234567890", []),
            ("1234GP", []),
            ("hello world", []),
        ],
    )
    # validate_result on already-compacted plates
    for plate in ["DK28LFGP", "CC75CXZN", "GET103WP", "015SBZEC"]:
        _check_exact("ZA_LICENSE_PLATE", plate, [(0, len(plate), 1.0)])


def test_za_mobile_number():
    _check(
        "ZA_MOBILE_NUMBER", [
            ("+27632118258", [(0, 12, 0.4)]),
            ("+27615889091", [(0, 12, 0.4)]),
            ("063 211 8258", [(0, 12, 0.4)]),
            ("082 560 9352", [(0, 12, 0.4)]),
            ("+27825609352", [(0, 12, 0.4)]),
            ("0825609352", [(0, 10, 0.4)]),
            ("My mobile number is +27632118258.", [(20, 32, 0.4)]),
            ("Cellphone: 082 560 9352", [(11, 23, 0.4)]),
            ("011 262 5500", []),  # landline
            ("021 447 1234", []),
            ("0800 123 456", []),  # toll-free
            ("+14155550132", []),  # US number
            ("1234567890", []),
            ("hello world", []),
        ],
    )
    _check_exact("ZA_MOBILE_NUMBER", "+27632118258", [(0, 12, 0.4)])
    _check_exact("ZA_MOBILE_NUMBER", "My mobile number is +27632118258.", [(20, 32, 0.75)])


def test_za_telephone_number():
    _check(
        "ZA_TELEPHONE_NUMBER", [
            ("011 262 5500", [(0, 12, 0.4)]),
            ("021 447 1234", [(0, 12, 0.4)]),
            ("010 222 0057", [(0, 12, 0.4)]),
            ("(011) 390-9872", [(0, 14, 0.4)]),
            ("0800 123 456", [(0, 12, 0.4)]),
            ("0860 123 456", [(0, 12, 0.4)]),
            ("H(011)3909872", [(1, 13, 0.4)]),
            ("Landline (011) 262-5500 on file.", [(9, 23, 0.4)]),
            ("H(011)3909872 B(011)4517333", [(1, 13, 0.4), (15, 27, 0.4)]),
            ("082 560 9352", []),  # mobile
            ("+27632118258", []),
            ("+14155550132", []),
            ("1234567890", []),
            ("hello world", []),
        ],
    )
    _check_exact("ZA_TELEPHONE_NUMBER", "011 262 5500", [(0, 12, 0.4)])
    _check_exact("ZA_TELEPHONE_NUMBER", "Landline (011) 262-5500 on file.", [(9, 23, 0.75)])


def test_za_phone_nsn_prefix_classifier():
    cases = [
        ("632118258", "mobile"), ("825609352", "mobile"), ("881234567", "mobile"), ("891234567", "mobile"),
        ("800123456", "telephone"), ("861234567", "telephone"), ("871234567", "telephone"),
        ("112625500", "telephone"), ("", None), ("012345678", None),
    ]
    for nsn, expected in cases:
        assert za_module._za_classify_by_nsn_prefix(nsn) == expected, nsn
    assert za_module._za_national_significant_number("+27 63 211 8258") == "632118258"
    assert za_module._za_national_significant_number("+27 (0) 82 560 9352") == "825609352"
    assert za_module._za_national_significant_number("0027632118258") == "632118258"
    assert za_module._za_national_significant_number("(011) 390-9872") == "113909872"
    assert za_module._za_national_significant_number("1234567890") == ""


# ---------------------------------------------------------------------------
# Nigeria
# ---------------------------------------------------------------------------
# 10 digits + Verhoeff check digit (same values the upstream recognizer's tests generate)
VALID_NIN_1 = "12345678902"
VALID_NIN_2 = "98765432102"
VALID_NIN_3 = "55512345672"
VALID_NIN_LEADING_ZERO = "01234567895"


def test_ng_nin_valid():
    _check(
        "NG_NIN", [
            (VALID_NIN_1, [(0, 11, 1.0)]),
            (f"NIN: {VALID_NIN_2}", [(5, 16, 1.0)]),
            (f"My NIN is {VALID_NIN_1} and yours is {VALID_NIN_3}", [(10, 21, 1.0), (35, 46, 1.0)]),
            (VALID_NIN_LEADING_ZERO, [(0, 11, 1.0)]),
        ],
    )
    assert VALID_NIN_LEADING_ZERO[0] == "0"


def test_ng_nin_invalid():
    broken = VALID_NIN_1[:-1] + str((int(VALID_NIN_1[-1]) + 1) % 10)
    _check(
        "NG_NIN", [
            ("12345678901", []),  # Verhoeff failure
            (broken, []),
            ("1234567890", []),  # 10 digits
            ("123456789012", []),  # 12 digits
            (f"99{VALID_NIN_1}88", []),  # embedded in a longer number
            ("1234567890a", []),  # pragma: allowlist secret
            ("00000000000", []),  # eleven zeros do not pass Verhoeff
        ],
    )


def test_ng_vehicle_registration():
    _check(
        "NG_VEHICLE_REGISTRATION", [
            ("APP-456CV", [(0, 9, 0.5)]),
            ("ABJ-001AA", [(0, 9, 0.5)]),
            ("KJA-999PZ", [(0, 9, 0.5)]),
            ("APP 456CV", [(0, 9, 0.5)]),
            ("APP456CV", [(0, 8, 0.5)]),
            ("The plate number is ABJ-123XY for this vehicle", [(20, 29, 0.5)]),
            ("Plates: APP-456CV and KJA-999PZ", [(8, 17, 0.5), (22, 31, 0.5)]),
            ("app-456cv", [(0, 9, 0.5)]),  # IGNORECASE
            ("AB-1234CD", []),
            ("123-456AB", []),
            ("AB-12CD", []),
            ("ABCD-123EF", []),
            ("", []),
        ],
    )
    _check_exact("NG_VEHICLE_REGISTRATION", "APP-456CV", [(0, 9, 0.5)])
    _check_exact("NG_VEHICLE_REGISTRATION", "Plates: APP-456CV and KJA-999PZ", [(8, 17, 0.5), (22, 31, 0.5)])
    _check_exact("NG_VEHICLE_REGISTRATION", "The plate number is ABJ-123XY for this vehicle", [(20, 29, 0.85)])


# ---------------------------------------------------------------------------
# Philippines
# ---------------------------------------------------------------------------
def test_ph_umid_valid():
    _check(
        "PH_UMID", [
            ("0111-1234567-8", [(0, 14, 0.5)]),
            ("0000-0000000-0", [(0, 14, 0.5)]),
            ("001112345678", [(0, 12, 0.3)]),
            ("My UMID number is 0111-1234567-8", [(18, 32, 0.5)]),
            ("UMID: 001112345678", [(6, 18, 0.3)]),
            ("CRN: 0111-1234567-8", [(5, 19, 0.5)]),
            ("philhealth 001112345678", [(11, 23, 0.3)]),
            ("gsis 0111-1234567-8", [(5, 19, 0.5)]),
            ("sss: 0111-1234567-8", [(5, 19, 0.5)]),
            ("pag-ibig 0111-1234567-8", [(9, 23, 0.5)]),
            ("umid card 0111-1234567-8", [(10, 24, 0.5)]),
            ("unified multi-purpose id 0111-1234567-8", [(25, 39, 0.5)]),
            ("unified multipurpose id 0111-1234567-8", [(24, 38, 0.5)]),
            ("common reference number 0111-1234567-8", [(24, 38, 0.5)]),
            ("1234-1234567-8", [(0, 14, 0.5)]),
            ("9999-9999999-9", [(0, 14, 0.5)]),
            ("123456789012", [(0, 12, 0.3)]),
            ("987654321098", [(0, 12, 0.3)]),
            ("First: 0111-1234567-8, Second: 001112345678", [(7, 21, 0.5), (31, 43, 0.3)]),
            ("0000-0000000-0 and 1111-1111111-1", [(0, 14, 0.5), (19, 33, 0.5)]),
        ],
    )
    _check_exact("PH_UMID", "0111-1234567-8", [(0, 14, 0.5)])
    _check_exact("PH_UMID", "001112345678", [(0, 12, 0.3)])
    _check_exact("PH_UMID", "UMID: 001112345678", [(6, 18, 0.65)])


def test_ph_umid_invalid():
    _check(
        "PH_UMID", [(text, []) for text in [
            "12345", "1234567890123", "hello world", "0111-123456-8", "0111-12345678-8", "011-1234567-8",
            "01111-1234567-8", "0111-1234567-89", "0111-1234567-", "-1234567-8", "0111 1234567 8", "0111.1234567.8",
        ]],
    )


def test_ph_tin():
    _check(
        "PH_TIN", [
            ("My TIN is 000-123-456-000", [(10, 25, 0.05)]),
            ("TIN: 000123456", [(5, 14, 0.01)]),
            ("BIR TIN: 000123456000", [(9, 21, 0.01)]),
            ("Tax ID: 000-123-456-001", [(8, 23, 0.05)]),
            ("TIN 000-123-456", [(4, 15, 0.05)]),
            ("TIN: 000-123-456-000", [(5, 20, 0.05)]),
            ("Please use 000-123-456-000 as your ID", [(11, 26, 0.05)]),
            ("Invalid TIN 000-123-457-000", []),  # wrong check digit
            ("Not a TIN 123456789", []),
            ("Invalid TIN 600-000-000", []),  # remainder 10 cannot be a check digit
        ],
    )
    _check_exact("PH_TIN", "Please use 000-123-456-000 as your ID", [(11, 26, 0.05)])
    _check_exact("PH_TIN", "000123456", [(0, 9, 0.01)])
    _check_exact("PH_TIN", "TIN: 000123456", [(5, 14, 0.4)])  # context floor


def test_ph_passport():
    _check(
        "PH_PASSPORT", [
            ("P1234567A", [(0, 9, 0.1)]),
            ("Z0000000Z", [(0, 9, 0.1)]),
            ("EB1234567", [(0, 9, 0.1)]),  # pragma: allowlist secret
            ("AA0000000", [(0, 9, 0.1)]),
            ("p1234567a", [(0, 9, 0.1)]),
            ("eb1234567", [(0, 9, 0.1)]),  # pragma: allowlist secret
            ("My Philippine passport number is P1234567A.", [(33, 42, 0.1)]),
            ("Passport: EB1234567 is valid.", [(10, 19, 0.1)]),
            ("P1234567A and EB1234567", [(0, 9, 0.1), (14, 23, 0.1)]),
            ("P123456A", []),
            ("P12345678A", []),
            ("E1234567", []),
            ("EB12345678", []),  # pragma: allowlist secret
            ("EB 1234567", []),
            ("P1234567 A", []),
            ("1234567A", []),
            ("", []),
        ],
    )
    _check_exact("PH_PASSPORT", "P1234567A", [(0, 9, 0.1)])
    _check_exact("PH_PASSPORT", "Passport: EB1234567 is valid.", [(10, 19, 0.45)])


def test_ph_mobile_number():
    prefixes = [
        "0917", "0918", "0919", "0920", "0921", "0927", "0928", "0929", "0930", "0939", "0947", "0949",
        "0956", "0961", "0966", "0967", "0977", "0994", "0995", "0996", "0997", "0998", "0999",
    ]
    cases = [
        ("+63 917 123 4567", [(0, 16, 0.4)]),
        ("+639171234567", [(0, 13, 0.4)]),
        ("+63-917-123-4567", [(0, 16, 0.4)]),
        ("+63 (917) 123 4567", [(0, 18, 0.4)]),
        ("09171234567", [(0, 11, 0.3)]),
        ("0917 123 4567", [(0, 13, 0.3)]),
        ("0917-123-4567", [(0, 13, 0.3)]),
        ("0 (917) 123 4567", [(0, 16, 0.3)]),
        ("9171234567", []),  # bare local format is not detected
        ("917 123 4567", []),
        ("917-123-4567", []),
        ("My mobile number is +639171234567.", [(20, 33, 0.4)]),
        ("Telepono: 09171234567", [(10, 21, 0.3)]),
        ("Numero: 9171234567", []),
        ("First: +639171234567, Second: 09181234567", [(7, 20, 0.4), (30, 41, 0.3)]),
        ("12345678901", []),
        ("0917123456", []),  # too short
        ("091712345678", []),  # too long
        ("15091712345678", []),  # embedded
        ("hello world", []),
    ] + [(prefix + "1234567", [(0, 11, 0.3)]) for prefix in prefixes]
    _check("PH_MOBILE_NUMBER", cases)
    _check_exact("PH_MOBILE_NUMBER", "09171234567", [(0, 11, 0.4)])


# ---------------------------------------------------------------------------
# IBAN
# ---------------------------------------------------------------------------
IBAN_CASES = [
    # (text, expected spans); every reported IBAN validates -> score 1.0
    ("AL47212110090000000235698741", [(0, 28)]),
    ("AL47 2121 1009 0000 0002 3569 8741", [(0, 34)]),
    ("AL47 212A 1009 0000 0002 3569 8741", []),
    ("AL47 212A 1009 0000 0002 3569 874", []),
    ("AL47 2121 1009 0000 0002 3569 8740", []),
    ("AD1200012030200359100100", [(0, 24)]),
    ("AD12 0001 2030 2003 5910 0100", [(0, 29)]),
    ("AD12000A2030200359100100", []),
    ("AD12000A203020035910010", []),
    ("AD12 0001 2030 2003 5910 0101", []),
    ("AT611904300234573201", [(0, 20)]),
    ("AT61 1904 3002 3457 3201", [(0, 24)]),
    ("AT61 1904 A002 3457 3201", []),
    ("AT61 1904 3002 3457 320", []),
    ("AT61 1904 3002 3457 3202", []),
    ("AZ21NABZ00000000137010001944", [(0, 28)]),
    ("AZ21 NABZ 0000 0000 1370 1000 1944", [(0, 34)]),
    ("AZ21NABZ000000001370100019", []),
    ("AZ21NABZ0000000013701000194", []),
    ("AZ21NABZ00000000137010001945", []),
    ("BH67BMAG00001299123456", [(0, 22)]),
    ("BH67 BMAG 0000 1299 1234 56", [(0, 27)]),
    ("BH67BMA100001299123456", []),
    ("BH67BMAG0000129912345", []),
    ("BH67BMAG00001299123457", []),
    ("BY13NBRB3600900000002Z00AB00", [(0, 28)]),
    ("BY13 NBRB 3600 9000 0000 2Z00 AB00", [(0, 34)]),
    ("BY13NBRBA600900000002Z00AB00", []),
    ("BY13 NBRB 3600 9000 0000 2Z00 AB0", []),
    ("BY13NBRB3600900000002Z00AB01", []),
    ("BE68539007547034", [(0, 16)]),  # pragma: allowlist secret
    ("BE71 0961 2345 6769", [(0, 19)]),
    ("BE71 A961 2345 6769", []),
    ("BE6853900754703", []),  # pragma: allowlist secret
    ("BE71 0961 2345 6760", []),
    ("BA391290079401028494", [(0, 20)]),  # pragma: allowlist secret
    ("BA39 1290 0794 0102 8494", [(0, 24)]),
    ("BA39 A290 0794 0102 8494", []),
    ("BA39129007940102849", []),  # pragma: allowlist secret
    ("BA39 1290 0794 0102 8495", []),
    ("BR9700360305000010009795493P1", [(0, 29)]),
    ("BR97 0036 0305 0000 1000 9795 493P 1", [(0, 36)]),
    ("BR97 0036 A305 0000 1000 9795 493P 1", []),
    ("BR9700360305000010009795493P", []),
    ("BR97 0036 0305 0000 1000 9795 493P 2", []),
    ("BG80BNBG96611020345678", [(0, 22)]),
    ("BG80 BNBG 9661 1020 3456 78", [(0, 27)]),
    ("BG80 BNBG 9661 A020 3456 78", []),
    ("BG80BNBG9661102034567", []),
    ("BG80 BNBG 9661 1020 3456 79", []),
    ("CR05015202001026284066", [(0, 22)]),
    ("CR05 0152 0200 1026 2840 66", [(0, 27)]),
    ("CR05 0152 0200 1026 2840 6A", []),
    ("CR05 0152 0200 1026 2840 6", []),
    ("CR05 0152 0200 1026 2840 67", []),
    ("HR1210010051863000160", [(0, 21)]),
    ("HR12 1001 0051 8630 0016 0", [(0, 26)]),
    ("HR12 001 0051 8630 0016 A", []),
    ("HR121001005186300016", []),
    ("HR12 1001 0051 8630 0016 1", []),
    ("CY17002001280000001200527600", [(0, 28)]),
    ("CY17 0020 0128 0000 0012 0052 7600", [(0, 34)]),
    ("CY17 0020 A128 0000 0012 0052 7600", []),
    ("CY17 0020 0128 0000 0012 0052 760", []),
    ("CY17 0020 0128 0000 0012 0052 7601", []),
    ("CZ6508000000192000145399", [(0, 24)]),
    ("CZ65 0800 0000 1920 0014 5399", [(0, 29)]),
    ("CZ65 0800 A000 1920 0014 5399", []),
    ("CZ65 0800 0000 1920 0014 539", []),
    ("CZ65 0800 0000 1920 0014 5390", []),
    ("DK5000400440116243", [(0, 18)]),
    ("DK50 0040 0440 1162 43", [(0, 22)]),
    ("DK50 0040 A440 1162 43", []),
    ("DK50 0040 0440 1162 4", []),
    ("DK50 0040 0440 1162 44", []),
    ("DO28BAGR00000001212453611324", [(0, 28)]),
    ("DO28 BAGR 0000 0001 2124 5361 1324", [(0, 34)]),
    ("DO28 BAGR A000 0001 2124 5361 1324", []),
    ("DO28 BAGR 0000 0001 2124 5361 132", []),
    ("DO28 BAGR 0000 0001 2124 5361 1325", []),
    ("TL380080012345678910157", [(0, 23)]),
    ("TL38 0080 0123 4567 8910 157", [(0, 28)]),
    ("TL38 A080 0123 4567 8910 157", []),
    ("TL38 0080 0123 4567 8910 158", []),
    ("EE382200221020145685", [(0, 20)]),
    ("EE38 2200 2210 2014 5685", [(0, 24)]),
    ("EE38 A200 2210 2014 5685", []),
    ("EE38 2200 2210  014 5686", []),
    ("FO6264600001631634", [(0, 18)]),
    ("FO62 6460 0001 6316 34", [(0, 22)]),
    ("FO62 A460 0001 6316 34", []),
    ("FO62 6460 0001 6316 35", []),
    ("FI2112345600000785", [(0, 18)]),
    ("FI21 1234 5600 0007 85", [(0, 22)]),
    ("FI21 A234 5600 0007 85", []),
    ("FI21 1234 5600 0007 86", []),
    ("FR1420041010050500013M02606", [(0, 27)]),
    ("FR14 2004 1010 0505 0001 3M02 606", [(0, 33)]),
    ("FR14 A004 1010 0505 0001 3M02 606", []),
    ("FR14 2004 1010 0505 0001 3M02 607", []),
    ("GE29NB0000000101904917", [(0, 22)]),
    ("GE29 NB00 0000 0101 9049 17", [(0, 27)]),
    ("GE29 NBA0 0000 0101 9049 17", []),
    ("GE29 NB00 0000 0101 9049 18", []),
    ("DE89370400440532013000", [(0, 22)]),
    ("DE89 3704 0044 0532 0130 00", [(0, 27)]),
    ("DE89 A704 0044 0532 0130 00", []),
    ("DE89 3704 0044 0532 0130 01", []),
    ("GI75NWBK000000007099453", [(0, 23)]),
    ("GI75 NWBK 0000 0000 7099 453", [(0, 28)]),
    ("GI75 aWBK 0000 0000 7099 453", []),
    ("GI75 NWBK 0000 0000 7099 454", []),
    ("GR1601101250000000012300695", [(0, 27)]),
    ("GR16 0110 1250 0000 0001 2300 695", [(0, 33)]),
    ("GR16 A110 1250 0000 0001 2300 695", []),
    ("GR16 0110 1250 0000 0001 2300 696", []),
    ("GL8964710001000206", [(0, 18)]),
    ("GL89 6471 0001 0002 06", [(0, 22)]),
    ("GL89 A471 0001 0002 06", []),
    ("GL89 6471 0001 0002 07", []),
    ("GT82TRAJ01020000001210029690", [(0, 28)]),
    ("GT82 TRAJ 0102 0000 0012 1002 9690", [(0, 34)]),
    ("G T82 TRAJ 0102 0000 0012 1002 9690", []),
    ("GT82 TRAJ 0102 0000 0012 1002 9691", []),
    ("HU42117730161111101800000000", [(0, 28)]),
    ("HU42 1177 3016 1111 1018 0000 0000", [(0, 34)]),
    ("HU42 A177 3016 1111 1018 0000 0000", []),
    ("HU42 1177 3016 1111 1018 0000 0001", []),
    ("IS140159260076545510730339", [(0, 26)]),
    ("IS14 0159 2600 7654 5510 7303 39", [(0, 32)]),
    ("IS14 A159 2600 7654 5510 7303 39", []),
    ("IS14 0159 2600 7654 5510 7303 30", []),
    ("IE29AIBK93115212345678", [(0, 22)]),
    ("IE29 AIBK 9311 5212 3456 78", [(0, 27)]),
    ("IE29 AIBK A311 5212 3456 78", []),
    ("IE29 AIBK 9311 5212 3456 79", []),
    ("IL620108000000099999999", [(0, 23)]),
    ("IL62 0108 0000 0009 9999 999", [(0, 28)]),
    ("IL62 A108 0000 0009 9999 999", []),
    ("IL62 0108 0000 0009 9999 990", []),
    ("IT60X0542811101000000123456", [(0, 27)]),
    ("IT60 X054 2811 1010 0000 0123 456", [(0, 33)]),
    ("IT60 XW54 2811 1010 0000 0123 456", []),
    ("IT60 X054 2811 1010 0000 0123 457", []),
    ("JO94CBJO0010000000000131000302", [(0, 30)]),
    ("JO94 CBJO 0010 0000 0000 0131 0003 02", [(0, 37)]),
    ("JO94 CBJO A010 0000 0000 0131 0003 02", []),
    ("JO94 CBJO 0010 0000 0000 0131 0003 03", []),
    ("KZ86125KZT5004100100", [(0, 20)]),
    ("KZ86 125K ZT50 0410 0100", [(0, 24)]),
    ("KZ86 A25K ZT50 0410 0100", []),
    ("KZ86 125K ZT50 0410 0101", []),
    ("XK051212012345678906", [(0, 20)]),
    ("XK05 1212 0123 4567 8906", [(0, 24)]),
    ("XK05 A212 0123 4567 8906", []),
    ("XK05 1212 0123 4567 8907", []),
    ("KW81CBKU0000000000001234560101", [(0, 30)]),
    ("KW81 CBKU 0000 0000 0000 1234 5601 01", [(0, 37)]),
    ("KW81 aBKU 0000 0000 0000 1234 5601 01", []),
    ("KW81 CBKU 0000 0000 0000 1234 5601 02", []),
    ("LV80BANK0000435195001", [(0, 21)]),
    ("LV80 BANK 0000 4351 9500 1", [(0, 26)]),
    ("LV80 bANK 0000 4351 9500 1", []),
    ("LV80 BANK 0000 4351 9500 2", []),
    ("LB62099900000001001901229114", [(0, 28)]),
    ("LB62 0999 0000 0001 0019 0122 9114", [(0, 34)]),
    ("LB62 A999 0000 0001 0019 0122 9114", []),
    ("LB62 0999 0000 0001 0019 0122 9115", []),
    ("LI21088100002324013AA", [(0, 21)]),
    ("LI21 0881 0000 2324 013A A", [(0, 26)]),
    ("LI21 A881 0000 2324 013A A", []),
    ("LI21 0881 0000 2324 013A B", []),
    ("LT121000011101001000", [(0, 20)]),
    ("LT12 1000 0111 0100 1000", [(0, 24)]),
    ("LT12 A000 0111 0100 1000", []),
    ("LT12 1000 0111 0100 1001", []),
    ("LU280019400644750000", [(0, 20)]),
    ("LU28 0019 4006 4475 0000", [(0, 24)]),
    ("LU28 A019 4006 4475 0000", []),
    ("LU28 0019 4006 4475 0001", []),
    ("MT84MALT011000012345MTLCAST001S", [(0, 31)]),
    ("MT84 MALT 0110 0001 2345 MTLC AST0 01S", [(0, 38)]),
    ("MT84 MALT A110 0001 2345 MTLC AST0 01S", []),
    ("MT84 MALT 0110 0001 2345 MTLC AST0 01T", []),
    ("MR1300020001010000123456753", [(0, 27)]),
    ("MR13 0002 0001 0100 0012 3456 753", [(0, 33)]),
    ("MR13 A002 0001 0100 0012 3456 753", []),
    ("MR13 0002 0001 0100 0012 3456 754", []),
    ("MU17BOMM0101101030300200000MUR", [(0, 30)]),
    ("MU17 BOMM 0101 1010 3030 0200 000M UR", [(0, 37)]),
    ("MU17 BOMM A101 1010 3030 0200 000M UR", []),
    ("MU17 BOMM 0101 1010 3030 0200 000M US", []),
    ("MD24AG000225100013104168", [(0, 24)]),
    ("MD24 AG00 0225 1000 1310 4168", [(0, 29)]),
    ("MD24 AG00 0225 1000 1310 416", []),
    ("MD24 AG00 0225 1000 1310 4169", []),
    ("MC5811222000010123456789030", [(0, 27)]),
    ("MC58 1122 2000 0101 2345 6789 030", [(0, 33)]),
    ("MC58 A122 2000 0101 2345 6789 030", []),
    ("MC58 1122 2000 0101 2345 6789 031", []),
    ("ME25505000012345678951", [(0, 22)]),
    ("ME25 5050 0001 2345 6789 51", [(0, 27)]),
    ("ME25 A050 0001 2345 6789 51", []),
    ("ME25 5050 0001 2345 6789 52", []),
    ("NL91ABNA0417164300", [(0, 18)]),
    ("NL91 ABNA 0417 1643 00", [(0, 22)]),
    ("NL91 1BNA 0417 1643 00", []),
    ("NL91 ABNA 0417 1643 01", []),
    ("MK07250120000058984", [(0, 19)]),
    ("MK07 2501 2000 0058 984", [(0, 23)]),
    ("MK07 A501 2000 0058 984", []),
    ("MK07 2501 2000 0058 985", []),
    ("NO9386011117947", [(0, 15)]),
    ("NO93 8601 1117 947", [(0, 18)]),
    ("NO93 A601 1117 947", []),
    ("NO93 8601 1117 948", []),
    ("PK36SCBL0000001123456702", [(0, 24)]),
    ("PK36 SCBL 0000 0011 2345 6702", [(0, 29)]),
    ("PK36 SCBL A000 0011 2345 6702", []),
    ("PK36 SCBL 0000 0011 2345 6703", []),
    ("PS92PALS000000000400123456702", [(0, 29)]),
    ("PS92 PALS 0000 0000 0400 1234 5670 2", [(0, 36)]),
    ("PS92 PALS A000 0000 0400 1234 5670 2", []),
    ("PS92 PALS 0000 0000 0400 1234 5670 3", []),
    ("PL61109010140000071219812874", [(0, 28)]),
    ("PL61 1090 1014 0000 0712 1981 2874", [(0, 34)]),
    ("PL61 A090 1014 0000 0712 1981 2874", []),
    ("PL61 1090 1014 0000 0712 1981 2875", []),
    ("PT50000201231234567890154", [(0, 25)]),
    ("PT50 0002 0123 1234 5678 9015 4", [(0, 31)]),
    ("PT50 A002 0123 1234 5678 9015 4", []),
    ("PT50 0002 0123 1234 5678 9015 5", []),
    ("QA58DOHB00001234567890ABCDEFG", [(0, 29)]),
    ("QA58 DOHB 0000 1234 5678 90AB CDEF G", [(0, 36)]),
    ("QA58 0OHB 0000 1234 5678 90AB CDEF G", []),
    ("QA58 DOHB 0000 1234 5678 90AB CDEF H", []),
    ("RO49AAAA1B31007593840000", [(0, 24)]),
    ("RO49 AAAA 1B31 0075 9384 0000", [(0, 29)]),
    ("RO49 0AAA 1B31 0075 9384 0000", []),
    ("RO49 AAAA 1B31 0075 9384 0001", []),
    ("SM86U0322509800000000270100", [(0, 27)]),
    ("SM86 U032 2509 8000 0000 0270 100", [(0, 33)]),
    ("SM86 0032 2509 8000 0000 0270 100", []),
    ("SM86 U032 2509 8000 0000 0270 101", []),
    ("SA0380000000608010167519", [(0, 24)]),
    ("SA03 8000 0000 6080 1016 7519", [(0, 29)]),
    ("SA03 A000 0000 6080 1016 7519", []),
    ("SA03 8000 0000 6080 1016 7510", []),
    ("RS35260005601001611379", [(0, 22)]),
    ("RS35 2600 0560 1001 6113 79", [(0, 27)]),
    ("RS35 A600 0560 1001 6113 79", []),
    ("RS35 2600 0560 1001 6113 70", []),
    ("SK3112000000198742637541", [(0, 24)]),
    ("SK31 1200 0000 1987 4263 7541", [(0, 29)]),
    ("SK31 A200 0000 1987 4263 7541", []),
    ("SK31 1200 0000 1987 4263 7542", []),
    ("SI56263300012039086", [(0, 19)]),
    ("SI56 2633 0001 2039 086", [(0, 23)]),
    ("SI56 A633 0001 2039 086", []),
    ("SI56 2633 0001 2039 087", []),
    ("ES9121000418450200051332", [(0, 24)]),
    ("ES91 2100 0418 4502 0005 1332", [(0, 29)]),
    ("ES91 A100 0418 4502 0005 1332", []),
    ("ES91 2100 0418 4502 0005 1333", []),
    ("SE4550000000058398257466", [(0, 24)]),
    ("SE45 5000 0000 0583 9825 7466", [(0, 29)]),
    ("SE45 A000 0000 0583 9825 7466", []),
    ("SE45 5000 0000 0583 9825 7467", []),
    ("CH9300762011623852957", [(0, 21)]),
    ("CH93 0076 2011 6238 5295 7", [(0, 26)]),
    ("CH93 A076 2011 6238 5295 7", []),
    ("CH93 0076 2011 6238 5295 8", []),
    ("TN5910006035183598478831", [(0, 24)]),
    ("TN59 1000 6035 1835 9847 8831", [(0, 29)]),
    ("TN59 A000 6035 1835 9847 8831", []),
    ("CH93 0076 2011 6238 5295 9", []),
    ("TR330006100519786457841326", [(0, 26)]),
    ("TR33 0006 1005 1978 6457 8413 26", [(0, 32)]),
    ("TR33 A006 1005 1978 6457 8413 26", []),
    ("TR33 0006 1005 1978 6457 8413 27", []),
    ("AE070331234567890123456", [(0, 23)]),  # pragma: allowlist secret
    ("AE07 0331 2345 6789 0123 456", [(0, 28)]),
    ("AE07 A331 2345 6789 0123 456", []),
    ("AE07 0331 2345 6789 0123 457", []),
    ("GB29NWBK60161331926819", [(0, 22)]),
    ("GB29 NWBK 6016 1331 9268 19", [(0, 27)]),
    ("GB29 1WBK 6016 1331 9268 19", []),
    ("GB29 NWBK 6016 1331 9268 10", []),
    ("VA59001123000012345678", [(0, 22)]),
    ("VA59 0011 2300 0012 3456 78", [(0, 27)]),
    ("VA59 A011 2300 0012 3456 78", []),
    ("VA59 0011 2300 0012 3456 79", []),
    ("VG96VPVG0000012345678901", [(0, 24)]),
    ("VG96 VPVG 0000 0123 4567 8901", [(0, 29)]),
    ("VG96 VPVG A000 0123 4567 8901", []),
    ("VG96 VPVG 0000 0123 4567 8902", []),
    ("EG380019000500000000263180002", [(0, 29)]),
    ("EG38 0019 0005 0000 0000 2631 8000 2", [(0, 36)]),
    ("EG38A019000500000000263180002", []),
    ("EG380019000500000000263180003", []),
    ("UA213223130000026007233566001", [(0, 29)]),
    ("UA21 3223 1300 0002 6007 2335 6600 1", [(0, 36)]),
    ("UA21A223130000026007233566001", []),
    ("UA213223130000026007233566002", []),
    ("IQ98NBIQ850123456789012", [(0, 23)]),
    ("IQ98 NBIQ 8501 2345 6789 012", [(0, 28)]),
    ("IQ98NBIQ850123456789013", []),
    ("LC55HEMM000100010012001200023015", [(0, 32)]),
    ("LC55 HEMM 0001 0001 0012 0012 0002 3015", [(0, 39)]),
    ("LC55HEMM000100010012001200023016", []),
    ("SC18SSCB11010000000000001497USD", [(0, 31)]),
    ("SC18 SSCB 1101 0000 0000 0000 1497 USD", [(0, 38)]),
    ("SC18SSCB11010000000000001497USE", []),
    ("LY83002048000020100120361", [(0, 25)]),
    ("LY83 0020 4800 0020 1001 2036 1", [(0, 31)]),
    ("LY83002048000020100120362", []),
    ("this is an iban VG96 VPVG 0000 0123 4567 8901 in a sentence", [(16, 45)]),
    ("this is an iban VG96 VPVG 0000 0123 4567 8901 X in a sentence", [(16, 45)]),
    ("AB150120690000003111141", []),
    ("IL15 0120 6900 0000", []),
    ("IL15 0120 6900 0000 3111 0120 6900 0000 3111 141", []),
    ("IL150120690000003111141", []),
    ("AM47212110090000000235698740", []),
    ("list of ibans: AL47212110090000000235698741, AL47212110090000000235698741", [(15, 43), (45, 73)]),
    ("Dash as iban separator: AL47-2121-1009-0000-0002-3569-8741", [(24, 58)]),
    ("Slash as iban separator: AL47/2121/1009/0000/0002/3569/8741", []),
    ("Dalla's Pizza | 3843 Peartree Road, Bamblee, SD 20241 440-600-5124", []),
    ("AL47212110090000000235698741 ALL CAPS", [(0, 28)]),
    ("CY17 0020 0128 0000 0012 0052 7601 failed", []),
]


def test_iban_upstream_cases():
    countries = set()
    for text, spans in IBAN_CASES:
        findings = _run("IBAN", text)
        assert _spans(findings) == spans, f"IBAN: {text!r} -> {_spans(findings)}, expected {spans}"
        for finding in findings:
            assert finding["score"] == 1.0, f"IBAN: {text!r} score {finding['score']}"
            countries.add(finding["value"][:2])
    assert len(countries) >= 70, countries


def test_iban_group_fallback_keeps_longest_valid_candidate():
    # Trailing junk is not swallowed (upstream retries with shorter capture groups)
    findings = _run("IBAN", "this is an iban VG96 VPVG 0000 0123 4567 8901 X in a sentence")
    assert [(f["start"], f["end"], f["value"]) for f in findings] == [(16, 45, "VG96 VPVG 0000 0123 4567 8901")]
    findings = _run("IBAN", "AL47212110090000000235698741 ALL CAPS")
    assert [(f["value"], f["score"], f["pattern"]) for f in findings] == [
        ("AL47212110090000000235698741", 1.0, "IBAN Generic (group 2 fallback)"),
    ]
    # A full valid match is reported once, under the primary pattern
    findings = _run("IBAN", "BR97 0036 0305 0000 1000 9795 493P 1")
    assert [(f["value"], f["pattern"]) for f in findings] == [
        ("BR97 0036 0305 0000 1000 9795 493P 1", "IBAN Generic"),
    ]


def test_iban_is_case_sensitive_and_flags():
    import re
    patterns = _rule("IBAN").patterns
    for pattern in patterns:
        assert pattern.flags == re.DOTALL | re.MULTILINE
    # the upstream recognizer's regex, verbatim; the fallbacks are built from the same sub-expressions
    assert patterns[0].regex == (
        r"(?<![A-Z0-9])([A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]{4}){2,6})"
        r"((?:[ -]?[A-Z0-9]{4})?)((?:[ -]?[A-Z0-9]{1,3})?)(?![A-Z0-9])"
    )
    assert patterns[0].regex == (
        za_module._IBAN_LOOKBEHIND + za_module._IBAN_GROUP_1 + za_module._IBAN_GROUP_2
        + za_module._IBAN_GROUP_3 + za_module._IBAN_LOOKAHEAD
    )
    assert _run("IBAN", "de89370400440532013000") == []
    assert _run("IBAN", "gb29 nwbk 6016 1331 9268 19") == []


def test_iban_validator_semantics():
    assert za_module._validate_iban("DE89 3704 0044 0532 0130 00") is True
    assert za_module._validate_iban("DE89-3704-0044-0532-0130-00") is True
    assert za_module._validate_iban("DE89370400440532013001") is False  # bad checksum  # pragma: allowlist secret
    assert za_module._validate_iban("AB150120690000003111141") is False  # unknown country
    # checksum ok but the country format only matches when upper-cased -> None
    assert za_module._validate_iban("GB29NWBK60161331926819") is True
    assert za_module._validate_iban("GB29nwbk60161331926819") is None
    assert za_module._validate_iban("CH93 0076 2011 6238 5295 7") is True


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------
def test_crypto():
    _check(
        "CRYPTO", [
            ("16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ", [(0, 34, 1.0)]),  # P2PKH
            ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", [(0, 34, 1.0)]),  # P2SH  # pragma: allowlist secret
            ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", [(0, 42, 1.0)]),  # Bech32  # pragma: allowlist secret
            ("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297", [(0, 62, 1.0)]),  # Bech32m  # pragma: allowlist secret
            ("16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", [(0, 34, 1.0), (35, 69, 1.0)]),
            ("my wallet address is: 16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ", [(22, 56, 1.0)]),
            ("16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ2", []),  # checksum failure
            ("my wallet address is: 16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ2", []),
            ("", []),
            ("8f953371d3e85eddb89b05ed6b9e680791055315c73e1025ab5dba7bb2aee189", []),  # pragma: allowlist secret
        ],
    )
    _check_exact("CRYPTO", "16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ", [(0, 34, 1.0)])
    assert za_module._validate_crypto("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") is True  # pragma: allowlist secret
    assert za_module._validate_crypto("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr") is False  # pragma: allowlist secret
    assert za_module._validate_crypto("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i") is True
    assert za_module._validate_crypto("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62j") is False
    assert za_module._validate_crypto("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62I") is False  # 'I' is not base58


# ---------------------------------------------------------------------------
# IP address
# ---------------------------------------------------------------------------
IP_CASES = [
    # IPv4 / IPv6 basics
    ("microsoft.com 192.168.0.1", [(14, 25, 0.6)]),
    ("my ip: 192.168.0", []),
    ("microsoft.com 684D:1111:222:3333:4444:5555:6:77", [(14, 47, 0.6)]),
    ("my ip: 684D:1111:222:3333:4444:5555:6:77", [(7, 40, 0.6)]),
    ("684D:1111:222:3333:4444:5555:77", []),
    ("2345:0425:2CA1:0000:0000:0567:5673:23b5", [(0, 39, 0.6)]),
    ("2345:0425:2CA1::0567:5673:23b5", [(0, 30, 0.6)]),
    ("2400:c401::5054:ff:fe1b:b031", [(0, 28, 0.6)]),
    ("Use local ipv6 ::", [(15, 17, 0.1)]),
    ("my ip: ::1", [(7, 10, 0.6)]),
    ("connecting from ::1", [(16, 19, 0.6)]),
    ("src=:: dst=::1", [(4, 6, 0.1), (11, 14, 0.6)]),
    # IPv6 compression
    ("fe80::1", [(0, 7, 0.6)]),
    ("2001:db8::8a2e:370:7334", [(0, 23, 0.6)]),
    ("2001:db8:85a3::8a2e:370", [(0, 23, 0.6)]),
    ("2001:db8::1", [(0, 11, 0.6)]),
    ("fe80::1%eth0", [(0, 12, 0.6)]),
    ("A099::09C0:876A:130B", [(0, 20, 0.6)]),
    # IPv6 in context
    ("Server IP: 2001:db8::1", [(11, 22, 0.6)]),
    ("Connect to [2001:db8::1]:8080", [(12, 23, 0.6)]),
    ("my ip is 2400:c401::5054:ff:fe1b:b031", [(9, 37, 0.6)]),
    ("Gateway: fe80::1 on interface", [(9, 16, 0.6)]),
    ("Visit http://[2001:db8::1]/path", [(14, 25, 0.6)]),
    ("SSH to user@2001:db8::1", [(12, 23, 0.6)]),
    # IPv4-mapped / IPv4-compatible
    ("::ffff:192.0.2.1", [(0, 16, 0.6)]),
    ("::ffff:10.0.0.1", [(0, 15, 0.6)]),
    ("::ffff:172.16.0.1", [(0, 17, 0.6)]),
    ("::ffff:127.0.0.1", [(0, 16, 0.6)]),
    ("::ffff:255.255.255.255", [(0, 22, 0.6)]),
    ("::ffff:0.0.0.0", [(0, 14, 0.6)]),
    ("::ffff:0:192.168.1.1", [(0, 20, 0.6)]),
    ("::ffff:0000:10.0.0.1", [(0, 20, 0.6)]),
    ("Mapped: ::ffff:192.168.1.1", [(8, 26, 0.6)]),
    ("Connect to ::ffff:10.0.0.1 now", [(11, 26, 0.6)]),
    ("[::ffff:192.168.1.1]:80", [(1, 19, 0.6)]),
    ("::192.168.1.1", [(0, 13, 0.6)]),
    ("::10.0.0.1", [(0, 10, 0.6)]),
    ("::ffff:256.0.0.1", []),
    ("::ffff:192.168.1", []),
    # IPv4-embedded
    ("2001:db8::192.168.1.1", [(0, 21, 0.6)]),
    ("2001:db8:1::192.0.2.1", [(0, 21, 0.6)]),
    ("64:ff9b::192.0.2.1", [(0, 18, 0.6)]),
    ("2001:db8:85a3::8a2e:192.168.0.1", [(0, 31, 0.6)]),
    ("0:0:0:0:0:FFFF:129.144.52.38", [(0, 28, 0.6)]),
    ("2001:db8:0:0:0:0:192.168.1.1", [(0, 28, 0.6)]),
    ("NAT64: 64:ff9b::198.51.100.1", [(7, 28, 0.6)]),
    ("Tunnel to 2001:db8::10.0.0.1", [(10, 28, 0.6)]),
    ("2001:db8::256.1.1.1", []),
    # multiple
    ("IPv4: 192.168.1.1, IPv6: 2001:db8::1", [(6, 17, 0.6), (25, 36, 0.6)]),
    ("Primary: 10.0.0.1, Secondary: 172.16.0.1", [(9, 17, 0.6), (30, 40, 0.6)]),
    ("IPs: 192.168.1.1, 10.0.0.1, 2001:db8::1", [(5, 16, 0.6), (18, 26, 0.6), (28, 39, 0.6)]),
    # not IPs
    ("MAC address aa:bb:cc:dd:ee:ff", []),
    ("Time 12:34:56", []),
    ("Ratio 1:2:3:4", []),
    ("CSS color #ff00aa", []),
    ("Version 1.2.3", []),
    ("Port 80:443", []),
    ("abc:def:ghi", []),
    ("123:abc", []),
    ("file:///path/to/file", []),
    ("std::cout", []),
    ("MyClass::toString", []),
    (":::", []),
    # boundaries
    ("IP192.168.1.1text", []),
    ("text192.168.1.1", []),
    ("(192.168.1.1)", [(1, 12, 0.6)]),
    ("'2001:db8::1'", [(1, 12, 0.6)]),
    ("IP: 192.168.1.1.", [(4, 15, 0.6)]),
    ("192.168.1.1,", [(0, 11, 0.6)]),
    ("[2001:db8::1]", [(1, 12, 0.6)]),
    ("Server IP: 2400:c401::5054:ff:fe1b:b031.", [(11, 39, 0.6)]),
    ("2001:db8::1.", [(0, 11, 0.6)]),
    ("fe80::1text", []),
    ("text2001:db8::1", []),
    ("192.168.1.1.1", [(0, 11, 0.6)]),
    # rejected by validation / structure
    ("256.256.256.256", []),
    ("192.168.1.256", []),
    ("gggg:hhhh::1234", []),
    ("192.168.1", []),
    ("300.168.1.1", []),
    ("12345:db8::1", []),
    ("2001::db8::1", []),
    ("2001::25de::cade", []),
    ("192.168.2.1@eth0", [(0, 11, 0.6)]),
    ("text::ffff:192.0.2.1", [(11, 20, 0.6)]),
    ("foo2001:db8::10.0.0.1", [(13, 21, 0.6)]),
    # special variants
    ("localhost 127.0.0.1", [(10, 19, 0.6)]),
    ("Broadcast 255.255.255.255", [(10, 25, 0.6)]),
    ("Private 10.0.0.0", [(8, 16, 0.6)]),
    ("Link-local 169.254.1.1", [(11, 22, 0.6)]),
    ("Subnet 172.16.0.0", [(7, 17, 0.6)]),
    ("Default 0.0.0.0", [(8, 15, 0.6)]),
    ("Unspecified ::", [(12, 14, 0.1)]),
    ("Loopback ::1", [(9, 12, 0.6)]),
    ("Multicast ff02::1", [(10, 17, 0.6)]),
    # CIDR
    ("192.168.1.0/24", [(0, 14, 0.6)]),
    ("10.0.0.0/8", [(0, 10, 0.6)]),
    ("0.0.0.0/0", [(0, 9, 0.6)]),
    ("192.168.1.1/32", [(0, 14, 0.6)]),
    ("2001:db8::/32", [(0, 13, 0.6)]),
    ("fe80::/10", [(0, 9, 0.6)]),
    ("::1/128", [(0, 7, 0.6)]),
    ("fe80::1%eth0/64", [(0, 15, 0.6)]),
    ("2001:db8::%eth0/128", [(0, 19, 0.6)]),
    ("::/0", [(0, 4, 0.1)]),
    ("::/128", [(0, 6, 0.1)]),
    ("::ffff:192.168.1.0/96", [(0, 21, 0.6)]),
    ("64:ff9b::192.0.2.0/96", [(0, 21, 0.6)]),
    ("Subnet: 192.168.1.0/24", [(8, 22, 0.6)]),
    ("Prefix: 2001:db8::/32", [(8, 21, 0.6)]),
    ("Route is 10.0.0.0/8.", [(9, 19, 0.6)]),
    ("Use 2001:db8::/32.", [(4, 17, 0.6)]),
    ("10.0.0.0/123", [(0, 8, 0.6)]),  # invalid prefix length: base IP still reported
    ("2001:db8::/9999", [(0, 10, 0.6)]),
]


def test_ip_address_upstream_cases():
    _check("PII.IPAddress", IP_CASES)


def test_ip_address_scores():
    _check_exact("PII.IPAddress", "192.168.1.0/24", [(0, 14, 0.6)])
    _check_exact("PII.IPAddress", "Unspecified ::", [(12, 14, 0.1)])
    _check_exact("PII.IPAddress", "src=:: dst=::1", [(4, 6, 0.1), (11, 14, 0.6)])
    _check_exact("PII.IPAddress", "my ip: 192.168.0.1", [(7, 18, 0.95)])  # "ip" context word
    assert _rule("PII.IPAddress").name == "PII.IPAddress"


# ---------------------------------------------------------------------------
# MAC address
# ---------------------------------------------------------------------------
def test_mac_address():
    _check(
        "MAC_ADDRESS", [
            ("My MAC address is 00:1A:2B:3C:4D:5E", [(18, 35, 0.6)]),
            ("Device MAC: AA:BB:CC:DD:EE:FF", [(12, 29, 0.6)]),
            ("MAC: 01:23:45:67:89:AB", [(5, 22, 0.6)]),
            ("Lowercase MAC: 0a:23:f5:67:89:ac", [(15, 32, 0.6)]),
            ("My MAC address is 00-1A-2B-3C-4D-5E", [(18, 35, 0.6)]),
            ("Hardware address: AA-BB-CC-DD-EE-FF", [(18, 35, 0.6)]),
            ("MAC: 01-23-45-67-89-AB", [(5, 22, 0.6)]),
            ("Lowercase MAC: 01-b3-4a-67-d9-cf", [(15, 32, 0.6)]),
            ("Mixedcase MAC: 0d-B3-4a-6A-d9-cF", [(15, 32, 0.6)]),
            ("Cisco MAC: 0012.3456.789A", [(11, 25, 0.6)]),
            ("My MAC is 0012.3456.789a", [(10, 24, 0.6)]),
            ("Physical address is aabb.ccdd.eeff", [(20, 34, 0.6)]),
            ("MACs: 00:11:22:33:44:55 and AA-BB-CC-DD-EE-FF", [(6, 23, 0.6), (28, 45, 0.6)]),
            ("ethernet mac address: 00:1A:2B:3C:4D:5E", [(22, 39, 0.6)]),
            ("The hardware address is AA-BB-CC-DD-EE-FF", [(24, 41, 0.6)]),
            ("Not a MAC: 00:1A:2B:3C:4D", []),
            ("Invalid: ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", []),
            ("Broadcast: FF:FF:FF:FF:FF:FF", []),
            ("Invalid: 00:00:00:00:00:00", []),
            ("Mixed test cases for hyphens and colons: 10:2F:33-AC-29-C3", []),
        ],
    )
    _check_exact("MAC_ADDRESS", "00:1A:2B:3C:4D:5E", [(0, 17, 0.6)])
    _check_exact("MAC_ADDRESS", "MACs: 00:11:22:33:44:55 and AA-BB-CC-DD-EE-FF", [(6, 23, 0.6), (28, 45, 0.6)])
    _check_exact("MAC_ADDRESS", "ethernet mac address: 00:1A:2B:3C:4D:5E", [(22, 39, 0.95)])


# ---------------------------------------------------------------------------
# URL
# ---------------------------------------------------------------------------
def test_url():
    _check(
        "URL", [
            ("https://www.microsoft.com/", [(0, 26, 0.6)]),
            ("http://www.microsoft.com/", [(0, 25, 0.6)]),
            ("http://www.microsoft.com", [(0, 24, 0.6)]),
            ("http://microsoft.com", [(0, 20, 0.6)]),
            ("http://microsoft.site", [(0, 21, 0.6)]),
            ("http://microsoft.webcam", [(0, 23, 0.6)]),
            ("http://microsoft.vlaanderen", [(0, 27, 0.6)]),
            ("https://webhook.site/a8eedfd6-9d8a-44e0-b0fc-cc7d517db5dc?q=1&b=2", [(0, 65, 0.6)]),
            ("https://www.microsoft.com/store/abc/", [(0, 36, 0.6)]),
            ("microsoft.com", [(0, 13, 0.5)]),
            ("my domains: microsoft.com google.co.il", [(12, 25, 0.5), (26, 38, 0.5)]),
            ('"https://upstream.dataprivacystack.org/"', [(0, 40, 0.6)]),
            ("'https://upstream.dataprivacystack.org/'", [(0, 40, 0.6)]),
            ("www.microsoft", []),
            ("http://microsoft", []),
            ("'www.microsoft'", []),
        ],
    )
    _check_exact("URL", "https://www.microsoft.com/", [(0, 26, 0.6)])
    _check_exact("URL", "microsoft.com", [(0, 13, 0.5)])
    _check_exact("URL", "my domains: microsoft.com google.co.il", [(12, 25, 0.5), (26, 38, 0.5)])
    _check_exact("URL", '"https://upstream.dataprivacystack.org/"', [(0, 40, 0.6)])


def test_url_long_hostname_and_no_catastrophic_backtracking():
    host = "a." * 60 + "example"
    text = f"http://{host}.com/path"
    _check_exact("URL", text, [(0, len(text), 0.6)])
    start = time.time()
    assert _run("URL", "." * 3000) == []
    assert time.time() - start < 15


# ---------------------------------------------------------------------------
# UUID
# ---------------------------------------------------------------------------
def test_uuid():
    _check(
        "UUID", [
            ("Request ID: 550e8400-e29b-41d4-a716-446655440000", [(12, 48, 0.5)]),  # v4
            ("User UUID: 6fa459ea-ee8a-3ca4-894e-db77e160355e", [(11, 47, 0.5)]),
            ("Trace: f47ac10b-58cc-1372-8567-0e02b2c3d479", [(7, 43, 0.5)]),  # v1
            ("DCE UUID: 550e8400-e29b-21d4-a716-446655440000", [(10, 46, 0.5)]),  # v2
            ("6ba7b810-9dad-31d1-80b4-00c04fd430c8", [(0, 36, 0.5)]),  # v3
            ("Object id 74738ff5-5367-5958-9aee-98fffdcd1876 created", [(10, 46, 0.5)]),  # v5
            ("Sortable ID: 1ec9414c-232a-6b00-b3c8-9e6bdeced846", [(13, 49, 0.5)]),  # v6
            ("New record: 018f4f8e-9a3b-7c3d-8e9f-1a2b3c4d5e6f", [(12, 48, 0.5)]),  # v7
            ("Custom UUID: 550e8400-e29b-81d4-a716-446655440000", [(13, 49, 0.5)]),  # v8
            ("GUID: 550E8400-E29B-41D4-A716-446655440000", [(6, 42, 0.5)]),
            ("unique identifier: 550e8400-e29b-41d4-a716-446655440000", [(19, 55, 0.5)]),
            ("The guid is 6fa459ea-ee8a-3ca4-894e-db77e160355e", [(12, 48, 0.5)]),
            (
                "IDs: 550e8400-e29b-41d4-a716-446655440000 and f47ac10b-58cc-1372-8567-0e02b2c3d479",
                [(5, 41, 0.5), (46, 82, 0.5)],
            ),
            ("Not a UUID: 550e8400-e29b-41d4-a716", []),
            ("Invalid: zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", []),
            ("Nil UUID: 00000000-0000-0000-0000-000000000000", []),
            ("Bad version: 550e8400-e29b-01d4-a716-446655440000", []),
            ("Bad version: 550e8400-e29b-91d4-a716-446655440000", []),
            ("Bad variant: 550e8400-e29b-41d4-1716-446655440000", []),
        ],
    )
    _check_exact("UUID", "6ba7b810-9dad-31d1-80b4-00c04fd430c8", [(0, 36, 0.5)])
    _check_exact("UUID", "Request ID: 550e8400-e29b-41d4-a716-446655440000", [(12, 48, 0.5)])
    _check_exact("UUID", "The guid is 6fa459ea-ee8a-3ca4-894e-db77e160355e", [(12, 48, 0.85)])


# ---------------------------------------------------------------------------
# Phone rules without python-phonenumbers (the upstream recognizer's NSN-prefix fallback)
# ---------------------------------------------------------------------------
def test_phone_rules_fall_back_to_nsn_prefix_classifier_without_phonenumbers():
    saved = za_module.phonenumbers
    za_module.phonenumbers = None
    try:
        _check(
            "ZA_MOBILE_NUMBER", [
                ("+27632118258", [(0, 12, 0.4)]),
                ("082 560 9352", [(0, 12, 0.4)]),
                ("Cellphone: 082 560 9352", [(11, 23, 0.4)]),
                ("011 262 5500", []),
                ("0800 123 456", []),
                ("+14155550132", []),
                ("1234567890", []),
            ],
        )
        _check(
            "ZA_TELEPHONE_NUMBER", [
                ("(011) 390-9872", [(0, 14, 0.4)]),
                ("0860 123 456", [(0, 12, 0.4)]),
                ("H(011)3909872 B(011)4517333", [(1, 13, 0.4), (15, 27, 0.4)]),
                ("082 560 9352", []),
                ("+27632118258", []),
            ],
        )
        _check(
            "PH_MOBILE_NUMBER", [
                ("+63 917 123 4567", [(0, 16, 0.4)]),
                ("09171234567", [(0, 11, 0.4)]),
                ("9171234567", []),
                ("15091712345678", []),
            ],
        )
    finally:
        za_module.phonenumbers = saved
