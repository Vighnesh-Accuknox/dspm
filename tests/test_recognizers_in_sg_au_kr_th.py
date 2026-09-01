"""
Tests for src/engine/recognizers/in_sg_au_kr_th.py (India, Singapore, Australia,
South Korea, Thailand).

Expected positions and scores come from upstream-analyzer's
tests/test_<recognizer>_recognizer.py. Those tests call recognizer.analyze()
directly, i.e. without the upstream recognizer's context enhancer, whereas run_rule applies the
context boost natively. So when a context word sits next to the match, the
expected score is lifted the way the enhancer would lift it (+context_boost,
floored at min_score_with_context, capped at 1.0). Range expectations (lo, hi)
are checked as score >= lo, and <= hi when no context word fired.
"""
import json
import os
import re

from src.engine.recognizers.in_sg_au_kr_th import (
    IN_VEHICLE_RTO_DISTRICTS,
    RULES,
    _sanitize_in_gstin,
    _validate_in_aadhaar,
    _validate_in_gstin,
    _validate_in_gstin_pan_format,
    _validate_sg_uen,
    _validate_th_tnin,
)
from src.engine.rules import FIELD_HINT_SCORE, run_rule
from src.engine.validators import verhoeff_check

_EPS = 0.00001
_BY_NAME = {r.name: r for r in RULES}
_MAPPING_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures", "findings-mapping.json")


def _rule(name):
    return _BY_NAME[name]


def _boosted(rule, score):
    return min(1.0, max(score + rule.context_boost, rule.min_score_with_context))


def _check(rule, text, expected):
    """
    expected: list of (start, end, score); score is an exact float (the upstream recognizer's
    assert_result) or a (lo, hi) range (assert_result_within_score_range).
    An empty list means the text must yield no finding.
    """
    findings = run_rule(rule, text)
    assert len(findings) == len(expected), f"{rule.name} {text!r}: {findings}"
    for finding, (start, end, score) in zip(findings, expected):
        assert finding["detector"] == rule.name
        assert (finding["start"], finding["end"]) == (start, end), f"{rule.name} {text!r}: {finding}"
        assert finding["value"] == text[start:end]
        got = finding["score"]
        boosted = finding["context_word"] is not None
        if isinstance(score, tuple):
            lo, hi = score
            assert got >= lo - _EPS, f"{rule.name} {text!r}: score {got} < {lo}"
            if not boosted:
                assert got <= hi + _EPS, f"{rule.name} {text!r}: score {got} > {hi}"
        else:
            want = _boosted(rule, score) if boosted else score
            assert abs(got - want) < _EPS, f"{rule.name} {text!r}: score {got} != {want}"


def _run_table(name, table):
    rule = _rule(name)
    for text, expected in table:
        _check(rule, text, expected)


def _assert_field_hint(name, value, field_name):
    rule = _rule(name)
    assert re.search(rule.field_hint, field_name.lower()), f"{name}: field_hint does not match {field_name!r}"
    findings = run_rule(rule, value, field_name=field_name)
    assert len(findings) == 1, f"{name}: {value!r} with field {field_name!r} -> {findings}"
    assert findings[0]["score"] >= FIELD_HINT_SCORE - _EPS, (name, field_name, findings)


# --------------------------------------------------------------- generic ----

def test_rule_set_shape():
    assert len(RULES) == 18
    assert len(_BY_NAME) == 18, "duplicate rule names"
    for rule in RULES:
        assert rule.region in {"IN", "SG", "AU", "KR", "TH"}, rule.name
        assert rule.name.upper().startswith(rule.region), rule.name
        assert rule.patterns and rule.context and rule.field_hint and rule.description, rule.name
        assert rule.severity in {"Critical", "High", "Medium", "Low"}, rule.name
        assert rule.enabled
        assert rule.examples


def test_rule_names_and_severity_match_findings_mapping():
    with open(_MAPPING_PATH, encoding="utf-8") as fh:
        mapping = json.load(fh)[0]
    for rule in RULES:
        assert rule.name in mapping, f"{rule.name} missing from findings-mapping.json"
        entry = mapping[rule.name]
        assert rule.category == entry["category"], rule.name
        severity = "Low" if entry["final_risk_factor"] == "Lowest" else entry["final_risk_factor"]
        assert rule.severity == severity, rule.name


def test_examples_are_detected_as_whole_values():
    for rule in RULES:
        for example in rule.examples:
            findings = run_rule(rule, example)
            assert len(findings) == 1, (rule.name, example, findings)
            assert (findings[0]["start"], findings[0]["end"]) == (0, len(example)), (rule.name, example)
            if rule.validator is not None and rule.validator(example) is True:
                assert findings[0]["score"] == 1.0, (rule.name, example)


def test_field_hints_require_token_boundaries():
    # '_' is a word character for \b, so hints use lookarounds instead; make sure
    # short tokens still do not fire inside unrelated words.
    for name, field_name in [
        ("IN PAN", "company"),
        ("IN PAN", "japan_office"),
        ("IN PAN", "expand"),
        ("IN GST", "gstatic_url"),
        ("AU_ABN", "abnormal_flag"),
        ("AU_ACN", "vacancy"),
        ("SG_NRIC_FIN", "finance_total"),
        ("SG_UEN", "fluent"),
        ("KR_BRN", "brnch"),
        ("KR_FRN", "frnt_desk"),
        ("KR_RRN", "irrn"),
        ("TH_TNIN", "tnint"),
        ("IN Aadhaar", "guide"),
        ("IN VOTER ID", "epicenter"),
    ]:
        assert re.search(_rule(name).field_hint, field_name) is None, (name, field_name)


# ----------------------------------------------------------------- India ----

def test_in_aadhaar():
    _run_table(
        "IN Aadhaar", [
            ("123456789012", []),
            ("312345678909", [(0, 12, 1.0)]),
            ("399876543211", [(0, 12, 1.0)]),
            ("1234 5678 9012", []),
            ("3123 4567 8909", [(0, 14, 1.0)]),
            ("3998 7654 3211", [(0, 14, 1.0)]),
            ("1234-5678-9012", []),
            ("3123-4567-8909", [(0, 14, 1.0)]),
            ("3998-7654-3211", [(0, 14, 1.0)]),
            ("1234:5678:9012", []),
            ("3123:4567:8909", [(0, 14, 1.0)]),
            ("3998:7654:3211", [(0, 14, 1.0)]),
            ("My Aadhaar number is 400123456787 with a lot of text beyond it", [(21, 33, 1.0)]),
        ],
    )


def test_in_aadhaar_validator():
    # the upstream recognizer's verhoeff_test_set
    assert _validate_in_aadhaar("312345678909") is True
    assert _validate_in_aadhaar("400123456787") is True
    assert _validate_in_aadhaar("123456789012") is False
    # separators are stripped before validation
    assert _validate_in_aadhaar("3123-4567-8909") is True
    assert _validate_in_aadhaar("3123:4567:8909") is True
    # first digit must be >= 2 even when the Verhoeff digit is right
    assert verhoeff_check("123456789012") is False
    # a Verhoeff-valid palindrome is still rejected
    assert verhoeff_check("200009900002") is True
    assert _validate_in_aadhaar("200009900002") is False


def test_in_aadhaar_field_hint():
    _assert_field_hint("IN Aadhaar", "312345678909", "aadhaar_number")
    _assert_field_hint("IN Aadhaar", "3123 4567 8909", "customer_uid")
    _assert_field_hint("IN Aadhaar", "312345678909", "uidai_no")


def test_in_gstin():
    _run_table(
        "IN GST", [
            ("27ABCDE1234F1Z5", [(0, 15, 1.0)]),
            ("07PQRST6789K1Z2", [(0, 15, 1.0)]),
            ("01ABCDE1234F1Z5", [(0, 15, 1.0)]),
            ("37ABCDE1234F1Z5", [(0, 15, 1.0)]),
            ("My GSTIN number is 27ABCDE1234F1Z5 for business registration", [(19, 34, 1.0)]),
            ("GST registration: 07PQRST6789K1Z2", [(18, 33, 1.0)]),
            ("Tax identification GSTIN: 01ABCDE1234F1Z5", [(26, 41, 1.0)]),
            ("GSTINs: 27ABCDE1234F1Z5 and 07PQRST6789K1Z2", [(8, 23, 1.0), (28, 43, 1.0)]),
            # invalid
            ("27ABCDE1234F1Z", []),  # too short
            ("27ABCDE1234F1Z55", []),  # too long
            ("00ABCDE1234F1Z5", []),  # invalid state code
            ("38ABCDE1234F1Z5", []),  # invalid state code
            ("27ABCDE1234F1Y5", []),  # missing 'Z' at position 14
            ("", []),
            ("123456789012345", []),  # all digits
            ("ABCDEFGHIJKLMNO", []),  # all letters
        ],
    )


def test_in_gstin_validator():
    for gstin, expected in [
        ("27ABCDE1234F1Z5", True),
        ("07PQRST6789K1Z2", True),
        ("01ABCDE1234F1Z5", True),
        ("37ABCDE1234F1Z5", True),
        ("27abcde1234f1z5", True),  # matched case-insensitively, validated upper-cased
        ("27ABCDE1234F1Z", False),
        ("27ABCDE1234F1Z55", False),
        ("00ABCDE1234F1Z5", False),
        ("38ABCDE1234F1Z5", False),
        ("27ABCDE1234F1Y5", False),
    ]:
        assert _validate_in_gstin(gstin) is expected, gstin


def test_in_gstin_pan_format():
    for pan, expected in [
        ("ABCDE1234F", True),
        ("PQRST6789K", True),
        ("ABCD1234F", False),  # too short
        ("ABCDE12345F", False),  # too long
        ("12345ABCDE", False),  # numbers first
        ("ABCDE1234", False),  # missing last letter
    ]:
        assert _validate_in_gstin_pan_format(pan) is expected, pan


def test_in_gstin_sanitize():
    for text, expected in [
        ("27ABCDE1234F1Z5", "27ABCDE1234F1Z5"),
        ("27-ABCDE-1234-F1-Z5", "27ABCDE1234F1Z5"),
        ("27 ABCDE 1234 F1 Z5", "27ABCDE1234F1Z5"),
        ("The company GSTIN is 27ABCDE1234F1Z5 for tax purposes", "27ABCDE1234F1Z5"),
    ]:
        assert _sanitize_in_gstin(text) == expected, text


def test_in_gstin_field_hint():
    _assert_field_hint("IN GST", "27ABCDE1234F1Z5", "gstin")
    _assert_field_hint("IN GST", "07PQRST6789K1Z2", "company_gst_no")


def test_in_pan():
    _run_table(
        "IN PAN", [
            ("AAASA1111R", [(0, 10, 0.1)]),
            ("ABCPD1234Z", [(0, 10, 0.5)]),
            ("ABCND1234Z", [(0, 10, 0.1)]),
            ("A1111DFSFS", [(0, 10, 0.01)]),
            ("ABCD1234", []),
            ("My PAN number is ABBPM4567S with a lot of text beyond it", [(17, 27, 0.5)]),
        ],
    )


def test_in_pan_field_hint():
    _assert_field_hint("IN PAN", "ABCND1234Z", "customer_pan")
    _assert_field_hint("IN PAN", "A1111DFSFS", "pan_number")
    _assert_field_hint("IN PAN", "AAASA1111R", "PanCard")


def test_in_passport():
    _run_table(
        "IN PASSPORT", [
            ("A3456781", [(0, 8, 0.1)]),
            ("B3097651", [(0, 8, 0.1)]),
            ("C3590543", [(0, 8, 0.1)]),
            ("my passport number is T3569075", [(22, 30, 0.1)]),
            ("passport number: J6932157", [(17, 25, 0.1)]),
            # invalid
            ("b0097650", []),
            ("my passport number is T356907", []),
        ],
    )


def test_in_passport_field_hint():
    _assert_field_hint("IN PASSPORT", "A3456781", "passport_no")
    _assert_field_hint("IN PASSPORT", "C3590543", "indianPassportNumber")


def test_in_vehicle_registration():
    _run_table(
        "IN_VEHICLE_REGISTRATION", [
            ("KA53ME3456", [(0, 10, 1.0)]),
            ("KA99ME3456", [(0, 10, 0.5)]),  # unknown district: pattern score kept
            ("MN2412", [(0, 6, 0.01)]),
            ("MCX1243", [(0, 7, 0.2)]),
            ("I15432", [(0, 6, 0.01)]),
            ("DL3CJI0001", [(0, 10, 1.0)]),
            # zero-padded district codes for states stored single-digit (DL, GJ)
            ("DL01CA1234", [(0, 10, 1.0)]),
            ("GJ09AB1234", [(0, 10, 1.0)]),
            ("ABNE123456", []),
            ("My Bike's registration number is OD02BA2341 with a lot of text beyond", [(33, 43, 1.0)]),
        ],
    )


def test_in_vehicle_registration_district_lists():
    # the upstream recognizer's test_list_length
    expected = {
        "WB": 97, "UP": 85, "UK": 20, "TS": 37, "TR": 8, "TN": 98, "SK": 8, "RJ": 57,
        "PY": 5, "PB": 98, "OR": 30, "OD": 34, "NL": 10, "MZ": 8, "MP": 70, "MN": 7,
        "ML": 10, "MH": 50, "LD": 9, "LA": 2, "KL": 98, "KA": 70, "JH": 23, "HR": 98,
        "HP": 98, "GJ": 39, "GA": 12, "DL": 13, "DN": 1, "DD": 3, "CH": 4, "CG": 30,
        "BR": 38, "AS": 33, "AR": 20, "AP": 2, "AN": 1,
    }
    for state, size in expected.items():
        assert len(IN_VEHICLE_RTO_DISTRICTS[state]) == size, state
    assert len(IN_VEHICLE_RTO_DISTRICTS) == 38  # incl. JK
    assert "21" not in IN_VEHICLE_RTO_DISTRICTS["KA"] and "22" in IN_VEHICLE_RTO_DISTRICTS["KA"]
    assert IN_VEHICLE_RTO_DISTRICTS["DL"] == frozenset(str(n) for n in range(1, 14))


def test_in_vehicle_registration_field_hint():
    _assert_field_hint("IN_VEHICLE_REGISTRATION", "KA99ME3456", "vehicle_registration_number")
    _assert_field_hint("IN_VEHICLE_REGISTRATION", "MN2412", "license_plate")
    _assert_field_hint("IN_VEHICLE_REGISTRATION", "MCX1243", "rto_reg_no")


def test_in_voter():
    _run_table(
        "IN VOTER ID", [
            ("KSD1287349", [(0, 10, 0.4)]),
            ("my voter: DBJ2289013", [(10, 20, 0.4)]),
            ("uzb2345117", [(0, 10, 0.3)]),
            ("this MUP5632811", [(5, 15, 0.3)]),
            ("You can vote with your CPJ4467918 number", [(23, 33, 0.4)]),
            # invalid
            ("zxdf8923q1", []),
            ("A8923571WZ", []),
        ],
    )


def test_in_voter_field_hint():
    _assert_field_hint("IN VOTER ID", "uzb2345117", "voter_id")
    _assert_field_hint("IN VOTER ID", "KSD1287349", "epic_no")


# ------------------------------------------------------------- Singapore ----

def test_sg_nric_fin():
    medium = (0.5, 0.8)
    _run_table(
        "SG_NRIC_FIN", [
            ("S2740116C", [(0, 9, medium)]),
            ("T1234567Z", [(0, 9, medium)]),
            ("F2346401L", [(0, 9, medium)]),
            ("G1122144L", [(0, 9, medium)]),
            ("M4332674T", [(0, 9, medium)]),
            ("S9108268C T7572225C", [(0, 9, medium), (10, 19, medium)]),
            ("NRIC S2740116C was processed", [(5, 14, medium)]),
            # weak match: prefix outside S/T/F/G/M
            ("A1234567Z", [(0, 9, (0, 0.3))]),
            ("B1234567Z", [(0, 9, (0, 0.3))]),
            # no match
            ("PA12348L", []),
            ("", []),
        ],
    )


def test_sg_nric_fin_field_hint():
    _assert_field_hint("SG_NRIC_FIN", "A1234567Z", "nric")
    _assert_field_hint("SG_NRIC_FIN", "S2740116C", "fin_number")


def test_sg_uen():
    _run_table(
        "SG_UEN", [
            ("53125226D", [(0, 9, 1.0)]),  # format A
            ("201434292D", [(0, 10, 1.0)]),  # format B
            ("T16RF0037C", [(0, 10, 1.0)]),  # format C
            ("S57TU0392K", [(0, 10, 1.0)]),
            ("R16RF0037F", [(0, 10, 1.0)]),
            ("53125226D 201434292D S57TU0392K", [(0, 9, 1.0), (10, 20, 1.0), (21, 31, 1.0)]),
            ("UEN 53125226D was processed", [(4, 13, 1.0)]),
            ("53125226d", [(0, 9, 1.0)]),
            ("t16rf0037c", [(0, 10, 1.0)]),
            # no match
            ("53125226", []),
            ("", []),
        ],
    )


def test_sg_uen_validator_rejects_bad_checksums():
    # not in the upstream recognizer's table; exercises each ported format checker
    assert _validate_sg_uen("53125226D") is True
    assert _validate_sg_uen("53125226A") is False  # format A, wrong check letter
    assert _validate_sg_uen("201434292A") is False  # format B, wrong check letter
    assert _validate_sg_uen("209934292D") is False  # format B, registration year in the future
    assert _validate_sg_uen("T16RF0037A") is False  # format C, wrong check letter
    assert _validate_sg_uen("T16ZZ0037C") is False  # format C, unknown entity type
    assert _validate_sg_uen("5312522") is False
    assert run_rule(_rule("SG_UEN"), "53125226A 201434292A T16ZZ0037C") == []


def test_sg_uen_field_hint():
    _assert_field_hint("SG_UEN", "53125226D", "company_uen")


# ------------------------------------------------------------- Australia ----

_AU_NEGATIVE_FORMATS = [
    ("5282475355632", []),
    ("52824753556AF", []),
    ("51 824 753 5564", []),
    ("123 456\n789", []),
]


def test_au_abn():
    _run_table(
        "AU_ABN", [
            ("51 824 753 556", [(0, 14, (1.0, 1.0))]),
            ("51824753556", [(0, 11, (1.0, 1.0))]),
            # valid formatting, invalid checksum
            ("52 824 753 556", []),
            ("52824753556", []),
            # a valid ABN never starts with 0
            ("00000000560", []),
        ] + _AU_NEGATIVE_FORMATS,
    )


def test_au_abn_field_hint():
    _assert_field_hint("AU_ABN", "51824753556", "abn")


def test_au_acn():
    _run_table(
        "AU_ACN", [
            ("000 000 019", [(0, 11, (1.0, 1.0))]),
            ("005 499 981", [(0, 11, (1.0, 1.0))]),
            ("006249976", [(0, 9, (1.0, 1.0))]),
            ("000000180", [(0, 9, (1.0, 1.0))]),  # check digit 0
            ("824 753 557", []),
            ("824753557", []),
        ] + _AU_NEGATIVE_FORMATS,
    )


def test_au_acn_field_hint():
    _assert_field_hint("AU_ACN", "006249976", "acn_number")


def test_au_medicare():
    _run_table(
        "AU_MEDICARE", [
            ("2123 45670 1", [(0, 12, (1.0, 1.0))]),
            ("2123456701", [(0, 10, (1.0, 1.0))]),
            ("2123 25870 1", []),
            ("2123258701", []),
            ("212345670221", []),
            ("2123456702AF", []),
            ("123 456\n789", []),
        ],
    )


def test_au_medicare_field_hint():
    _assert_field_hint("AU_MEDICARE", "2123456701", "medicare_no")


def test_au_tfn():
    _run_table(
        "AU_TFN", [
            ("876 543 210", [(0, 11, (1.0, 1.0))]),
            ("876543210", [(0, 9, (1.0, 1.0))]),
            ("824 753 557", []),
            ("824753557", []),
        ] + _AU_NEGATIVE_FORMATS,
    )


def test_au_tfn_field_hint():
    _assert_field_hint("AU_TFN", "876543210", "tfn")
    _assert_field_hint("AU_TFN", "876 543 210", "tax_file_number")


# ----------------------------------------------------------------- Korea ----

def test_kr_brn():
    _run_table(
        "KR_BRN", [
            ("104-86-56659", [(0, 12, (1.0, 1.0))]),
            ("1048656659", [(0, 10, (1.0, 1.0))]),
            ("104-82-13138", [(0, 12, (1.0, 1.0))]),
            ("My BRN is 1048656659", [(10, 20, (1.0, 1.0))]),
            ("104-86-56658", []),  # wrong checksum
            ("110-81-4127", []),  # too short
            ("110-81-412722", []),  # too long
            ("110-81-4127A", []),  # contains letters
            ("123-45-67890", []),  # fails checksum
        ],
    )


def test_kr_brn_field_hint():
    _assert_field_hint("KR_BRN", "1048656659", "brn")
    _assert_field_hint("KR_BRN", "104-86-56659", "business_registration_no")


def test_kr_driver_license():
    _run_table(
        "KR_DRIVER_LICENSE", [
            ("11-22-123456-12", [(0, 15, (1.0, 1.0))]),
            ("112212345612", [(0, 12, (1.0, 1.0))]),
            ("My license is 13-22-123456-12", [(14, 29, (1.0, 1.0))]),
            ("28 22 123456 12", [(0, 15, (1.0, 1.0))]),
            ("99-22-123456-12", []),  # unregistered regional code
            ("11-22-12345-12", []),
            ("11-22-123456-1", []),
            ("11-22-123A56-12", []),
            ("111-22-123456-12", []),
            ("11-22-123456-123", []),
        ],
    )


def test_kr_driver_license_field_hint():
    _assert_field_hint("KR_DRIVER_LICENSE", "112212345612", "driver_license_no")
    _assert_field_hint("KR_DRIVER_LICENSE", "11-22-123456-12", "drivingLicence")


def test_kr_frn():
    medium, strong = (0.5, 0.5), (1.0, 1.0)
    _run_table(
        "KR_FRN", [
            # valid format, checksum not matching (post-2020 numbers are random)
            ("911124-5678901", [(0, 14, medium)]),
            ("9111245678901", [(0, 13, medium)]),
            ("000505-7637892", [(0, 14, medium)]),
            ("0005056637892", [(0, 13, medium)]),
            ("His Korean FRN is 911124-5678901", [(18, 32, medium)]),
            # checksum matches
            ("911124-5678906", [(0, 14, strong)]),
            ("9111245678906", [(0, 13, strong)]),
            ("050912-6000012", [(0, 14, strong)]),
            ("0509126000012", [(0, 13, strong)]),
            ("His FRN is 9111245678906", [(11, 24, strong)]),
            # invalid
            ("001332-1234567", []),
            ("0013321234567", []),
            ("960121+1021413", []),
            ("960111-10214131", []),
            ("960303-0021413", []),
            ("760413-1212134", []),
            ("000402-2214431", []),
            ("051102-9234110", []),
        ],
    )


def test_kr_frn_field_hint():
    _assert_field_hint("KR_FRN", "9111245678901", "frn")
    _assert_field_hint("KR_FRN", "911124-5678901", "foreigner_reg_no")


def test_kr_passport():
    current, previous = (0.1, 0.1), (0.05, 0.05)
    _run_table(
        "KR_PASSPORT", [
            ("M123A4567", [(0, 9, current)]),
            ("m456B7890", [(0, 9, current)]),
            ("d789C1234", [(0, 9, current)]),
            ("S012D5678", [(0, 9, current)]),
            ("M345E9012", [(0, 9, current)]),
            ("M678f3456", [(0, 9, current)]),
            ("M901g7890", [(0, 9, current)]),
            ("My passport number is M123A4567", [(22, 31, current)]),
            ("Korean passport: M456B7890", [(17, 26, current)]),
            ("여권번호는 M789C1234입니다", [(6, 15, current)]),
            ("Korean passport number: M123A4567", [(24, 33, current)]),
            ("대한민국 여권번호: M456B7890", [(11, 20, current)]),
            # previous format
            ("M12345678", [(0, 9, previous)]),
            ("m87654321", [(0, 9, previous)]),
            ("d11223344", [(0, 9, previous)]),
            ("s99887766", [(0, 9, previous)]),
            ("My old passport M12345678", [(16, 25, previous)]),
            ("대한민국 여권 S87654321", [(8, 17, previous)]),
            ("M123A4567 and M456B7890", [(0, 9, current), (14, 23, current)]),
            # invalid
            ("A123B4567", []),
            ("M12A4567", []),
            ("M1234A567", []),
            ("M123AB567", []),
            ("M123A456", []),
            ("M123A45678", []),
            ("M1234567", []),
            ("M123456789", []),
            ("123A4567", []),
            ("MM123A4567", []),
            ("M123 A4567", []),
            ("M123-A4567", []),
            ("", []),
            ("passport", []),
            ("M123a456", []),
            ("This is just text", []),
        ],
    )


def test_kr_passport_field_hint():
    _assert_field_hint("KR_PASSPORT", "M12345678", "passport_number")


def test_kr_rrn():
    medium, strong = (0.5, 0.5), (1.0, 1.0)
    _run_table(
        "KR_RRN", [
            ("960121-1234567", [(0, 14, medium)]),
            ("9601211234567", [(0, 13, medium)]),
            ("000505-3637892", [(0, 14, medium)]),
            ("0005053637892", [(0, 13, medium)]),
            ("His Korean RRN is 960121-1234567", [(18, 32, medium)]),
            ("960121-1021413", [(0, 14, strong)]),
            ("9601211021413", [(0, 13, strong)]),
            ("050912-2000019", [(0, 14, strong)]),
            ("0509122000019", [(0, 13, strong)]),
            ("His RRN is 9601211021413", [(11, 24, strong)]),
            # invalid
            ("001332-1234567", []),
            ("0013321234567", []),
            ("960121+1021413", []),
            ("960111-10214131", []),
            ("960303-0021413", []),
            ("760413-5212134", []),
            ("000402-6214431", []),
            ("051102-9234110", []),
        ],
    )


def test_kr_rrn_field_hint():
    _assert_field_hint("KR_RRN", "9601211234567", "rrn")
    _assert_field_hint("KR_RRN", "960121-1234567", "resident_registration_number")


def test_kr_context_keeps_korean_words():
    assert "사업자등록번호" in _rule("KR_BRN").context
    assert "운전면허번호" in _rule("KR_DRIVER_LICENSE").context
    assert "외국인등록번호" in _rule("KR_FRN").context
    assert "여권" in _rule("KR_PASSPORT").context
    assert "korean resident registration number" in _rule("KR_RRN").context


# -------------------------------------------------------------- Thailand ----

def test_th_tnin():
    valid = (0.5, 1.0)
    _run_table(
        "TH_TNIN", [
            ("1234567890121", [(0, 13, valid)]),
            ("2345678901234", [(0, 13, valid)]),
            ("3456789012347", [(0, 13, valid)]),
            ("4567890123459", [(0, 13, valid)]),
            ("5678901234560", [(0, 13, valid)]),
            # province codes 22, 52, 58 are assigned
            ("1220000000007", [(0, 13, valid)]),
            ("1520000000004", [(0, 13, valid)]),
            ("1580000000004", [(0, 13, valid)]),
            ("My Thai ID is 1234567890121", [(14, 27, valid)]),
            ("TNIN: 2345678901234", [(6, 19, valid)]),
            ("เลขประจำตัวประชาชน: 3456789012347", [(20, 33, valid)]),
            ("Thai National ID 1234567890121", [(17, 30, valid)]),
            ("เลขบัตรประชาชน 2345678901234", [(15, 28, valid)]),
            # wrong length / non-digits
            ("123456789012", []),
            ("12345678901234", []),
            ("123456789012a", []),
            ("123456789012 ", []),
            # first or second digit 0
            ("0234567890124", []),
            ("0034567890124", []),
            ("1034567890124", []),
            ("1304567890124", []),
            # forbidden province codes
            ("1284567890124", []),
            ("1294567890124", []),
            ("1594567890124", []),
            ("1684567890124", []),
            ("1694567890124", []),
            ("1784567890124", []),
            ("1794567890124", []),
            ("1874567890124", []),
            ("1884567890124", []),
            ("1894567890124", []),
            ("1974567890124", []),
            ("1984567890124", []),
            ("1994567890124", []),
            # checksum failures
            ("1234567890123", []),
            ("2345678901235", []),
            ("3456789012346", []),
            ("0000000000000", []),
            ("1111111111111", []),
        ],
    )


def test_th_tnin_validator():
    assert _validate_th_tnin("1234567890121") is True
    assert _validate_th_tnin("2345678901234") is True
    assert _validate_th_tnin("3456789012347") is True
    assert _validate_th_tnin("0234567890124") is False
    assert _validate_th_tnin("1034567890124") is False
    assert _validate_th_tnin("1284567890124") is False
    assert _validate_th_tnin("1294567890124") is False
    assert _validate_th_tnin("123456789012") is False
    assert _validate_th_tnin("12345678901234") is False
    assert _validate_th_tnin("123456789012a") is False
    assert _validate_th_tnin("123456789012 ") is False


def test_th_tnin_context_and_field_hint():
    assert _rule("TH_TNIN").context == (
        "thai national id",
        "thai id number",
        "tnin",
        "เลขประจำตัวประชาชน",
        "เลขบัตรประชาชน",
        "รหัสปชช",
    )
    _assert_field_hint("TH_TNIN", "1234567890121", "thai_id")
    _assert_field_hint("TH_TNIN", "2345678901234", "national_id_number")
    _assert_field_hint("TH_TNIN", "3456789012347", "tnin")
