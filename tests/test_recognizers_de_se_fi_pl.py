"""
Tests for the upstream DE / SE / FI / PL recognizers ported to src.engine.rules.

Every valid / invalid example and expected score comes from the upstream recognizer's own
tests (tests/test_<name>_recognizer.py). Bare values are asserted with the
exact upstream score; running-text examples are asserted with ">=" because this
engine also applies the context-word boost that the upstream recognizer's recognizer-level
tests do not exercise.
"""
import json
import re
from pathlib import Path

from src.engine.recognizers.de_se_fi_pl import RULES
from src.engine.rules import FIELD_HINT_SCORE, run_rule

MAX_SCORE = 1.0
EPS = 1e-6
ROOT = Path(__file__).resolve().parent.parent


def _rule(name):
    for rule in RULES:
        if rule.name == name:
            return rule
    raise AssertionError(f"rule {name} not found in de_se_fi_pl.RULES")


def _single(rule, text, start, end, score, at_least=False):
    """Exactly one match at [start, end) with the given score (or >= score)."""
    results = run_rule(rule, text)
    assert len(results) == 1, (rule.name, text, results)
    res = results[0]
    assert res["detector"] == rule.name
    assert (res["start"], res["end"]) == (start, end), (rule.name, text, res)
    if at_least:
        assert res["score"] >= score - EPS, (rule.name, text, res)
    else:
        assert abs(res["score"] - score) < EPS, (rule.name, text, res)
    return res


def _none(rule, text):
    results = run_rule(rule, text)
    assert results == [], (rule.name, text, results)


def _count(rule, text, expected_len):
    results = run_rule(rule, text)
    assert len(results) == expected_len, (rule.name, text, results)
    return results


def _validator(rule, cases):
    for value, expected in cases:
        got = rule.validator(value)
        assert got is expected, (rule.name, value, got, expected)


def _field_hint(rule, value, field_names):
    for field_name in field_names:
        assert re.search(rule.field_hint, field_name.lower()), (rule.name, field_name)
        results = run_rule(rule, value, field_name=field_name)
        assert len(results) == 1, (rule.name, value, field_name, results)
        assert results[0]["score"] >= FIELD_HINT_SCORE - EPS, (rule.name, value, field_name, results)


# ---------------------------------------------------------------------------
# Module-level consistency
# ---------------------------------------------------------------------------

EXPECTED_NAMES = {
    "DE_ID_CARD", "DE_PASSPORT", "DE_SOCIAL_SECURITY", "DE_TAX_ID", "DE_TAX_NUMBER",
    "DE_VAT_ID", "DE_HANDELSREGISTER", "DE_HEALTH_INSURANCE", "DE_BSNR", "DE_LANR",
    "DE_FUEHRERSCHEIN", "DE_KFZ", "DE_PLZ", "SE_PERSONNUMMER", "SE_ORGANISATIONSNUMMER",
    "FI_PERSONAL_IDENTITY_CODE", "PL_PESEL",
}


def test_all_expected_rules_present_and_unique():
    names = [r.name for r in RULES]
    assert len(names) == len(set(names)), names
    assert set(names) == EXPECTED_NAMES, set(names) ^ EXPECTED_NAMES


def test_rules_match_findings_mapping():
    with open(ROOT / "fixtures" / "findings-mapping.json", encoding="utf-8") as fh:
        mapping = json.load(fh)[0]
    for rule in RULES:
        assert rule.name in mapping, rule.name
        entry = mapping[rule.name]
        assert rule.category == entry["category"], (rule.name, rule.category, entry["category"])
        severity = "Low" if entry["final_risk_factor"] == "Lowest" else entry["final_risk_factor"]
        assert rule.severity == severity, (rule.name, rule.severity, severity)


def test_regions():
    for rule in RULES:
        expected = rule.name.split("_", 1)[0]
        assert rule.region == expected, (rule.name, rule.region)
    assert {r.region for r in RULES} == {"DE", "SE", "FI", "PL"}


def test_every_rule_has_description_examples_field_hint_and_context():
    for rule in RULES:
        assert rule.description and "\n" not in rule.description, rule.name
        assert rule.field_hint, rule.name
        assert rule.context, rule.name
        assert 1 <= len(rule.examples) <= 3, (rule.name, rule.examples)
        for example in rule.examples:
            results = run_rule(rule, example)
            assert len(results) == 1, (rule.name, example, results)
            assert results[0]["value"] == example, (rule.name, example, results)


# ---------------------------------------------------------------------------
# DE_BSNR
# ---------------------------------------------------------------------------

def test_de_bsnr():
    rule = _rule("DE_BSNR")
    pattern_score = 0.2
    # Structurally valid -> validate_result None -> pattern score (whitelisted or not)
    for text in ("021234568", "521234567", "711234567", "351234567", "991234567", "051234567"):
        _single(rule, text, 0, 9, pattern_score)
    _single(rule, "Betriebsstättennummer: 021234568", 23, 32, pattern_score, at_least=True)
    _single(rule, "BSNR 711234567 der Praxis.", 5, 14, pattern_score, at_least=True)
    # All-zero, wrong length, non-numeric -> dropped / no match
    for text in ("000000000", "02123456", "0212345689", "02123456A"):
        _none(rule, text)


def test_de_bsnr_validator():
    _validator(
        _rule("DE_BSNR"), [
            ("021234568", None), ("521234567", None), ("711234567", None), ("351234567", None),
            ("741234567", None), ("991234567", None), ("051234567", None),
            ("000000000", False), ("02123456", False), ("0212345689", False), ("02123456A", False),
        ],
    )


def test_de_bsnr_field_hint():
    _field_hint(_rule("DE_BSNR"), "021234568", ["bsnr", "betriebsstaetten_nr", "praxis_nummer"])


# ---------------------------------------------------------------------------
# DE_FUEHRERSCHEIN
# ---------------------------------------------------------------------------

def test_de_fuehrerschein():
    rule = _rule("DE_FUEHRERSCHEIN")
    for text in (
        "BO12345678A", "MU12345678B", "HH98765432C", "KO12345678X", "DO98765432Z",
        "GE123456780", "MU123456785", "mu12345678b",
    ):
        _single(rule, text, 0, 11, 0.35)
    _count(rule, "Führerscheinnummer: BO12345678A", 1)
    _count(rule, "Fahrerlaubnis MU12345678B wurde ausgestellt.", 1)
    for text in ("BO12345678", "BO12345678AB", "12345678901", "B12345678A"):
        _none(rule, text)


def test_de_fuehrerschein_field_hint():
    _field_hint(
        _rule("DE_FUEHRERSCHEIN"), "BO12345678A",
        ["fuehrerschein_nr", "führerscheinnummer", "driver_license", "drivers_licence_no"],
    )


# ---------------------------------------------------------------------------
# DE_HANDELSREGISTER
# ---------------------------------------------------------------------------

def test_de_handelsregister():
    rule = _rule("DE_HANDELSREGISTER")
    for text in ("HRB 123456", "HRB 1", "HRB123456", "HRA 12345", "HRA12345", "HRB 999999", "hrb 12345"):
        _single(rule, text, 0, len(text), 0.5)
    _count(rule, "Amtsgericht München HRB 12345.", 1)
    _count(rule, "eingetragen im HRA 99999 Köln", 1)
    _count(rule, "Handelsregisternummer: HRB 123456", 1)
    for text in ("HRC 12345", "HR 12345", "HRB 1234567"):
        _none(rule, text)


def test_de_handelsregister_field_hint():
    _field_hint(_rule("DE_HANDELSREGISTER"), "HRB 123456", ["handelsregisternummer", "hrb", "hr_nr"])


# ---------------------------------------------------------------------------
# DE_HEALTH_INSURANCE
# ---------------------------------------------------------------------------

def test_de_health_insurance():
    rule = _rule("DE_HEALTH_INSURANCE")
    for text in (
        "A000500015", "C000500021", "A123456780", "M123456785", "B123456782",
        "Z000000005", "Z999999997", "a123456780",
    ):
        _single(rule, text, 0, 10, MAX_SCORE)
    _single(rule, "Krankenkasse KVNR: A123456780", 19, 29, MAX_SCORE)
    _single(rule, "eGK-Nummer M123456785 bitte angeben.", 11, 21, MAX_SCORE)
    for text in ("A123456787", "M123456789", "1123456780", "A12345678", "A1234567890"):
        _none(rule, text)


def test_de_health_insurance_validator():
    _validator(
        _rule("DE_HEALTH_INSURANCE"), [
            ("A000500015", True), ("C000500021", True), ("A123456780", True), ("M123456785", True),
            ("B123456782", True), ("Z000000005", True), ("Z999999997", True),
            ("A123456787", False), ("M123456789", False), ("A000500010", False),
            ("1123456780", False), ("A12345678", False), ("A1234567890", False),
            ("a123456780", True),
        ],
    )


def test_de_health_insurance_field_hint():
    _field_hint(
        _rule("DE_HEALTH_INSURANCE"), "A000500015",
        ["krankenversicherungsnummer", "kvnr", "health_insurance_no"],
    )


# ---------------------------------------------------------------------------
# DE_ID_CARD
# ---------------------------------------------------------------------------

def test_de_id_card():
    rule = _rule("DE_ID_CARD")
    npa_validated = 1.0
    legacy_pattern_score = 0.5
    for text in ("L01X00T44", "C01234565", "CZ6311T03", "G00000002", "l01x00t44"):
        _single(rule, text, 0, 9, npa_validated)
    _single(rule, "Personalausweis: L01X00T44.", 17, 26, npa_validated)
    # Legacy T-format: matched by both patterns, validate_result None, dedupe keeps 0.5
    for text in ("T22000129", "T00000000", "T99999999", "t22000129"):
        _single(rule, text, 0, 9, legacy_pattern_score)
    _single(rule, "Ausweis Nr. T22000129 gültig bis 2025.", 12, 21, legacy_pattern_score, at_least=True)
    for text in ("L01X00T47", "C01234567", "T2200012", "T220001290", "123456789"):
        _none(rule, text)


def test_de_id_card_validator():
    _validator(
        _rule("DE_ID_CARD"), [
            ("L01X00T44", True), ("C01234565", True), ("CZ6311T03", True), ("G00000002", True),
            ("l01x00t44", True),
            ("L01X00T47", False), ("C01234567", False),
            ("T22000129", None), ("T00000000", None),
            ("L01X00T4", False), ("L01X00T440", False), ("L01X00T4A", False),
        ],
    )


def test_de_id_card_field_hint():
    # Legacy number has no checksum (0.5) so the lift to 0.85 comes from the field hint
    _field_hint(_rule("DE_ID_CARD"), "T22000129", ["personalausweis_nr", "id_card_number", "ausweisnummer"])


# ---------------------------------------------------------------------------
# DE_KFZ
# ---------------------------------------------------------------------------

def test_de_kfz():
    rule = _rule("DE_KFZ")
    for text in (
        "B AB 1234", "M XY 999", "HH AB 1234", "KA EF 12H", "S AB 12E", "MIL E 1234",
        "MIL EF 1234E", "B-AB-1234", "M-XY-999", "HH-AB-1234", "b ab 1234", "m xy 999",
    ):
        _single(rule, text, 0, len(text), 0.3)  # umlaut-aware patterns (0.3) win over ASCII (0.2)
    _count(rule, "Das Fahrzeug mit Kennzeichen B AB 1234 wurde gesehen.", 1)
    _count(rule, "Kennzeichen: HH-AB-1234.", 1)
    for text in ("BAB1234", "B 1234", "BXYZ AB 1234"):
        _none(rule, text)


def test_de_kfz_field_hint():
    _field_hint(_rule("DE_KFZ"), "B AB 1234", ["kfz_kennzeichen", "license_plate", "kfz"])


# ---------------------------------------------------------------------------
# DE_LANR
# ---------------------------------------------------------------------------

def test_de_lanr():
    rule = _rule("DE_LANR")
    for text in ("123456601", "234567701", "100000601", "987654401", "555555501", "999999901"):
        _single(rule, text, 0, 9, MAX_SCORE)
    _single(rule, "LANR: 123456601 des behandelnden Arztes.", 6, 15, MAX_SCORE)
    _single(rule, "Arztnummer 987654401 auf dem Rezept.", 11, 20, MAX_SCORE)
    for text in ("123456901", "234567601", "100000401", "12345660", "1234566010"):
        _none(rule, text)


def test_de_lanr_validator():
    _validator(
        _rule("DE_LANR"), [
            ("123456601", True), ("234567701", True), ("100000601", True), ("987654401", True),
            ("555555501", True), ("999999901", True),
            ("123456901", False), ("234567601", False), ("100000401", False),
            ("12345660", False), ("1234566010", False), ("12345660a", False),
        ],
    )


def test_de_lanr_field_hint():
    _field_hint(_rule("DE_LANR"), "123456601", ["lanr", "arzt_nr", "physician_number"])


# ---------------------------------------------------------------------------
# DE_PASSPORT
# ---------------------------------------------------------------------------

def test_de_passport():
    rule = _rule("DE_PASSPORT")
    for text in ("C01234565", "F12345671", "L01X00T44", "CZ6311T03", "G00000002", "C01X00T41", "c01234565"):
        _single(rule, text, 0, 9, MAX_SCORE)
    _single(rule, "Reisepass C01234565 ausgestellt am 01.01.2020.", 10, 19, MAX_SCORE)
    _single(rule, "Pass-Nr.: F12345671", 10, 19, MAX_SCORE)
    for text in ("C01234567", "F12345678", "L01X00T47", "C0123456", "C012345678", "901234567"):
        _none(rule, text)


def test_de_passport_validator():
    _validator(
        _rule("DE_PASSPORT"), [
            ("C01234565", True), ("F12345671", True), ("L01X00T44", True), ("CZ6311T03", True),
            ("G00000002", True), ("C01X00T41", True), ("c01234565", True),
            ("C01234567", False), ("L01X00T47", False),
            ("C0123456", False), ("C012345678", False), ("C0123456A", False),
            ("A01234567", False), ("IOQSUBDE1", False),
        ],
    )


def test_de_passport_field_hint():
    _field_hint(_rule("DE_PASSPORT"), "C01234565", ["reisepass_nr", "passport_number", "passnummer"])


# ---------------------------------------------------------------------------
# DE_PLZ
# ---------------------------------------------------------------------------

def test_de_plz():
    rule = _rule("DE_PLZ")
    for text in ("10115", "80331", "22085", "01001", "99998"):
        _single(rule, text, 0, 5, 0.05)
    _count(rule, "PLZ: 10115", 1)
    _count(rule, "Postleitzahl 80331 München", 1)
    for text in ("00000", "01000", "99999", "101150", "1011"):
        _none(rule, text)


def test_de_plz_positions_and_score_range():
    rule = _rule("DE_PLZ")
    for text, start, end in (("10115", 0, 5), ("PLZ 80331", 4, 9)):
        res = _single(rule, text, start, end, 0.0, at_least=True)
        assert 0.0 <= res["score"] <= 0.5 + EPS, res


def test_de_plz_field_hint():
    _field_hint(_rule("DE_PLZ"), "10115", ["plz", "postal_code", "zip", "zipCode"])


# ---------------------------------------------------------------------------
# DE_SOCIAL_SECURITY
# ---------------------------------------------------------------------------

def test_de_social_security():
    rule = _rule("DE_SOCIAL_SECURITY")
    for text in ("15070649C103", "65070803A019", "20151090B023", "38551285K051"):
        _single(rule, text, 0, 12, MAX_SCORE)
    _single(rule, "RVNR: 15070649C103 laut Sozialversicherungsausweis.", 6, 18, MAX_SCORE)
    for text in (
        "15070649C100", "65070803A012", "15070049C103", "15071349C103",
        "150706491103", "15070649C10", "15070649C1030",
    ):
        _none(rule, text)


def test_de_social_security_validator():
    _validator(
        _rule("DE_SOCIAL_SECURITY"), [
            ("15070649C103", True), ("65070803A019", True), ("20151090B023", True), ("38551285K051", True),
            ("15070649C100", False), ("65070803A012", False), ("65070803A018", False),
            ("150706491103", False), ("15070649C10", False), ("15070649C1030", False),
            ("15420649C103", False), ("15850649C103", False),
            ("15070049C103", False), ("15071349C103", False),
        ],
    )


def test_de_social_security_field_hint():
    _field_hint(
        _rule("DE_SOCIAL_SECURITY"), "15070649C103",
        ["sozialversicherungsnummer", "social_security_number", "svnr", "rv_nr"],
    )


# ---------------------------------------------------------------------------
# DE_TAX_ID
# ---------------------------------------------------------------------------

def test_de_tax_id():
    rule = _rule("DE_TAX_ID")
    for text in ("12345678903", "98765432106"):
        _single(rule, text, 0, 11, MAX_SCORE)
    _single(rule, "Meine Steuer-ID: 12345678903.", 17, 28, MAX_SCORE)
    _single(rule, "IdNr. 98765432106 liegt vor.", 6, 17, MAX_SCORE)
    for text in (
        "12345678901", "98765432100", "02345678901", "1234567890", "123456789030",
        "11111111111", "11112345678",
    ):
        _none(rule, text)


def test_de_tax_id_validator():
    _validator(
        _rule("DE_TAX_ID"), [
            ("12345678903", True), ("98765432106", True),
            ("12345678901", False), ("98765432100", False),
            ("02345678903", False), ("abcdefghijk", False),
            ("1234567890", False), ("123456789030", False),
            ("11111111111", False), ("11112345678", False), ("12222234567", False),
        ],
    )


def test_de_tax_id_field_hint():
    _field_hint(_rule("DE_TAX_ID"), "12345678903", ["steuer_id", "tax_id", "idnr", "steueridentifikationsnummer"])


# ---------------------------------------------------------------------------
# DE_TAX_NUMBER
# ---------------------------------------------------------------------------

def test_de_tax_number():
    rule = _rule("DE_TAX_NUMBER")
    # ELSTER unified 13-digit format (Bundesland codes 01-16)
    for text in ("0281508150123", "0981508150999", "1681508150001", "0181508150000"):
        _single(rule, text, 0, 13, 0.5)
    for text in ("1781508150001", "0081508150001", "028150815012"):
        _none(rule, text)
    # Slash-separated Bayern-style 3/3/5 (matched by both slash patterns, 0.4 wins)
    for text in ("123/456/78901", "987/654/32100"):
        _single(rule, text, 0, len(text), 0.4)
    # General slash-separated 2-3 / 3-4 / 4-5
    for text in ("12/345/6789", "12/3456/7890", "123/3456/7890"):
        _single(rule, text, 0, len(text), 0.2)
    _count(rule, "Steuernummer: 0981508150999 wurde vergeben.", 1)
    _count(rule, "St.-Nr. 123/456/78901 bitte angeben.", 1)


def test_de_tax_number_field_hint():
    _field_hint(_rule("DE_TAX_NUMBER"), "12/345/6789", ["steuernummer", "tax_number", "st_nr", "steuer_nr"])


# ---------------------------------------------------------------------------
# DE_VAT_ID
# ---------------------------------------------------------------------------

def test_de_vat_id_default_mode():
    rule = _rule("DE_VAT_ID")
    for text in ("DE136695976", "DE129273398", "DE123456788", "DE111111117", "de136695976"):
        _single(rule, text, 0, 11, MAX_SCORE)
    _single(rule, "USt-IdNr.: DE136695976", 11, 22, MAX_SCORE)
    _count(rule, "Bitte angeben: DE129273398 auf der Rechnung.", 1)
    # Heuristic mode: valid structure, invalid checksum -> kept at pattern score, not dropped
    for text in ("DE123456789", "DE987654321", "DE100000001"):
        _single(rule, text, 0, 11, 0.5)
    for text in ("AT123456789", "FR12345678901", "DE12345678", "DE1234567890"):
        _none(rule, text)


def test_de_vat_id_real_world_formatting():
    rule = _rule("DE_VAT_ID")
    _single(rule, "DE 136 695 976", 0, 14, MAX_SCORE)
    for text in (
        "DE 129 273 398", "DE 136695976", "DE-136-695-976", "DE.136.695.976",
        "DE 136-695.976", "de 136 695 976",
    ):
        _single(rule, text, 0, len(text), MAX_SCORE)
    _count(rule, "Rechnung USt-IdNr. DE 136 695 976 von Beispiel GmbH", 1)


def test_de_vat_id_validator_tri_state():
    _validator(
        _rule("DE_VAT_ID"), [
            ("DE136695976", True), ("DE129273398", True), ("DE123456788", True), ("DE111111117", True),
            ("de136695976", True), ("DE 136 695 976", True), ("DE-136-695-976", True),
            ("DE.136.695.976", True), ("de 136-695.976", True),
            ("DE12345678", False), ("DE1234567890", False), ("AT123456789", False), ("", False),
            ("DEabcdefghi", False),
            ("DE123456789", None), ("DE987654321", None), ("DE100000001", None),
        ],
    )


def test_de_vat_id_validator_strict_mode():
    from src.engine.recognizers.de_se_fi_pl import _validate_de_vat_id

    for value, expected in (
        ("DE136695976", True), ("DE 136 695 976", True),
        ("DE12345678", False), ("AT123456789", False),
        ("DE123456789", False), ("DE987654321", False), ("DE100000001", False),
    ):
        assert _validate_de_vat_id(value, strict_checksum=True) is expected, value


def test_de_vat_id_field_hint():
    # Checksum-failing value keeps 0.5 by itself; the field hint lifts it to 0.85
    _field_hint(_rule("DE_VAT_ID"), "DE123456789", ["ust_id", "vat_id", "uid", "umsatzsteuer_id"])


# ---------------------------------------------------------------------------
# SE_ORGANISATIONSNUMMER
# ---------------------------------------------------------------------------

def test_se_organisationsnummer():
    rule = _rule("SE_ORGANISATIONSNUMMER")
    _single(rule, "212000-0142", 0, 11, MAX_SCORE)
    _single(rule, "Our company identity code is: 212000-0142. Thank you.", 30, 41, MAX_SCORE)
    _single(rule, "2120000142", 0, 10, MAX_SCORE)
    _single(rule, "556703-7485", 0, 11, MAX_SCORE)
    _single(rule, "5567037485", 0, 10, MAX_SCORE)
    _single(rule, "556703-7485 är vårt orgnummer.", 0, 11, MAX_SCORE)
    _single(rule, "556703-7485 tillhör vårt företag.", 0, 11, MAX_SCORE)
    for text in ("19000309-3393", "19001309-2393", "55670x-7485", "556703-7r85"):
        _none(rule, text)


def test_se_organisationsnummer_validator():
    _validator(
        _rule("SE_ORGANISATIONSNUMMER"), [
            ("212000-0142", True), ("5567037485", True),
            ("2120000143", False),   # Luhn mismatch
            ("2100000142", False),   # third digit < 2
            ("212000-014", False),   # 9 digits
        ],
    )


def test_se_organisationsnummer_field_hint():
    _field_hint(_rule("SE_ORGANISATIONSNUMMER"), "212000-0142", ["organisationsnummer", "org_nr", "orgnummer"])


# ---------------------------------------------------------------------------
# SE_PERSONNUMMER
# ---------------------------------------------------------------------------

def test_se_personnummer():
    rule = _rule("SE_PERSONNUMMER")
    _single(rule, "189004119807", 0, 12, MAX_SCORE)
    _single(rule, "My personal identity code is: 189110089811. Thank you.", 30, 42, MAX_SCORE)
    _single(rule, "191005059801", 0, 12, MAX_SCORE)
    _single(rule, "198712202384", 0, 12, MAX_SCORE)
    _single(rule, "871220-2384", 0, 11, MAX_SCORE)
    _single(rule, "199109242397 är mitt pnr.", 0, 12, MAX_SCORE)
    _single(rule, "19910924-2397 är mitt pnr.", 0, 13, MAX_SCORE)
    _single(rule, "199201232387", 0, 12, MAX_SCORE)
    _single(rule, "9201232387", 0, 10, MAX_SCORE)
    _single(rule, "Here's my personnummer 200109022392.", 23, 35, MAX_SCORE)
    _single(rule, "201109252385", 0, 12, MAX_SCORE)
    _single(rule, "20110925-2385", 0, 13, MAX_SCORE)
    _single(rule, "My swedish id code is199003052397.", 21, 33, MAX_SCORE)  # Very Weak pattern only
    for text in ("19000309-3393", "19001309-2393", "200504422381", "189x09179809", "18970c17-9809"):
        _none(rule, text)


def test_se_personnummer_validator():
    _validator(
        _rule("SE_PERSONNUMMER"), [
            ("198712202384", True), ("871220-2384", True),
            ("19000309-3393", False),  # Luhn mismatch
            ("19001309-2393", False),  # month 13
            ("200504422381", False),   # day 42
            ("8712202384", True),      # samordningsnummer-style days (61+) are accepted by the date check
            ("871280-2384", False),    # day 80 -> 20 ok for date, but Luhn fails
            ("8712", False),
        ],
    )


def test_se_personnummer_field_hint():
    _field_hint(_rule("SE_PERSONNUMMER"), "198712202384", ["personnummer", "personal_number", "person_nr", "pnr"])


# ---------------------------------------------------------------------------
# FI_PERSONAL_IDENTITY_CODE
# ---------------------------------------------------------------------------

def test_fi_personal_identity_code():
    rule = _rule("FI_PERSONAL_IDENTITY_CODE")
    for text in (
        "010594Y9032", "010594Y9021", "020594X903P", "020594X902N", "030594W903B",
        "030694W9024", "040594V9030", "040594V902Y", "050594U903M", "050594U902L",
        "010516B903X", "010516B902W", "020516C903K", "020516C902J", "030516D9037",
        "030516D9026", "010501E9032", "020502E902X", "020503F9037", "020504A902E",
        "020504B904H", "131052-308T", "131052-308t", "020504a902e",
    ):
        _single(rule, text, 0, 11, MAX_SCORE)
    _single(rule, "My personal identity code is: 010594Y9032. Thank you.", 30, 41, MAX_SCORE)
    _single(rule, "020594X903P is my hetu.", 0, 11, MAX_SCORE)
    _single(rule, "Here's my henkilötunnus 020594X902N.", 24, 35, MAX_SCORE)
    _single(rule, "My finnish id code is030594W903B.", 21, 32, MAX_SCORE)  # Very Weak pattern only
    for text in (
        "111111-111A", "111111+110G", "311190-1111", "310289-211C", "012245A110G",
        "010324A110G", "131052/308T", "131052:308T", "131052.308T", "290200+311B",
    ):
        _none(rule, text)


def test_fi_personal_identity_code_validator():
    _validator(
        _rule("FI_PERSONAL_IDENTITY_CODE"), [
            ("010594Y9032", True), ("131052-308T", True), ("131052-308t", True),
            ("111111-111A", False),   # control character mismatch
            ("311190-1111", False),   # 31 November
            ("290200+311B", False),   # 29 Feb 1800 (not a leap year)
            ("010594Y903", False),    # 10 characters
        ],
    )


def test_fi_personal_identity_code_field_hint():
    _field_hint(
        _rule("FI_PERSONAL_IDENTITY_CODE"), "010594Y9032",
        ["henkilotunnus", "henkilötunnus", "hetu", "personal_identity_code"],
    )


# ---------------------------------------------------------------------------
# PL_PESEL
# ---------------------------------------------------------------------------

def test_pl_pesel():
    rule = _rule("PL_PESEL")
    _single(rule, "44051401458", 0, 11, MAX_SCORE)
    _single(rule, "My pesel is 44051401458.", 12, 23, MAX_SCORE)
    _single(rule, "02070803628", 0, 11, MAX_SCORE)
    _single(rule, "11111111116", 0, 11, MAX_SCORE)
    for text in ("44051401459", "85040812345", "1111321111", "11110021111", "11-11-11-11114"):
        _none(rule, text)


def test_pl_pesel_validator():
    _validator(
        _rule("PL_PESEL"), [
            ("44051401458", True), ("02070803628", True), ("11111111116", True),
            ("44051401459", False), ("85040812345", False),
            ("4405140145", False), ("440514014588", False),
            ("4405140145A", False), ("44-051401458", False),
        ],
    )


def test_pl_pesel_field_hint():
    _field_hint(_rule("PL_PESEL"), "44051401458", ["pesel", "pesel_number", "customerPesel"])
