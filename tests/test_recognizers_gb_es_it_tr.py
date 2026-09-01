"""
Tests for the upstream-ported GB / ES / IT / TR rules (src/engine/recognizers/gb_es_it_tr.py).

Spans, valid / invalid inputs and scores come from the upstream recognizer's own recognizer
tests (upstream-analyzer/tests/test_<recognizer>_recognizer.py). the upstream recognizer's
tests call the recognizer directly, i.e. without the context-aware enhancer;
run_rule applies it, so an input that carries a context word next to the value
scores base + 0.35 (floor 0.4, cap 1.0) here - always >= the recognizer-level
expectation. Such cases are marked "context:" below.
"""
import json
import re
from pathlib import Path

from src.engine.recognizers.gb_es_it_tr import (
    RULES,
    _validate_es_nie,
    _validate_tr_license_plate,
    _validate_tr_national_id,
)
from src.engine.rules import run_rule

EPS = 1e-6
MAPPING_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "findings-mapping.json"


def _rule(name):
    for rule in RULES:
        if rule.name == name:
            return rule
    raise AssertionError(f"rule {name!r} not found in RULES")


def _spans(rule, text, field_name=None):
    """[(start, end, score), ...] for every finding of rule in text."""
    return [(r["start"], r["end"], r["score"]) for r in run_rule(rule, text, field_name)]


def _check(rule, text, expected, field_name=None):
    """
    expected: list of (start, end, score) tuples, one per expected finding in
    text order; an empty list means the text must not produce any finding.
    """
    found = _spans(rule, text, field_name)
    assert len(found) == len(expected), f"{rule.name} on {text!r}: expected {expected}, got {found}"
    for (start, end, score), (exp_start, exp_end, exp_score) in zip(found, expected):
        assert (start, end) == (exp_start, exp_end), f"{rule.name} on {text!r}: span {(start, end)} != {(exp_start, exp_end)}"
        assert abs(score - exp_score) < EPS, f"{rule.name} on {text!r}: score {score} != {exp_score}"


def _check_all(rule, valid, invalid):
    for text, expected in valid:
        _check(rule, text, expected)
    for text in invalid:
        _check(rule, text, [])


def _field_score(rule, value, field_name):
    found = run_rule(rule, value, field_name=field_name)
    assert len(found) == 1, f"{rule.name}: {value!r} with field {field_name!r} -> {found}"
    return found[0]["score"]


# --------------------------------------------------------------------------- #
# Rule metadata
# --------------------------------------------------------------------------- #

EXPECTED_RULES = {
    "UK_DRIVING_LICENCE": "GB",
    "UK_NHS": "GB",
    "GB NINO": "GB",
    "UK_PASSPORT": "GB",
    "UK_POSTCODE": "GB",
    "UK_VEHICLE_REGISTRATION": "GB",
    "ES_NIF": "ES",
    "ES_NIE": "ES",
    "ES_PASSPORT": "ES",
    "IT_FISCAL_CODE": "IT",
    "IT_IDENTITY_CARD": "IT",
    "IT_PASSPORT": "IT",
    "IT_DRIVER_LICENSE": "IT",
    "IT_VAT_CODE": "IT",
    "TR_NATIONAL_ID": "TR",
    "TR_LICENSE_PLATE": "TR",
}


def test_rules_present_with_regions():
    names = [rule.name for rule in RULES]
    assert sorted(names) == sorted(EXPECTED_RULES)
    assert len(names) == len(set(names))
    for rule in RULES:
        assert rule.region == EXPECTED_RULES[rule.name]
        assert rule.description
        assert rule.field_hint
        assert rule.patterns
        assert rule.context
        assert rule.enabled


def test_rules_match_findings_mapping():
    mapping = json.loads(MAPPING_PATH.read_text())[0]
    for rule in RULES:
        assert rule.name in mapping, f"{rule.name} is not a key of findings-mapping.json"
        entry = mapping[rule.name]
        assert rule.category == entry["category"], rule.name
        severity = "Low" if entry["final_risk_factor"] == "Lowest" else entry["final_risk_factor"]
        assert rule.severity == severity, rule.name


def test_examples_are_detected_by_their_own_rule():
    for rule in RULES:
        assert rule.examples, rule.name
        for example in rule.examples:
            found = run_rule(rule, example)
            assert len(found) == 1, f"{rule.name}: example {example!r} -> {found}"
            assert found[0]["value"] == example
            assert found[0]["score"] > 0


def test_field_hints_ignore_unrelated_columns():
    for rule in RULES:
        for column in ("customer_name", "email", "created_at", "description"):
            assert re.search(rule.field_hint, column) is None, f"{rule.name} hint matches {column!r}"


# --------------------------------------------------------------------------- #
# United Kingdom
# --------------------------------------------------------------------------- #

def test_uk_driving_licence():
    rule = _rule("UK_DRIVING_LICENCE")
    # upstream expects a score in [0.3, 0.5]; the check digits are not public so the
    # validator never confirms a licence and the pattern score (0.5) is kept.
    valid = [
        ("MORGA607054SM9IJ", [(0, 16, 0.5)]),                # male licence
        ("MORGA657054SM9IJ", [(0, 16, 0.5)]),                # female (month + 50)
        ("FO999512018AA1AB", [(0, 16, 0.5)]),                # padded surname
        ("SMIT9801015JK2CD", [(0, 16, 0.5)]),                # single-char padding
        ("Licence: MORGA607054SM9IJ ok", [(9, 25, 0.5)]),    # embedded in text
        ("morga607054sm9ij", [(0, 16, 0.5)]),                # lowercase
        ("JONES710153J99EF", [(0, 16, 0.5)]),                # no middle initial
        ("SMITH802290AB1CD", [(0, 16, 0.5)]),                # 29 February
        ("SMITH812310AB1CD", [(0, 16, 0.5)]),                # month 12
        ("SMITH851010AB1CD", [(0, 16, 0.5)]),                # month 51 (January, female)
        ("SMITH862310AB1CD", [(0, 16, 0.5)]),                # month 62 (December, female)
    ]
    invalid = [
        "MORGA600054SM9IJ",   # month 00
        "MORGA613054SM9IJ",   # month 13
        "MORGA650054SM9IJ",   # month 50
        "MORGA663054SM9IJ",   # month 63
        "MORGA601004SM9IJ",   # day 00
        "MORGA601324SM9IJ",   # day 32
        "MORGA65705SM9IJ",    # 15 characters
        "MORGA6570544SM9IJ",  # 17 characters
        "99999657054SM9IJ",   # all-9 surname (validator False)
        "MO9G9657054SM9IJ",   # 9 before a letter in the surname (validator False)
    ]
    _check_all(rule, valid, invalid)


def test_uk_driving_licence_field_name():
    rule = _rule("UK_DRIVING_LICENCE")
    for field in ("driver_license_number", "driving_licence", "dl_no", "dvla_number"):
        assert _field_score(rule, "MORGA607054SM9IJ", field) >= 0.85
    assert run_rule(rule, "99999657054SM9IJ", field_name="driving_licence") == []


def test_uk_nhs():
    rule = _rule("UK_NHS")
    valid = [
        ("401-023-2137", [(0, 12, 1.0)]),
        ("221 395 1837", [(0, 12, 1.0)]),
        ("0032698674", [(0, 10, 1.0)]),
    ]
    invalid = ["401-023-2138"]  # checksum failure
    _check_all(rule, valid, invalid)


def test_uk_nhs_field_name():
    rule = _rule("UK_NHS")
    for field in ("nhs_number", "nhs", "patient_nhs_no", "nhsNumber"):
        assert _field_score(rule, "0032698674", field) >= 0.85
    # a failed checksum is never rescued by the column name
    assert run_rule(rule, "401-023-2138", field_name="nhs_number") == []


def test_gb_nino():
    rule = _rule("GB NINO")
    valid = [
        ("AA 12 34 56 B", [(0, 13, 0.5)]),
        ("hh 01 02 03 d", [(0, 13, 0.5)]),
        ("tw987654a", [(0, 9, 0.5)]),
        ("nino: PR 123612C", [(6, 16, 0.85)]),                                     # context: "nino"
        ("Here is my National Insurance Number YZ 61 48 68 B", [(37, 50, 0.85)]),  # context: "national insurance"
        ("my AB123456C", [(3, 12, 0.5)]),                                          # span never starts at the space
        ("contact AB 12 34 56 C now", [(8, 21, 0.5)]),
    ]
    invalid = [
        "AA 12 34 56 H",   # suffix must be A-D
        "AB 12 34 56 1",   # numeric suffix
        "ab1234561",
        "FQ 00 00 00 C",   # F is not a valid first letter
        "BG123612A",       # excluded prefix
        "my BG123612A",
        "nino BG 12 36 12 A",
        "nino: nt 99 88 77 a",
        "This isn't a valid national insurance number UV 98 76 54 B",
    ]
    _check_all(rule, valid, invalid)


def test_gb_nino_field_name():
    rule = _rule("GB NINO")
    for field in ("nino", "national_insurance_number", "ni_number", "NationalInsuranceNo"):
        assert _field_score(rule, "AA 12 34 56 B", field) >= 0.85
    assert run_rule(rule, "BG123612A", field_name="nino") == []


def test_uk_passport():
    rule = _rule("UK_PASSPORT")
    valid = [
        ("AB1234567", [(0, 9, 0.1)]),
        ("XY9876543", [(0, 9, 0.1)]),
        ("ab1234567", [(0, 9, 0.1)]),
        ("My passport number is CD7654321 and it expires soon", [(22, 31, 0.45)]),  # context: "passport"
        ("Passports: AB1234567 and XY9876543", [(11, 20, 0.1), (25, 34, 0.1)]),     # "passports" is not a context word
    ]
    invalid = [
        "A12345678",        # 1 letter + 8 digits
        "ABC123456",        # 3 letters + 6 digits
        "AB123456",         # too short
        "AB12345678",       # too long
        "123456789",        # digits only (old format excluded)
        "AB 1234567",       # space in number
        "1234567AB",        # reversed
        "XYZAB1234567QRS",  # no word boundary
    ]
    _check_all(rule, valid, invalid)


def test_uk_passport_field_name():
    rule = _rule("UK_PASSPORT")
    for field in ("passport_no", "passport", "uk_passport_number", "passportNumber"):
        assert _field_score(rule, "AB1234567", field) >= 0.85


def test_uk_postcode():
    rule = _rule("UK_POSTCODE")
    valid = [
        ("M1 1AA", [(0, 6, 0.1)]),       # A9 9AA
        ("M60 1NW", [(0, 7, 0.1)]),      # A99 9AA
        ("W1A 1HQ", [(0, 7, 0.1)]),      # A9A 9AA
        ("CR2 6XH", [(0, 7, 0.1)]),      # AA9 9AA
        ("DN55 1PT", [(0, 8, 0.1)]),     # AA99 9AA
        ("EC1A 1BB", [(0, 8, 0.1)]),     # AA9A 9AA
        ("GIR 0AA", [(0, 7, 0.1)]),      # special
        ("M11AA", [(0, 5, 0.1)]),        # without space
        ("EC1A1BB", [(0, 7, 0.1)]),
        ("DN551PT", [(0, 7, 0.1)]),
        ("GIR0AA", [(0, 6, 0.1)]),
        ("My address is SW1A 1AA in London", [(14, 22, 0.45)]),   # context: "address"
        ("Send to postcode EC2A 1NT please", [(17, 25, 0.45)]),   # context: "postcode"
        ("From SW1A 1AA to EC1A 1BB", [(5, 13, 0.1), (17, 25, 0.1)]),
    ]
    invalid = [
        "QA1 1AA",      # Q in position 1
        "VA1 1AA",      # V in position 1
        "XA1 1AA",      # X in position 1
        "M1 1CA",       # C in inward code
        "M1 1AI",       # I in inward code
        "1A1 1AA",      # starts with digit
        "ABCM11AADEF",  # no word boundary
    ]
    _check_all(rule, valid, invalid)


def test_uk_postcode_field_name():
    rule = _rule("UK_POSTCODE")
    for field in ("post_code", "postcode", "postal_code", "billing_postcode", "postalCode"):
        assert _field_score(rule, "M1 1AA", field) >= 0.85


def test_uk_vehicle_registration():
    rule = _rule("UK_VEHICLE_REGISTRATION")
    valid = [
        # current format (2001+): validator confirms the age identifier -> 1.0
        ("AB51 ABC", [(0, 8, 1.0)]),
        ("BD62XYZ", [(0, 7, 1.0)]),
        ("LN14-HGT", [(0, 8, 1.0)]),
        ("aa02 aaa", [(0, 8, 1.0)]),
        ("My car reg is AB51 ABC and it expires", [(14, 22, 1.0)]),
        ("Vehicles AB51 ABC and BD62XYZ were seen", [(9, 17, 1.0), (22, 29, 1.0)]),
        ("AB70 DEF", [(0, 8, 1.0)]),
        # prefix format (1983-2001): validator None -> pattern score
        ("A123 BCD", [(0, 8, 0.2)]),
        ("K1 ABC", [(0, 6, 0.2)]),
        ("M456DEF", [(0, 7, 0.2)]),
        # suffix format (1963-1983)
        ("ABC 123D", [(0, 8, 0.15)]),
        ("ABC 1D", [(0, 6, 0.15)]),
        ("DEF456G", [(0, 7, 0.15)]),
    ]
    invalid = [
        "IB51 ABC",       # I in area code
        "AQ51 ABC",       # Q in area code
        "AB00 ABC",       # age id 00
        "AB35 ABC",       # age id in the 30-50 gap (validator False)
        "AB49 ABC",
        "AB80 ABC",       # age id 80+
        "AB51 AIB",       # I in random letters
        "I123 BCD",       # I as prefix year letter
        "O123 BCD",       # O as prefix year letter
        "ABC 123I",       # I as suffix year letter
        "ABC 123Z",       # Z as suffix year letter
        "hello world",
        "1234567890",
        "XXXAB51ABCYYY",  # no word boundary
    ]
    _check_all(rule, valid, invalid)


def test_uk_vehicle_registration_field_name():
    rule = _rule("UK_VEHICLE_REGISTRATION")
    for field in ("vehicle_reg", "number_plate", "licence_plate", "registration_no", "vrn"):
        assert _field_score(rule, "A123 BCD", field) >= 0.85
        assert _field_score(rule, "ABC 123D", field) >= 0.85
    assert run_rule(rule, "AB35 ABC", field_name="vehicle_reg") == []


# --------------------------------------------------------------------------- #
# Spain
# --------------------------------------------------------------------------- #

def test_es_nif():
    rule = _rule("ES_NIF")
    valid = [
        ("55555555K", [(0, 9, 1.0)]),
        ("55555555-K", [(0, 10, 1.0)]),
        ("1111111-G", [(0, 9, 1.0)]),
        ("1111111G", [(0, 8, 1.0)]),
        ("01111111G", [(0, 9, 1.0)]),
        ("55555555k", [(0, 9, 1.0)]),   # control letter upper-cased before the check
        ("12345678z", [(0, 9, 1.0)]),
        ("12345678Z", [(0, 9, 1.0)]),
    ]
    invalid = [
        "401-023-2138",
        "12345678a",  # wrong control letter, regardless of case
    ]
    _check_all(rule, valid, invalid)


def test_es_nif_field_name():
    rule = _rule("ES_NIF")
    for field in ("dni", "nif", "nif_cliente", "customer_dni"):
        assert _field_score(rule, "55555555K", field) >= 0.85
    assert run_rule(rule, "12345678a", field_name="dni") == []


def test_es_nie():
    rule = _rule("ES_NIE")
    valid = [
        ("Z8078221M", [(0, 9, 1.0)]),
        ("X9613851N", [(0, 9, 1.0)]),
        ("Y8063915Z", [(0, 9, 1.0)]),
        ("Y8063915-Z", [(0, 10, 1.0)]),
        ("Mi NIE es X9613851N", [(10, 19, 1.0)]),
        ("Z8078221M en mi NIE", [(0, 9, 1.0)]),
        ("Mi Número de identificación de extranjero es Y8063915-Z", [(45, 55, 1.0)]),
        ("x9613851n", [(0, 9, 1.0)]),   # prefix and control letter upper-cased before the check
        ("z8078221m", [(0, 9, 1.0)]),
    ]
    invalid = [
        "Y8063915Q",  # wrong control letter
        "Y806391Q",   # too short
        "58063915Q",  # prefix must be X, Y or Z
        "W8063915Q",
        "x9613851q",  # wrong control letter, lowercase
    ]
    _check_all(rule, valid, invalid)


def test_es_nie_validator_rejects_non_digit_middle():
    # upstream: a custom pattern letting letters through must be rejected, not crash
    assert _validate_es_nie("XABCDEFG") is False
    assert _validate_es_nie("X9613851N") is True
    assert _validate_es_nie("y8063915-z") is True


def test_es_nie_field_name():
    rule = _rule("ES_NIE")
    for field in ("nie", "nie_number", "numero_nie"):
        assert _field_score(rule, "X9613851N", field) >= 0.85
    assert run_rule(rule, "Y8063915Q", field_name="nie") == []


def test_es_passport():
    rule = _rule("ES_PASSPORT")
    valid = [
        ("AAA123456", [(0, 9, 0.05)]),
        ("XYZ987654", [(0, 9, 0.05)]),
        ("Mi pasaporte es AAA123456", [(16, 25, 0.4)]),               # context: "pasaporte"
        ("AAA123456 es mi número de pasaporte", [(0, 9, 0.05)]),      # "pasaporte" is beyond the 3-word suffix window
        ("aaa123456", [(0, 9, 0.05)]),
        ("xyz987654", [(0, 9, 0.05)]),
        ("Mi pasaporte es aaa123456", [(16, 25, 0.4)]),
        ("aaa123456 es mi número de pasaporte", [(0, 9, 0.05)]),
        ("AaA123456", [(0, 9, 0.05)]),
        ("XyZ987654", [(0, 9, 0.05)]),
        ("Mi pasaporte es AaA123456", [(16, 25, 0.4)]),
        ("AaA123456 es mi número de pasaporte", [(0, 9, 0.05)]),
    ]
    invalid = [
        "AA123456",   # 2-letter prefix
        "AAAA12345",  # 4-letter prefix
        "AAA12345",   # 5 digits
    ]
    _check_all(rule, valid, invalid)


def test_es_passport_field_name():
    rule = _rule("ES_PASSPORT")
    for field in ("pasaporte", "numero_pasaporte", "passport_number"):
        assert _field_score(rule, "AAA123456", field) >= 0.85


# --------------------------------------------------------------------------- #
# Italy
# --------------------------------------------------------------------------- #

def test_it_driver_license():
    rule = _rule("IT_DRIVER_LICENSE")
    # upstream expects a score in [0.1, 0.4]; the pattern score is 0.2
    valid = [
        ("AA0123456B", [(0, 10, 0.2)]),
        ("AA0123456B and AA0123456B", [(0, 10, 0.2), (15, 25, 0.2)]),
        ("U1H00B000C", [(0, 10, 0.2)]),
        ("U1K711J11M", [(0, 10, 0.2)]),                 # J and K are allowed (issue #1555)
        ("license U1K711J11M here", [(8, 18, 0.2)]),
    ]
    invalid = [
        "U1H00A000B",  # A is not allowed after the U1 prefix
        "990123456B",
    ]
    _check_all(rule, valid, invalid)


def test_it_driver_license_field_name():
    rule = _rule("IT_DRIVER_LICENSE")
    for field in ("patente", "numero_patente", "driver_license"):
        assert _field_score(rule, "AA0123456B", field) >= 0.85


def test_it_fiscal_code():
    rule = _rule("IT_FISCAL_CODE")
    valid = [
        ("AAAAAA00B11C333Y", [(0, 16, 1.0)]),   # valid check character -> validator True
        ("AAAAAA00B11C333N", [(0, 16, 0.3)]),   # wrong check character -> validator None keeps 0.3
        ("AAAAAA00B11C333Y and AAAAAA00B11C333N", [(0, 16, 1.0), (21, 37, 0.3)]),
    ]
    invalid = [
        "AAAAAA - 00B11C333N",
        "A55AAA00B11C333N",
    ]
    _check_all(rule, valid, invalid)


def test_it_fiscal_code_field_name():
    rule = _rule("IT_FISCAL_CODE")
    for field in ("codice_fiscale", "fiscal_code", "cf", "cf_cliente", "codiceFiscale"):
        assert _field_score(rule, "AAAAAA00B11C333N", field) >= 0.85


def test_it_identity_card():
    rule = _rule("IT_IDENTITY_CARD")
    # upstream expects a score in [0.0, 0.05]; every pattern scores 0.01
    valid = [
        ("AA1234567 aa 1234567", [(0, 9, 0.01), (10, 20, 0.01)]),  # paper-based
        ("1234567Aa", [(0, 9, 0.01)]),                             # CIE 2.0
        ("AA12345aa", [(0, 9, 0.01)]),                             # CIE 3.0
    ]
    _check_all(rule, valid, [])


def test_it_identity_card_field_name():
    rule = _rule("IT_IDENTITY_CARD")
    for field in ("identity_card_no", "carta_identita", "id_card", "cie", "cartaIdentita"):
        assert _field_score(rule, "AA1234567", field) >= 0.85
        assert _field_score(rule, "1234567AA", field) >= 0.85


def test_it_passport():
    rule = _rule("IT_PASSPORT")
    valid = [
        ("AA1234567", [(0, 9, 0.01)]),
        ("aa7654321", [(0, 9, 0.01)]),
    ]
    _check_all(rule, valid, [])


def test_it_passport_field_name():
    rule = _rule("IT_PASSPORT")
    for field in ("passaporto", "numero_passaporto", "passport_no"):
        assert _field_score(rule, "AA1234567", field) >= 0.85


def test_it_vat_code():
    rule = _rule("IT_VAT_CODE")
    # upstream expects a score in [0.9, 1.0]; the validator confirms -> 1.0
    valid = [
        ("01333550323", [(0, 11, 1.0)]),
        ("00000000000 and 01333550323", [(16, 27, 1.0)]),  # only the second one is valid
        ("01333550_323", [(0, 12, 1.0)]),                  # "_" is stripped before the check
    ]
    invalid = [
        "00000000000",  # passes the checksum but is rejected explicitly
        "00000000001",
    ]
    _check_all(rule, valid, invalid)


def test_it_vat_code_field_name():
    rule = _rule("IT_VAT_CODE")
    for field in ("partita_iva", "piva", "p_iva", "vat_number", "vat"):
        assert _field_score(rule, "01333550323", field) >= 0.85
    assert run_rule(rule, "00000000001", field_name="partita_iva") == []


# --------------------------------------------------------------------------- #
# Turkey
# --------------------------------------------------------------------------- #

def test_tr_national_id():
    rule = _rule("TR_NATIONAL_ID")
    # upstream expects a score in [0.5, 1.0]; the checksum validator confirms -> 1.0
    valid = [
        ("10000000146", [(0, 11, 1.0)]),
        ("76543210794", [(0, 11, 1.0)]),
        ("36493665440", [(0, 11, 1.0)]),
        ("53857632436", [(0, 11, 1.0)]),
        ("94357219628", [(0, 11, 1.0)]),
        ("79059236630", [(0, 11, 1.0)]),
        ("64625294480", [(0, 11, 1.0)]),
        ("TC Kimlik No: 10000000146", [(14, 25, 1.0)]),
        ("Başvuru sahibinin TCKN numarası 10000000146 olarak tescil edilmiştir.", [(32, 43, 1.0)]),
        ("Birinci kişi: 10000000146, ikinci kişi: 76543210794", [(14, 25, 1.0), (40, 51, 1.0)]),
        ("Turkish ID 10000000146", [(11, 22, 1.0)]),
        ("Türk kimlik numarası 36493665440", [(21, 32, 1.0)]),
    ]
    invalid = [
        "00000000000",   # first digit 0
        "02531814694",
        "12345678900",   # wrong 10th digit
        "76543210780",
        "83219500748",
        "11798724308",
        "10000000145",   # wrong 11th digit
        "62286775983",
        "97485249605",
        "1234567890",    # 10 digits
        "123456789012",  # 12 digits
        "abcdefghijk",
    ]
    _check_all(rule, valid, invalid)


def test_tr_national_id_validator():
    for tckn in ("10000000146", "76543210794", "36493665440", "53857632436", "94357219628", "79059236630", "64625294480"):
        assert _validate_tr_national_id(tckn) is True
    for tckn in ("00000000000", "02531814694", "12345678900", "76543210780", "83219500748", "11798724308",
                 "10000000145", "62286775983", "97485249605", "1234567890", "123456789012", "abcdefghijk"):
        assert _validate_tr_national_id(tckn) is False


def test_tr_national_id_field_name():
    rule = _rule("TR_NATIONAL_ID")
    for field in ("tc_kimlik_no", "tckn", "kimlik_no", "national_id", "tc_no", "tcKimlikNo"):
        assert _field_score(rule, "10000000146", field) >= 0.85
    assert run_rule(rule, "12345678900", field_name="tckn") == []


def test_tr_license_plate():
    rule = _rule("TR_LICENSE_PLATE")
    # upstream expects a score in [0.5, 1.0]; the province-code validator confirms -> 1.0
    valid = [
        ("34 ABC 1234", [(0, 11, 1.0)]),
        ("06 A 123", [(0, 8, 1.0)]),
        ("35 JK 12", [(0, 8, 1.0)]),
        ("16 B 1234", [(0, 9, 1.0)]),
        ("34ABC1234", [(0, 9, 1.0)]),
        ("34 abc 1234", [(0, 11, 1.0)]),
        ("Araç plakası 34 ABC 1234 olarak kayıtlıdır.", [(13, 24, 1.0)]),
        ("Plaka 34 ABC 1234 ve 06 JK 567", [(6, 17, 1.0), (21, 30, 1.0)]),
        ("01 A 12", [(0, 7, 1.0)]),
        ("81 A 12", [(0, 7, 1.0)]),
        ("07 AB 123", [(0, 9, 1.0)]),
        ("License plate 34 ABC 1234", [(14, 25, 1.0)]),
        ("Plaka numarası 06 A 123 olarak kayıtlı", [(15, 23, 1.0)]),
        ("34-ABC-1234", [(0, 11, 1.0)]),   # hyphen pattern
    ]
    invalid = [
        "00 ABC 123",  # province 00
        "82 ABC 123",  # province > 81
        "99 ABC 123",
        "hello world",
        "1234567890",
    ]
    _check_all(rule, valid, invalid)


def test_tr_license_plate_validator():
    assert _validate_tr_license_plate("34 ABC 1234") is True
    assert _validate_tr_license_plate("06 A 123") is True
    assert _validate_tr_license_plate("01 A 12") is True
    assert _validate_tr_license_plate("81 A 12") is True
    assert _validate_tr_license_plate("00 ABC 123") is False
    assert _validate_tr_license_plate("82 ABC 123") is False
    assert _validate_tr_license_plate("12") is None       # shorter than 3 characters
    assert _validate_tr_license_plate("") is None
    assert _validate_tr_license_plate("AB ABC 123") is None  # non-numeric province code
    assert _validate_tr_license_plate("XY 123") is None


def test_tr_license_plate_field_name():
    rule = _rule("TR_LICENSE_PLATE")
    for field in ("plaka", "arac_plaka", "license_plate", "number_plate", "plakaNo"):
        assert _field_score(rule, "34 ABC 1234", field) >= 0.85
