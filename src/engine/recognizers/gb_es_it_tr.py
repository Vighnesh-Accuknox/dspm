"""
upstream-ported rules for the United Kingdom (GB), Spain (ES), Italy (IT) and
Turkey (TR).

Source (MIT): upstream analyzer/predefined_recognizers/country_specific/
{uk,spain,italy,turkey}. Pattern names, regexes, scores and CONTEXT lists are
copied verbatim; each recognizer's validate_result() is ported as a
module-private function that applies the same replacement pairs before
checking. Detector names are keys of fixtures/findings-mapping.json; the upstream recognizer's
UK_NINO is reported under the pre-existing engine name "GB NINO".

Deviations from the source:
  * IT_DRIVER_LICENSE: the upstream recognizer's regex carries an inline "(?i)" after the
    leading "\\b". Python's re only accepts global flags at the start of the
    expression, so the flag is moved to position 0 (no semantic change: every
    pattern is compiled with IGNORECASE anyway).
  * Validators guard against inputs the regexes can never produce (empty digit
    strings, unexpected characters) instead of raising.
  * field_hint regexes use (?<![a-z]) / (?![a-z]) instead of \\b so that
    snake_case column names such as "nhs_number" match ("_" is a word char).
"""
import re
from typing import List, Optional

from src.engine.rules import Pattern, Rule
from src.engine.validators import digits_only, sanitize

# the upstream recognizer's default replacement_pairs for the recognizers that sanitise input
_DASH_SPACE = (("-", ""), (" ", ""))


# --------------------------------------------------------------------------- #
# United Kingdom
# --------------------------------------------------------------------------- #

_UK_DL_SURNAME_RE = re.compile(r"^[A-Z]+9*$")


def _validate_uk_driving_licence(text: str) -> Optional[bool]:
    """
    The DVLA check-digit algorithm is not public, so a licence can never be
    confirmed (None); clearly invalid surname blocks are rejected (False).
    """
    text = text.upper()
    # Reject if surname portion is all 9s (no valid surname)
    if text[:5] == "99999":
        return False
    # Surname must have letters before any 9-padding (9s only trailing)
    if not _UK_DL_SURNAME_RE.match(text[:5]):
        return False
    return None


def _validate_uk_nhs(text: str) -> bool:
    """NHS modulus 11: sum(digit * weight) over weights 10..1 must be divisible by 11."""
    text = sanitize(text, _DASH_SPACE)
    if not text.isdigit():
        return False
    total = sum(int(c) * multiplier for c, multiplier in zip(text, reversed(range(11))))
    return total % 11 == 0


def _validate_uk_vehicle_registration(text: str) -> Optional[bool]:
    """
    Current (2001+) format only: the two-digit age identifier must be 02-29
    (March) or 51-79 (September). Prefix / suffix formats return None.
    """
    sanitized_value = sanitize(text, _DASH_SPACE)
    # Current format is exactly 7 chars after sanitization
    if len(sanitized_value) == 7 and sanitized_value[:2].isalpha():
        age_id_str = sanitized_value[2:4]
        if age_id_str.isdigit():
            age_id = int(age_id_str)
            return (2 <= age_id <= 29) or (51 <= age_id <= 79)
    return None


# --------------------------------------------------------------------------- #
# Spain
# --------------------------------------------------------------------------- #

_ES_CONTROL_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"  # pragma: allowlist secret


def _validate_es_nif(text: str) -> bool:
    """NIF / DNI: control letter = TRWAGMYFPDXBNJZSQVHLCKE[number mod 23]."""
    text = sanitize(text, _DASH_SPACE).upper()
    digits = digits_only(text)
    if not text or not digits:
        return False
    letter = text[-1]
    return letter == _ES_CONTROL_LETTERS[int(digits) % 23]


def _validate_es_nie(text: str) -> bool:
    """NIE: X/Y/Z prefix counts as 0/1/2, then the same mod-23 control letter as the NIF."""
    text = sanitize(text, _DASH_SPACE).upper()
    if not text:
        return False
    letter = text[-1]
    # check last is a letter, and first is in X,Y,Z
    if not text[1:-1].isdigit() or text[:1] not in "XYZ":
        return False
    # check size is 8 or 9
    if len(text) < 8 or len(text) > 9:
        return False
    # replace XYZ with 012, and check the mod 23
    number = int(str("XYZ".index(text[0])) + text[1:-1])
    return letter == _ES_CONTROL_LETTERS[number % 23]


# --------------------------------------------------------------------------- #
# Italy
# --------------------------------------------------------------------------- #

# Codice fiscale check character tables (the upstream recognizer's map_odd / map_even / map_mod)
_IT_CF_ODD = {
    "0": 1, "1": 0, "2": 5, "3": 7, "4": 9, "5": 13, "6": 15, "7": 17, "8": 19, "9": 21,
    "A": 1, "B": 0, "C": 5, "D": 7, "E": 9, "F": 13, "G": 15, "H": 17, "I": 19, "J": 21,
    "K": 2, "L": 4, "M": 18, "N": 20, "O": 11, "P": 3, "Q": 6, "R": 8, "S": 12, "T": 14,
    "U": 16, "V": 10, "W": 22, "X": 25, "Y": 24, "Z": 23,
}
_IT_CF_EVEN = {
    "0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9,
    "A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5, "G": 6, "H": 7, "I": 8, "J": 9,
    "K": 10, "L": 11, "M": 12, "N": 13, "O": 14, "P": 15, "Q": 16, "R": 17, "S": 18,
    "T": 19, "U": 20, "V": 21, "W": 22, "X": 23, "Y": 24, "Z": 25,
}
_IT_CF_CHECK = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # map_mod: 0 -> A ... 25 -> Z


def _validate_it_fiscal_code(text: str) -> Optional[bool]:
    """
    Codice fiscale check character. upstream returns True when it matches and
    None (not False) otherwise, so a wrong check character keeps the base score.
    """
    text = text.upper()
    if not text:
        return None
    control = text[-1]
    text_to_validate = text[:-1]
    try:
        odd_sum = sum(_IT_CF_ODD[char] for char in text_to_validate[0::2])
        even_sum = sum(_IT_CF_EVEN[char] for char in text_to_validate[1::2])
    except KeyError:
        return None
    check_value = _IT_CF_CHECK[(odd_sum + even_sum) % 26]
    return True if check_value == control else None


_IT_VAT_PAIRS = (("-", ""), (" ", ""), ("_", ""))


def _validate_it_vat_code(text: str) -> bool:
    """Partita IVA: Luhn-style check digit over 11 digits; the all-zero code is rejected."""
    text = sanitize(text, _IT_VAT_PAIRS)
    # Edge-case that passes the checksum even though it is not a valid italian vat code
    if text == "00000000000":
        return False
    if len(text) != 11 or not text.isdigit():
        return False
    x = 0
    y = 0
    for i in range(0, 5):
        x += int(text[2 * i])
        tmp_y = int(text[2 * i + 1]) * 2
        if tmp_y > 9:
            tmp_y = tmp_y - 9
        y += tmp_y
    t = (x + y) % 10
    c = (10 - t) % 10
    return c == int(text[10])


# --------------------------------------------------------------------------- #
# Turkey
# --------------------------------------------------------------------------- #


def _validate_tr_license_plate(text: str) -> Optional[bool]:
    """Province code (first two characters) must be 01-81; None when it is not numeric."""
    sanitized_value = sanitize(text, _DASH_SPACE)
    if len(sanitized_value) >= 3:
        province_code = sanitized_value[:2]
        if province_code.isdigit():
            code = int(province_code)
            return 1 <= code <= 81
    return None


def _validate_tr_national_id(text: str) -> bool:
    """
    TCKN (official NVI algorithm): 11 digits, first digit non-zero,
    10th digit = (7 * sum(odd positions) - sum(even positions)) mod 10,
    11th digit = sum(first ten digits) mod 10.
    """
    sanitized_value = sanitize(text, ())  # the upstream recognizer's default replacement_pairs is empty
    if len(sanitized_value) != 11 or not sanitized_value.isdigit():
        return False
    if sanitized_value[0] == "0":
        return False
    digits = [int(d) for d in sanitized_value]
    odd_sum = sum(digits[i] for i in range(0, 9, 2))
    even_sum = sum(digits[i] for i in range(1, 8, 2))
    tenth = (odd_sum * 7 - even_sum) % 10
    if tenth != digits[9]:
        return False
    eleventh = sum(digits[:10]) % 10
    return eleventh == digits[10]


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

UK_DRIVING_LICENCE = Rule(
    name="UK_DRIVING_LICENCE",
    category="Regional Compliance",
    severity="High",
    region="GB",
    description="UK DVLA driving licence number (16 characters encoding surname, date of birth and initials).",
    patterns=[
        Pattern(
            "UK Driving Licence",
            r"\b[A-Z9]{5}[0-9](?:0[1-9]|1[0-2]|5[1-9]|6[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9][A-Z9]{2}[A-Z0-9][A-Z]{2}\b",  # noqa: E501
            0.5,
        ),
    ],
    context=[
        "driving licence",
        "driving license",
        "driver's licence",
        "driver's license",
        "dvla",
        "dl number",
        "licence number",
        "license number",
    ],
    validator=_validate_uk_driving_licence,
    field_hint=r"driv(er|ing)_?licen[cs]e|(?<![a-z])dl_?(num|no)|dvla",
    examples=("MORGA607054SM9IJ", "FO999512018AA1AB"),
)

UK_NHS = Rule(
    name="UK_NHS",
    category="Healthcare Data (PHI)",
    severity="High",
    region="GB",
    description="UK NHS number (10 digits with a modulus-11 check digit).",
    patterns=[
        Pattern(
            "NHS (medium)",
            r"\b([0-9]{3})[- ]?([0-9]{3})[- ]?([0-9]{4})\b",
            0.5,
        ),
    ],
    context=[
        "national health service",
        "nhs",
        "health services authority",
        "health authority",
    ],
    validator=_validate_uk_nhs,
    field_hint=r"(?<![a-z])nhs(?![a-z])|nhs_?(num|no|id)",
    examples=("401-023-2137", "221 395 1837", "0032698674"),
)

GB_NINO = Rule(
    name="GB NINO",
    category="Regional Compliance",
    severity="High",
    region="GB",
    description="UK National Insurance number (two prefix letters, six digits, suffix letter A-D).",
    patterns=[
        Pattern(
            "NINO (medium)",
            r"\b(?!bg|gb|nk|kn|nt|tn|zz|BG|GB|NK|KN|NT|TN|ZZ)([a-ceghj-pr-tw-zA-CEGHJ-PR-TW-Z]{1}[a-ceghj-npr-tw-zA-CEGHJ-NPR-TW-Z]{1}) ?([0-9]{2}) ?([0-9]{2}) ?([0-9]{2}) ?([a-dA-D]{1})\b",  # noqa: E501
            0.5,
        ),
    ],
    context=["national insurance", "ni number", "nino"],
    field_hint=r"(?<![a-z])nino(?![a-z])|national_?insurance|(?<![a-z])ni_?(num|no)",
    examples=("AA 12 34 56 B", "PR 123612C", "tw987654a"),
)

UK_PASSPORT = Rule(
    name="UK_PASSPORT",
    category="Regional Compliance",
    severity="High",
    region="GB",
    description="UK passport number (two letters followed by seven digits, 2015+ format).",
    patterns=[
        Pattern(
            "UK Passport (weak)",
            r"\b[A-Z]{2}\d{7}\b",
            0.1,
        ),
    ],
    context=[
        "passport",
        "passport number",
        "travel document",
        "uk passport",
        "british passport",
        "her majesty",
        "his majesty",
        "hm passport",
        "hmpo",
    ],
    field_hint=r"passport",
    examples=("AB1234567", "XY9876543"),  # pragma: allowlist secret
)

UK_POSTCODE = Rule(
    name="UK_POSTCODE",
    category="PII",
    severity="Low",
    region="GB",
    description="UK postcode (A9 9AA, A99 9AA, A9A 9AA, AA9 9AA, AA99 9AA, AA9A 9AA and GIR 0AA).",
    patterns=[
        Pattern(
            "UK Postcode",
            r"\b("
            r"GIR\s?0AA"
            r"|[A-PR-UWYZ][0-9][ABCDEFGHJKPSTUW]?\s?[0-9][ABD-HJLNP-UW-Z]{2}"
            r"|[A-PR-UWYZ][0-9]{2}\s?[0-9][ABD-HJLNP-UW-Z]{2}"
            r"|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRVWXY]?\s?[0-9][ABD-HJLNP-UW-Z]{2}"
            r"|[A-PR-UWYZ][A-HK-Y][0-9]{2}\s?[0-9][ABD-HJLNP-UW-Z]{2}"
            r")\b",
            0.1,
        ),
    ],
    context=[
        "postcode",
        "post code",
        "postal code",
        "zip",
        "address",
        "delivery",
        "mailing",
        "shipping",
        "correspondence",
    ],
    field_hint=r"post_?code|postal_?code",
    examples=("SW1A 1AA", "M1 1AA", "EC1A 1BB"),
)

UK_VEHICLE_REGISTRATION = Rule(
    name="UK_VEHICLE_REGISTRATION",
    category="Regional Compliance",
    severity="Medium",
    region="GB",
    description="UK vehicle registration mark (current 2001+, prefix 1983-2001 and suffix 1963-1983 formats).",
    patterns=[
        Pattern(
            "UK Vehicle Registration (current)",
            r"\b[A-HJ-PR-Y][A-HJ-PR-Y](?:0[1-9]|[1-7][0-9])[- ]?[A-HJ-PR-Z]{3}\b",
            0.3,
        ),
        Pattern(
            "UK Vehicle Registration (prefix)",
            r"\b[A-HJ-NPR-TV-Y]\d{1,3}[- ]?[A-HJ-PR-Y][A-HJ-PR-Z]{2}\b",
            0.2,
        ),
        Pattern(
            "UK Vehicle Registration (suffix)",
            r"\b[A-HJ-PR-Z]{3}[- ]?\d{1,3}[- ]?[A-HJ-NPR-TV-Y]\b",
            0.15,
        ),
    ],
    context=[
        "vehicle",
        "registration",
        "number plate",
        "licence plate",
        "license plate",
        "reg",
        "vrn",
        "dvla",
        "v5c",
        "logbook",
        "mot",
        "car",
        "insured vehicle",
    ],
    validator=_validate_uk_vehicle_registration,
    field_hint=r"vehicle_?reg|number_?plate|licen[cs]e_?plate|registration_?(num|no)|(?<![a-z])vrn(?![a-z])",
    examples=("AB51 ABC", "A123 BCD", "ABC 123D"),
)

ES_NIF = Rule(
    name="ES_NIF",
    category="Regional Compliance",
    severity="Critical",
    region="ES",
    description="Spanish NIF / DNI (7-8 digits plus a mod-23 control letter).",
    patterns=[
        Pattern(
            "NIF",
            r"\b[0-9]?[0-9]{7}[-]?[A-Z]\b",
            0.5,
        ),
    ],
    context=["documento nacional de identidad", "DNI", "NIF", "identificación"],
    validator=_validate_es_nif,
    field_hint=r"(?<![a-z])(nif|dni)(?![a-z])",
    examples=("55555555K", "12345678Z", "1111111-G"),
)

ES_NIE = Rule(
    name="ES_NIE",
    category="Regional Compliance",
    severity="High",
    region="ES",
    description="Spanish NIE foreigner identification number (X/Y/Z prefix, 7 digits, mod-23 control letter).",
    patterns=[
        Pattern(
            "NIE",
            r"\b[X-Z]?[0-9]?[0-9]{7}[-]?[A-Z]\b",
            0.5,
        ),
    ],
    context=["número de identificación de extranjero", "NIE"],
    validator=_validate_es_nie,
    field_hint=r"(?<![a-z])nie(?![a-z])",
    examples=("X9613851N", "Y8063915-Z", "Z8078221M"),
)

ES_PASSPORT = Rule(
    name="ES_PASSPORT",
    category="Regional Compliance",
    severity="High",
    region="ES",
    description="Spanish passport number (three letters followed by six digits).",
    patterns=[
        Pattern(
            "ES_PASSPORT",
            r"\b[A-Z]{3}[0-9]{6}\b",
            0.05,
        ),
    ],
    context=["pasaporte", "passport", "número de pasaporte", "passport number"],
    field_hint=r"passport|pasaporte",
    examples=("AAA123456", "XYZ987654"),
)

IT_FISCAL_CODE = Rule(
    name="IT_FISCAL_CODE",
    category="Regional Compliance",
    severity="Critical",
    region="IT",
    description="Italian codice fiscale (16-character tax code with a check character).",
    patterns=[
        Pattern(
            "Fiscal Code",
            (
                r"(?i)((?:[A-Z][AEIOU][AEIOUX]|[AEIOU]X{2}"
                r"|[B-DF-HJ-NP-TV-Z]{2}[A-Z]){2}"
                r"(?:[\dLMNP-V]{2}(?:[A-EHLMPR-T](?:[04LQ][1-9MNP-V]|[15MR][\dLMNP-V]"
                r"|[26NS][0-8LMNP-U])|[DHPS][37PT][0L]|[ACELMRT][37PT][01LM]"
                r"|[AC-EHLMPR-T][26NS][9V])|(?:[02468LNQSU][048LQU]"
                r"|[13579MPRTV][26NS])B[26NS][9V])(?:[A-MZ][1-9MNP-V][\dLMNP-V]{2}"
                r"|[A-M][0L](?:[1-9MNP-V][\dLMNP-V]|[0L][1-9MNP-V]))[A-Z])"
            ),
            0.3,
        ),
    ],
    context=["codice fiscale", "cf"],
    validator=_validate_it_fiscal_code,
    field_hint=r"codice_?fiscale|fiscal_?code|(?<![a-z])cf(?![a-z])",
    examples=("AAAAAA00B11C333Y",),
)

IT_IDENTITY_CARD = Rule(
    name="IT_IDENTITY_CARD",
    category="Regional Compliance",
    severity="High",
    region="IT",
    description="Italian identity card number (paper-based, CIE 2.0 and CIE 3.0 formats).",
    patterns=[
        Pattern(
            "Paper-based Identity Card (very weak)",
            # The number is composed of 2 letters, space (optional), 7 digits
            r"(?i)\b[A-Z]{2}\s?\d{7}\b",
            0.01,
        ),
        Pattern(
            "Electronic Identity Card (CIE) 2.0 (very weak)",
            r"(?i)\b\d{7}[A-Z]{2}\b",
            0.01,
        ),
        Pattern(
            "Electronic Identity Card (CIE) 3.0 (very weak)",
            r"(?i)\b[A-Z]{2}\d{5}[A-Z]{2}\b",
            0.01,
        ),
    ],
    context=[
        "carta",
        "identità",
        "elettronica",
        "cie",
        "documento",
        "riconoscimento",
        "espatrio",
    ],
    field_hint=r"carta_?(d_?)?identit|identity_?card|(?<![a-z])id_?card|(?<![a-z])cie(?![a-z])",
    examples=("AA1234567", "1234567AA", "AA12345AA"),
)

IT_PASSPORT = Rule(
    name="IT_PASSPORT",
    category="Regional Compliance",
    severity="High",
    region="IT",
    description="Italian passport number (two letters followed by seven digits).",
    patterns=[
        Pattern(
            "Passport (very weak)",
            r"(?i)\b[A-Z]{2}\d{7}\b",
            0.01,
        ),
    ],
    context=[
        "passaporto",
        "elettronico",
        "italiano",
        "viaggio",
        "viaggiare",
        "estero",
        "documento",
        "dogana",
    ],
    field_hint=r"passport|passaporto",
    examples=("AA1234567",),
)

IT_DRIVER_LICENSE = Rule(
    name="IT_DRIVER_LICENSE",
    category="Regional Compliance",
    severity="High",
    region="IT",
    description="Italian driving licence number (two letters + 7 digits + letter, or U1 + 7 alphanumerics + letter).",
    patterns=[
        Pattern(
            "Driver License",
            # upstream: r"\b(?i)(...)\b" - the inline flag is moved to the start for Python's re
            (
                r"(?i)\b(([A-Z]{2}\d{7}[A-Z])"
                r"|(U1[BCDEFGHLJKMNPRSTUWYXZ0-9]{7}[A-Z]))\b"
            ),
            0.2,
        ),
    ],
    context=["patente", "patente di guida", "licenza", "licenza di guida"],
    field_hint=r"patente|driv(er|ing)_?licen[cs]e",
    examples=("AA0123456B", "U1H00B000C", "U1K711J11M"),  # pragma: allowlist secret
)

IT_VAT_CODE = Rule(
    name="IT_VAT_CODE",
    category="Regional Compliance",
    severity="Low",
    region="IT",
    description="Italian VAT number / partita IVA (11 digits with a Luhn-style check digit).",
    patterns=[
        Pattern(
            "IT Vat code (piva)",
            r"\b([0-9][ _]?){11}\b",
            0.1,
        ),
    ],
    context=["piva", "partita iva", "pi"],
    validator=_validate_it_vat_code,
    field_hint=r"partita_?iva|(?<![a-z])p_?iva(?![a-z])|(?<![a-z])vat(?![a-z])|vat_?(num|no|id|code)",
    examples=("01333550323",),
)

TR_NATIONAL_ID = Rule(
    name="TR_NATIONAL_ID",
    category="Regional Compliance",
    severity="Critical",
    region="TR",
    description="Turkish national identification number / TC Kimlik No (11 digits, NVI checksum).",
    patterns=[
        Pattern(
            "TR_NATIONAL_ID",
            r"\b[1-9][0-9]{10}\b",
            0.3,
        ),
    ],
    context=[
        "tc kimlik",
        "kimlik no",
        "kimlik numarası",
        "tckn",
        "tc no",
        "nüfus cüzdanı",
        "national id",
        "turkish id",
        "türk kimlik",
    ],
    validator=_validate_tr_national_id,
    field_hint=r"(?<![a-z])tc_?(kimlik|no)|kimlik|national_?id|tckn",
    examples=("10000000146", "76543210794", "36493665440"),
)

TR_LICENSE_PLATE = Rule(
    name="TR_LICENSE_PLATE",
    category="Regional Compliance",
    severity="Medium",
    region="TR",
    description="Turkish vehicle licence plate (province code 01-81, 1-3 letters, 2-4 digits).",
    patterns=[
        Pattern(
            "TR License Plate (space)",
            r"\b(0[1-9]|[1-7][0-9]|8[0-1])\s?[A-PR-VY-Z]{1,3}\s?\d{2,4}\b",
            0.3,
        ),
        Pattern(
            "TR License Plate (hyphen)",
            r"\b(0[1-9]|[1-7][0-9]|8[0-1])-[A-PR-VY-Z]{1,3}-\d{2,4}\b",
            0.3,
        ),
    ],
    context=[
        "plaka",
        "araç plakası",
        "plaka numarası",
        "kayıt plakası",
        "tr plaka",
        "license plate",
        "number plate",
        "plate",
        "taşıt plakası",
        "kayıt",
    ],
    validator=_validate_tr_license_plate,
    field_hint=r"plaka|licen[cs]e_?plate|number_?plate",
    examples=("34 ABC 1234", "06 A 123", "35 JK 12"),
)

RULES: List[Rule] = [
    # United Kingdom
    UK_DRIVING_LICENCE,
    UK_NHS,
    GB_NINO,
    UK_PASSPORT,
    UK_POSTCODE,
    UK_VEHICLE_REGISTRATION,
    # Spain
    ES_NIF,
    ES_NIE,
    ES_PASSPORT,
    # Italy
    IT_FISCAL_CODE,
    IT_IDENTITY_CARD,
    IT_PASSPORT,
    IT_DRIVER_LICENSE,
    IT_VAT_CODE,
    # Turkey
    TR_NATIONAL_ID,
    TR_LICENSE_PLATE,
]
