"""
upstream recognizers for India, Singapore, Australia, South Korea and Thailand
expressed as src.engine.rules.Rule objects.

Ported from upstream-analyzer (MIT, the upstream analyzer project)
upstream analyzer/predefined_recognizers/country_specific/{india,singapore,
australia,korea,thai}/. Pattern names, regexes, scores, context words and the
validate_result logic (including replacement_pairs sanitisation) are kept
verbatim; only the plumbing (PatternRecognizer -> Rule) changes.

Validators follow the upstream recognizer's contract: True -> score 1.0, False -> match
dropped, None -> pattern score kept.
"""
import re
from datetime import date
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from src.engine.rules import Pattern, Rule
from src.engine.validators import is_palindrome, sanitize, verhoeff_check

Pairs = Sequence[Tuple[str, str]]


def _codes(*spans: Tuple[int, int], width: int = 2) -> FrozenSet[str]:
    """{"01", ..., "NN"} for each inclusive (lo, hi) span, zero-padded to width."""
    out = set()
    for lo, hi in spans:
        out.update(str(n).zfill(width) for n in range(lo, hi + 1))
    return frozenset(out)


# =============================================================================
# India
# =============================================================================

# --- in_aadhaar_recognizer.py -------------------------------------------------
_IN_AADHAAR_PAIRS: Pairs = (("-", ""), (" ", ""), (":", ""))


def _validate_in_aadhaar(text: str) -> bool:
    """12 digits, first digit >= 2, Verhoeff check digit, not a palindrome."""
    value = sanitize(text, _IN_AADHAAR_PAIRS)
    return (
        len(value) == 12
        and value.isnumeric()
        and int(value[0]) >= 2
        and verhoeff_check(value)
        and not is_palindrome(value)
    )


# --- in_gstin_recognizer.py ---------------------------------------------------
_IN_GSTIN_PAIRS: Pairs = (("-", ""), (" ", ""))
# the upstream recognizer's _sanitize_value first tries to extract a strict GSTIN from the
# upper-cased text (plain `re`, no flags), falling back to replacement pairs.
_IN_GSTIN_STRICT_RE = re.compile(
    r"\b((?:0[1-9]|[1-3][0-7])[A-Za-z]{5}[0-9]{4}[A-Za-z]{1}"
    r"[0-9A-Za-z]{1}Z[0-9A-Za-z]{1})\b",
)


def _sanitize_in_gstin(text: str) -> str:
    match = _IN_GSTIN_STRICT_RE.search(text.upper())
    if match:
        return match.group(1)
    return sanitize(text.upper(), _IN_GSTIN_PAIRS)


def _validate_in_gstin_pan_format(pan: str) -> bool:
    """PAN inside a GSTIN: >=3 letters in the first 5, then 4 digits, then a letter."""
    if len(pan) != 10:
        return False
    if sum(1 for c in pan[:5] if c.isalpha()) < 3:
        return False
    if not pan[5:9].isdigit():
        return False
    if not pan[9].isalpha():
        return False
    return True


def _validate_in_gstin(text: str) -> bool:
    gstin = _sanitize_in_gstin(text)
    if len(gstin) != 15:
        return False
    state_code = gstin[:2]
    if not state_code.isdigit() or not (1 <= int(state_code) <= 37):
        return False
    if not _validate_in_gstin_pan_format(gstin[2:12]):
        return False
    if not gstin[12].isalnum():
        return False
    if gstin[13] != "Z":
        return False
    if not gstin[14].isalnum():
        return False
    return True


# --- in_vehicle_registration_recognizer.py -----------------------------------
_IN_VEHICLE_PAIRS: Pairs = (("-", ""), (" ", ""), (":", ""))

_IN_VEHICLE_FOREIGN_MISSION_CODES = frozenset({
    84, 85, 89, 93, 94, 95, 97, 98, 99, 102, 104, 105, 106, 109, 111, 112,
    113, 117, 119, 120, 121, 122, 123, 125, 126, 128, 133, 134, 135, 137,
    141, 145, 147, 149, 152, 153, 155, 156, 157, 159, 160,
})
_IN_VEHICLE_ARMED_FORCES_CODES = frozenset("ABCDEFHKPRX")
_IN_VEHICLE_DIPLOMATIC_CODES = frozenset({"CC", "CD", "UN"})

# RTO district codes per state / union territory (verbatim content of the upstream recognizer's
# in_vehicle_dist_* sets, written as ranges; DL and GJ are stored single-digit).
IN_VEHICLE_RTO_DISTRICTS: Dict[str, FrozenSet[str]] = {
    "AN": frozenset({"01"}),
    "AP": frozenset({"39", "40"}),
    "AR": _codes((1, 17), (19, 20), (22, 22)),
    "AS": _codes((1, 20), (22, 34)),
    "BR": _codes((1, 11), (19, 19), (21, 22), (24, 34), (37, 39), (43, 46), (50, 53), (55, 56)),
    "CG": _codes((1, 30)),
    "CH": _codes((1, 4)),
    "DD": _codes((1, 3)),
    "DN": frozenset({"09"}),  # old list
    "DL": _codes((1, 13), width=1),
    "GA": _codes((1, 12)),
    "GJ": _codes((1, 39), width=1),
    "HP": _codes((1, 20), (22, 99)),
    "HR": _codes((1, 20), (22, 99)),
    "JH": _codes((1, 20), (22, 24)),
    "JK": _codes((1, 20), (22, 22)),
    "KA": _codes((1, 20), (22, 71)),
    "KL": _codes((1, 20), (22, 99)),
    "LA": _codes((1, 2)),
    "LD": _codes((1, 9)),
    "MH": _codes((1, 20), (22, 51)),
    "ML": _codes((1, 10)),
    "MN": _codes((1, 7)),
    "MP": _codes((1, 20), (22, 71)),
    "MZ": _codes((1, 8)),
    "NL": _codes((1, 10)),
    "OD": _codes((1, 20), (22, 35)),
    "OR": _codes((1, 20), (22, 31)),  # old list
    "PB": _codes((1, 20), (22, 99)),
    "PY": _codes((1, 5)),
    "RJ": _codes((1, 20), (22, 58)),
    "SK": _codes((1, 8)),
    "TN": _codes((1, 20), (22, 99)),
    "TR": _codes((1, 8)),
    "TS": _codes((1, 20), (22, 38)),
    "UK": _codes((1, 20)),
    "UP": _codes((11, 20), (22, 96)),
    "WB": _codes((1, 20), (22, 98)),
}

_IN_UNION_TERRITORIES = frozenset({"AN", "CH", "DH", "DL", "JK", "LA", "LD", "PY"})
_IN_OLD_UNION_TERRITORIES = frozenset({"CT", "DN"})
_IN_STATES = frozenset({
    "AP", "AR", "AS", "BR", "CG", "GA", "GJ", "HR", "HP", "JH", "KA", "KL",
    "MP", "MH", "MN", "ML", "MZ", "NL", "OD", "PB", "RJ", "SK", "TN", "TS",
    "TR", "UP", "UK", "WB", "UT",
})
_IN_OLD_STATES = frozenset({"UL", "OR", "UA"})
_IN_NON_STANDARD_STATE_OR_UT = frozenset({"DD"})
_IN_TWO_FACTOR_REGISTRATION_PREFIX = (
    _IN_UNION_TERRITORIES | _IN_STATES | _IN_OLD_STATES
    | _IN_OLD_UNION_TERRITORIES | _IN_NON_STANDARD_STATE_OR_UT
)


def _validate_in_vehicle_registration(text: str) -> Optional[bool]:
    """
    State prefix + known RTO district + non-zero 4-digit serial -> True.
    upstream deliberately never returns False here: a plate that fails the
    lookup keeps its pattern score (None).
    """
    value = sanitize(text, _IN_VEHICLE_PAIRS)
    is_valid: Optional[bool] = None
    if len(value) >= 8:
        first_two = value[:2].upper()
        dist_code = ""
        if first_two in _IN_TWO_FACTOR_REGISTRATION_PREFIX:
            if value[2].isdigit():
                if value[3].isdigit():
                    dist_code = value[2:4]
                else:
                    dist_code = value[2:3]
                registration_digits = value[-4:]
                if registration_digits.isnumeric():
                    if 0 < int(registration_digits) <= 9999:
                        district_set = IN_VEHICLE_RTO_DISTRICTS.get(first_two, frozenset())
                        # Some states store single-digit district codes ("1".."9")
                        # while a modern plate zero-pads them ("DL01").
                        if dist_code and (
                            dist_code in district_set or str(int(dist_code)) in district_set
                        ):
                            is_valid = True
            # As in upstream this branch sits inside the state-prefix check, so
            # it only applies to state-prefixed values containing CC/CD/UN.
            for diplomatic_code in _IN_VEHICLE_DIPLOMATIC_CODES:
                if diplomatic_code in value:
                    vehicle_prefix = value.partition(diplomatic_code)[0]
                    if vehicle_prefix.isnumeric() and (
                        1 <= int(vehicle_prefix) <= 80
                        or int(vehicle_prefix) in _IN_VEHICLE_FOREIGN_MISSION_CODES
                    ):
                        is_valid = True
    return is_valid


# =============================================================================
# Singapore
# =============================================================================

# --- sg_uen_recognizer.py -----------------------------------------------------
_SG_UEN_FORMAT_A_WEIGHT = (10, 4, 9, 3, 8, 2, 7, 1)
_SG_UEN_FORMAT_A_ALPHABET = "XMKECAWLJDB"
_SG_UEN_FORMAT_B_WEIGHT = (10, 8, 6, 4, 9, 7, 5, 3, 1)
_SG_UEN_FORMAT_B_ALPHABET = "ZKCMDNERGWH"
_SG_UEN_FORMAT_C_WEIGHT = (4, 3, 5, 3, 10, 2, 2, 5, 7)
_SG_UEN_FORMAT_C_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWX0123456789"  # pragma: allowlist secret
_SG_UEN_FORMAT_C_PREFIX = frozenset({"T", "S", "R"})
_SG_UEN_FORMAT_C_ENTITY_TYPE = frozenset({
    "LP", "LL", "FC", "PF", "RF", "MQ", "MM", "NB", "CC", "CS", "MB", "FM", "GS",
    "DP", "CP", "NR", "CM", "CD", "MD", "HS", "VH", "CH", "MH", "CL", "XL", "CX",
    "HC", "RP", "TU", "TC", "FB", "FN", "PA", "PB", "SS", "MC", "SM", "GA", "GB",
})


def _validate_sg_uen_format_a(uen: str) -> bool:
    """Businesses registered with ACRA: 8 digits + check letter."""
    total = sum(int(n) * w for n, w in zip(uen[:-1], _SG_UEN_FORMAT_A_WEIGHT))
    return uen[-1] == _SG_UEN_FORMAT_A_ALPHABET[total % 11]


def _validate_sg_uen_format_b(uen: str) -> bool:
    """Local companies: YYYY + 5 digits + check letter."""
    if int(uen[0:4]) > date.today().year:
        return False
    total = sum(int(n) * w for n, w in zip(uen[:-1], _SG_UEN_FORMAT_B_WEIGHT))
    return uen[-1] == _SG_UEN_FORMAT_B_ALPHABET[total % 11]


def _validate_sg_uen_format_c(uen: str) -> bool:
    """Other entities: [TSR]YY + entity type + 4 digits + check letter."""
    if uen[0] not in _SG_UEN_FORMAT_C_PREFIX:
        return False
    if uen[3:5] not in _SG_UEN_FORMAT_C_ENTITY_TYPE:
        return False
    total = sum(
        _SG_UEN_FORMAT_C_ALPHABET.index(n) * w
        for n, w in zip(uen[:-1], _SG_UEN_FORMAT_C_WEIGHT)
    )
    return uen[-1] == _SG_UEN_FORMAT_C_ALPHABET[(total - 5) % 11]


def _validate_sg_uen(text: str) -> bool:
    # The pattern is matched case-insensitively; normalise before the checksum.
    uen = text.upper()
    if len(uen) == 9:
        return _validate_sg_uen_format_a(uen)
    if len(uen) == 10 and uen[0].isalpha():
        return _validate_sg_uen_format_c(uen)
    if len(uen) == 10:
        return _validate_sg_uen_format_b(uen)
    return False


# =============================================================================
# Australia
# =============================================================================
_AU_PAIRS: Pairs = (("-", ""), (" ", ""))


def _au_digits(text: str) -> List[int]:
    """upstream: sanitize, then every non-whitespace character as an int."""
    return [int(d) for d in sanitize(text, _AU_PAIRS) if not d.isspace()]


def _validate_au_abn(text: str) -> bool:
    """ABR modulus-89 check (subtract 1 from the first digit, weighted sum % 89 == 0)."""
    abn = _au_digits(text)
    if len(abn) != 11:
        return False
    weight = (10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19)
    abn[0] = abn[0] - 1
    return sum(abn[i] * weight[i] for i in range(11)) % 89 == 0


def _validate_au_acn(text: str) -> bool:
    """ASIC modified modulus-10 check on the 9th digit."""
    acn = _au_digits(text)
    if len(acn) != 9:
        return False
    weight = (8, 7, 6, 5, 4, 3, 2, 1)
    remainder = sum(acn[i] * weight[i] for i in range(8)) % 10
    return (10 - remainder) % 10 == acn[-1]


def _validate_au_medicare(text: str) -> bool:
    """Modulus-10 check digit at position 9 (10th digit is the issue number)."""
    medicare = _au_digits(text)
    if len(medicare) != 10:
        return False
    weight = (1, 3, 7, 9, 1, 3, 7, 9)
    return sum(medicare[i] * weight[i] for i in range(8)) % 10 == medicare[8]


def _validate_au_tfn(text: str) -> bool:
    """ATO modulus-11 check (weighted sum % 11 == 0)."""
    tfn = _au_digits(text)
    if len(tfn) != 9:
        return False
    weight = (1, 4, 3, 7, 5, 8, 6, 9, 10)
    return sum(tfn[i] * weight[i] for i in range(9)) % 11 == 0


# =============================================================================
# South Korea
# =============================================================================
_KR_DASH_PAIRS: Pairs = (("-", ""),)


def _validate_kr_brn(text: str) -> bool:
    """10-digit BRN checksum with keys 1,3,7,1,3,7,1,3,5 (9th digit adds its tens)."""
    value = sanitize(text, _KR_DASH_PAIRS)
    if len(value) != 10:
        return False
    if not value.isdigit():
        return False
    digits = [int(d) for d in value]
    magic_keys = (1, 3, 7, 1, 3, 7, 1, 3, 5)
    total = sum(digits[i] * magic_keys[i] for i in range(8))
    last_key_mul = digits[8] * magic_keys[8]
    total += (last_key_mul // 10) + last_key_mul
    return (10 - total % 10) % 10 == digits[9]


_KR_DRIVER_LICENSE_PAIRS: Pairs = (("-", ""), (" ", ""))
_KR_DRIVER_LICENSE_REGION_CODES = frozenset({
    "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
    "21", "22", "23", "24", "25", "26", "28",
})


def _validate_kr_driver_license(text: str) -> bool:
    """12 digits whose leading two are a registered regional code (no public checksum)."""
    value = sanitize(text, _KR_DRIVER_LICENSE_PAIRS)
    if len(value) != 12:
        return False
    if not value.isdigit():
        return False
    return value[:2] in _KR_DRIVER_LICENSE_REGION_CODES


_KR_RN_WEIGHTS = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)


def _validate_kr_registration_number(text: str, base: int) -> Optional[bool]:
    """
    Shared RRN/FRN check: region code (digits 8-9) in 0..95 and check digit
    X = (base - weighted_sum % 11) % 10 -> True. Numbers issued after October
    2020 are random, so a failed checksum yields None (pattern score kept).
    """
    value = sanitize(text, _KR_DASH_PAIRS)
    if len(value) != 13:
        return False
    if not value.isdigit():
        return False
    region_code = int(value[7:9])
    digit_sum = sum(int(value[i]) * _KR_RN_WEIGHTS[i] for i in range(12))
    checksum = (base - (digit_sum % 11)) % 10
    if 0 <= region_code <= 95 and checksum == int(value[12]):
        return True
    return None


def _validate_kr_rrn(text: str) -> Optional[bool]:
    return _validate_kr_registration_number(text, 11)


def _validate_kr_frn(text: str) -> Optional[bool]:
    return _validate_kr_registration_number(text, 13)


# =============================================================================
# Thailand
# =============================================================================


def _validate_th_tnin(text: str) -> bool:
    """13 digits; N13 = (11 - (13*N1 + 12*N2 + ... + 2*N12) mod 11) mod 10."""
    value = text  # upstream uses no replacement pairs for TNIN
    if len(value) != 13:
        return False
    if not value.isdigit():
        return False
    total = sum((13 - i) * int(value[i]) for i in range(12))
    x = total % 11
    expected = 1 - x if x <= 1 else 11 - x
    return expected == int(value[12])


# =============================================================================
# Rules
# =============================================================================

RULES: List[Rule] = [
    # ------------------------------------------------------------------ IN --
    Rule(
        name="IN Aadhaar",
        category="Regional Compliance",
        severity="Critical",
        region="IN",
        description="Indian Aadhaar (UIDAI) number: 12 digits with a Verhoeff check digit.",
        patterns=[
            Pattern("AADHAAR (Very Weak)", r"\b[0-9]{12}\b", 0.01),
            Pattern("AADHAR (Very Weak)", r"\b[0-9]{4}[- :][0-9]{4}[- :][0-9]{4}\b", 0.01),
        ],
        context=["aadhaar", "uidai"],
        validator=_validate_in_aadhaar,
        field_hint=r"aadha?ar|uidai|(?<![a-z])uid(?![a-z])",
        examples=("312345678909", "3998 7654 3211", "400123456787"),
    ),
    Rule(
        name="IN GST",
        category="Regional Compliance",
        severity="Low",
        region="IN",
        description="Indian GST identification number (GSTIN): state code + PAN + 'Z' + check character.",
        patterns=[
            Pattern(
                "GSTIN (High)",
                r"\b((?:0[1-9]|[1-3][0-7])[A-Za-z0-9]{10}[A-Za-z0-9]{1}Z[A-Za-z0-9]{1})\b",
                0.8,
            ),
            Pattern(
                "GSTIN (Medium)",
                r"\b((?:0[1-9]|[1-3][0-7])[A-Za-z0-9]{11}Z[A-Za-z0-9]{1})\b",
                0.4,
            ),
            Pattern("GSTIN (Low)", r"\b([0-9]{2}[A-Za-z0-9]{11}Z[A-Za-z0-9]{1})\b", 0.1),
        ],
        context=[
            "gstin",
            "gst",
            "goods and services tax",
            "tax identification",
            "gst number",
            "gst registration",
        ],
        validator=_validate_in_gstin,
        field_hint=r"(?<![a-z])gst(in)?(?![a-z])",
        examples=("27ABCDE1234F1Z5", "07PQRST6789K1Z2"),
    ),
    Rule(
        name="IN PAN",
        category="Regional Compliance",
        severity="High",
        region="IN",
        description="Indian Permanent Account Number (PAN): 5 letters, 4 digits, 1 letter.",
        patterns=[
            Pattern(
                "PAN (High)",
                r"\b([A-Za-z]{3}[AaBbCcFfGgHhJjLlPpTt]{1}[A-Za-z]{1}[0-9]{4}[A-Za-z]{1})\b",
                0.5,
            ),
            Pattern("PAN (Medium)", r"\b([A-Za-z]{5}[0-9]{4}[A-Za-z]{1})\b", 0.1),
            Pattern("PAN (Low)", r"\b((?=.*?[a-zA-Z])(?=.*?[0-9]{4})[\w@#$%^?~-]{10})\b", 0.01),
        ],
        context=["permanent account number", "pan"],
        field_hint=r"(?<![a-z])pan(?![a-z])|pan_?(num|no|card)",
        examples=("ABCPD1234Z", "ABBPM4567S"),
    ),
    Rule(
        name="IN PASSPORT",
        category="Regional Compliance",
        severity="High",
        region="IN",
        description="Indian passport number: a letter followed by 7 digits.",
        patterns=[
            Pattern("PASSPORT", r"\b[A-Z][1-9]\d\s?\d{4}[1-9]\b", 0.1),
        ],
        context=["passport", "indian passport", "passport number"],
        field_hint=r"passport",
        examples=("A3456781", "T3569075"),
    ),
    Rule(
        name="IN_VEHICLE_REGISTRATION",
        category="Regional Compliance",
        severity="Medium",
        region="IN",
        description="Indian RTO vehicle registration plate (state, district, series, serial; also BH/diplomatic/armed-forces formats).",
        patterns=[
            Pattern("India Vehicle Registration (Very Weak)", r"\b[A-Z]{1}(?!0000)[0-9]{4}\b", 0.01),
            Pattern("India Vehicle Registration (Very Weak)", r"\b[A-Z]{2}(?!0000)\d{4}\b", 0.01),
            Pattern("India Vehicle Registration (Very Weak)", r"\b(I)(?!00000)\d{5}\b", 0.01),
            Pattern("India Vehicle Registration (Weak)", r"\b[A-Z]{3}(?!0000)\d{4}\b", 0.20),
            Pattern("India Vehicle Registration (Medium)", r"\b\d{1,3}(CD|CC|UN)[1-9]{1}[0-9]{1,3}\b", 0.40),
            Pattern("India Vehicle Registration", r"\b[A-Z]{2}\d{1}[A-Z]{1,3}(?!0000)\d{4}\b", 0.50),
            Pattern("India Vehicle Registration", r"\b[A-Z]{2}\d{2}[A-Z]{1,2}(?!0000)\d{4}\b", 0.50),
            Pattern(
                "India Vehicle Registration",
                r"\b[2-9]{1}[1-9]{1}(BH)(?!0000)\d{4}[A-HJ-NP-Z]{2}\b",
                0.85,
            ),
            Pattern(
                "India Vehicle Registration",
                r"\b(?!00)\d{2}(A|B|C|D|E|F|H|K|P|R|X)\d{6}[A-Z]{1}\b",
                0.85,
            ),
        ],
        context=["RTO", "vehicle", "plate", "registration"],
        validator=_validate_in_vehicle_registration,
        field_hint=(
            r"vehicle_?(reg|num|no)|registration_?(num|no)|licen[cs]e_?plate"
            r"|number_?plate|(?<![a-z])rto(?![a-z])"
        ),
        examples=("KA53ME3456", "DL3CJI0001", "OD02BA2341"),
    ),
    Rule(
        name="IN VOTER ID",
        category="Regional Compliance",
        severity="High",
        region="IN",
        description="Indian voter ID (EPIC) number: 3 letters followed by 7 digits.",
        patterns=[
            Pattern(
                "VOTER",
                r"\b([A-Za-z]{1}[ABCDGHJKMNPRSYabcdghjkmnprsy]{1}[A-Za-z]{1}([0-9]){7})\b",
                0.4,
            ),
            Pattern("VOTER", r"\b([A-Za-z]){3}([0-9]){7}\b", 0.3),
        ],
        context=["voter", "epic", "elector photo identity card"],
        field_hint=r"voter|(?<![a-z])epic(?![a-z])",
        examples=("KSD1287349", "DBJ2289013", "CPJ4467918"),
    ),
    # ------------------------------------------------------------------ SG --
    Rule(
        name="SG_NRIC_FIN",
        category="Regional Compliance",
        severity="Critical",
        region="SG",
        description="Singapore NRIC / FIN: prefix letter (S, T, F, G, M), 7 digits, check letter.",
        patterns=[
            Pattern("Nric (weak)", r"(?i)(\b[A-Z][0-9]{7}[A-Z]\b)", 0.3),
            Pattern("Nric (medium)", r"(?i)(\b[STFGM][0-9]{7}[A-Z]\b)", 0.5),
        ],
        context=["fin", "fin#", "nric", "nric#"],
        field_hint=r"nric|(?<![a-z])fin(?![a-z])",
        examples=("S2740116C", "T1234567Z", "F2346401L"),
    ),
    Rule(
        name="SG_UEN",
        category="Regional Compliance",
        severity="Low",
        region="SG",
        description="Singapore Unique Entity Number (UEN) in ACRA formats A, B or C with checksum.",
        patterns=[
            Pattern(
                "UEN (low)",
                r"\b\d{8}[A-Z]\b|\b\d{9}[A-Z]\b|\b[TSR]\d{2}[A-Z]{2}\d{4}[A-Z]\b",
                0.3,
            ),
        ],
        context=["uen", "unique entity number", "business registration", "ACRA"],
        validator=_validate_sg_uen,
        field_hint=r"(?<![a-z])uen(?![a-z])",
        examples=("53125226D", "201434292D", "T16RF0037C"),
    ),
    # ------------------------------------------------------------------ AU --
    Rule(
        name="AU_ABN",
        category="Regional Compliance",
        severity="Low",
        region="AU",
        description="Australian Business Number (ABN): 11 digits with a modulus-89 check.",
        patterns=[
            Pattern("ABN (Medium)", r"\b\d{2}\s\d{3}\s\d{3}\s\d{3}\b", 0.1),
            Pattern("ABN (Low)", r"\b\d{11}\b", 0.01),
        ],
        context=["australian business number", "abn"],
        validator=_validate_au_abn,
        field_hint=r"(?<![a-z])abn(?![a-z])",
        examples=("51 824 753 556", "51824753556"),
    ),
    Rule(
        name="AU_ACN",
        category="Regional Compliance",
        severity="Low",
        region="AU",
        description="Australian Company Number (ACN): 9 digits with a modulus-10 check digit.",
        patterns=[
            Pattern("ACN (Medium)", r"\b\d{3}\s\d{3}\s\d{3}\b", 0.1),
            Pattern("ACN (Low)", r"\b\d{9}\b", 0.01),
        ],
        context=["australian company number", "acn"],
        validator=_validate_au_acn,
        field_hint=r"(?<![a-z])acn(?![a-z])",
        examples=("000 000 019", "005 499 981", "006249976"),
    ),
    Rule(
        name="AU_MEDICARE",
        category="Healthcare Data (PHI)",
        severity="High",
        region="AU",
        description="Australian Medicare card number: 10 digits starting 2-6 with a modulus-10 check digit.",
        patterns=[
            Pattern("Australian Medicare Number (Medium)", r"\b[2-6]\d{3}\s\d{5}\s\d\b", 0.1),
            Pattern("Australian Medicare Number (Low)", r"\b[2-6]\d{9}\b", 0.01),
        ],
        context=["medicare"],
        validator=_validate_au_medicare,
        field_hint=r"medicare",
        examples=("2123 45670 1", "2123456701"),
    ),
    Rule(
        name="AU_TFN",
        category="Regional Compliance",
        severity="High",
        region="AU",
        description="Australian Tax File Number (TFN): 9 digits with a modulus-11 check.",
        patterns=[
            Pattern("TFN (Medium)", r"\b\d{3}\s\d{3}\s\d{3}\b", 0.1),
            Pattern("TFN (Low)", r"\b\d{9}\b", 0.01),
        ],
        context=["tax file number", "tfn"],
        validator=_validate_au_tfn,
        field_hint=r"(?<![a-z])tfn(?![a-z])|tax_?file",
        examples=("876 543 210", "876543210"),
    ),
    # ------------------------------------------------------------------ KR --
    Rule(
        name="KR_BRN",
        category="Regional Compliance",
        severity="Low",
        region="KR",
        description="Korean Business Registration Number (BRN): 10 digits (AAA-BB-CCCCC) with checksum.",
        patterns=[
            Pattern("BRN (Weak)", r"(?<!\d)\d{3}-\d{2}-\d{5}(?!\d)", 0.1),
            Pattern("BRN (Very weak)", r"(?<!\d)\d{10}(?!\d)", 0.05),
        ],
        context=[
            "사업자등록번호",
            "사업자번호",
            "사업자",
            "BRN",
            "Business Registration Number",
            "Korean BRN",
            "business number",
            "tax registration number",
        ],
        validator=_validate_kr_brn,
        field_hint=r"(?<![a-z])brn(?![a-z])|business_?reg",
        examples=("104-86-56659", "1048656659", "104-82-13138"),
    ),
    Rule(
        name="KR_DRIVER_LICENSE",
        category="Regional Compliance",
        severity="High",
        region="KR",
        description="Korean driver's license number: 12 digits (AA-BB-CCCCCC-DD) starting with a regional code.",
        patterns=[
            Pattern(
                "Driver License (very weak)",
                r"(?<!\d)(\d{2})[- ]?(\d{2})[- ]?(\d{6})[- ]?(\d{2})(?!\d)",
                0.05,
            ),
        ],
        context=[
            "운전면허",
            "운전면허번호",
            "면허번호",
            "Korean driver license",
            "Korean driver's license",
        ],
        validator=_validate_kr_driver_license,
        field_hint=r"driv(er|ing)s?_?licen[cs]e",
        examples=("11-22-123456-12", "112212345612"),
    ),
    Rule(
        name="KR_FRN",
        category="Regional Compliance",
        severity="High",
        region="KR",
        description="Korean Foreigner Registration Number (FRN): YYMMDD-[5-8]NNNNNN with checksum.",
        patterns=[
            Pattern(
                "FRN (Medium)",
                r"(?<!\d)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(-?)[5-8]\d{6}(?!\d)",
                0.5,
            ),
        ],
        context=[
            "외국인등록번호",
            "Korean FRN",
            "FRN",
            "Foreigner Registration Number",
            "Korean Foreigner Registration Number",
            "외국인번호",
        ],
        validator=_validate_kr_frn,
        field_hint=r"(?<![a-z])frn(?![a-z])|foreigner",
        examples=("911124-5678906", "050912-6000012"),
    ),
    Rule(
        name="KR_PASSPORT",
        category="Regional Compliance",
        severity="High",
        region="KR",
        description="Korean passport number: M/S/R/O/D + 3 digits + letter + 4 digits (or + 8 digits, old format).",
        patterns=[
            Pattern(
                "Passport Number (Current)",
                r"(?<![A-Z0-9a-z])[MmSsRrOoDd]\d{3}[A-Za-z]\d{4}(?![0-9])",
                0.1,
            ),
            Pattern(
                "Passport Number (Previous)",
                r"(?<![A-Z0-9a-z])[MmSsRrOoDd]\d{8}(?![0-9])",
                0.05,
            ),
        ],
        context=[
            "Korean passport",
            "Korean passport number",
            "대한민국 여권",
            "여권",
            "passport",
            "passport number",
        ],
        field_hint=r"passport",
        examples=("M123A4567", "M12345678"),
    ),
    Rule(
        name="KR_RRN",
        category="Regional Compliance",
        severity="Critical",
        region="KR",
        description="Korean Resident Registration Number (RRN): YYMMDD-[1-4]NNNNNN with checksum.",
        patterns=[
            Pattern(
                "RRN (Medium)",
                r"(?<!\d)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(-?)[1-4]\d{6}(?!\d)",
                0.5,
            ),
        ],
        context=[
            "Korean RRN",
            "Korean Resident Registration Number",
            "Resident Registration Number",
            "RRN",
            "rrn",
            "rrn#",
        ],
        validator=_validate_kr_rrn,
        field_hint=r"(?<![a-z])rrn(?![a-z])|resident_?reg",
        examples=("960121-1021413", "050912-2000019"),
    ),
    # ------------------------------------------------------------------ TH --
    Rule(
        name="TH_TNIN",
        category="Regional Compliance",
        severity="Critical",
        region="TH",
        description="Thai National ID Number (TNIN): 13 digits with province code and modulus-11 check digit.",
        patterns=[
            Pattern(
                "TNIN (Medium)",
                r"\b[1-9](?:[134][0-9]|2[0-7]|5[0-8]|[67][01234567]|[89][0123456])\d{10}\b",
                0.5,
            ),
        ],
        context=[
            "Thai National ID",
            "Thai ID Number",
            "TNIN",
            "เลขประจำตัวประชาชน",
            "เลขบัตรประชาชน",
            "รหัสปชช",
        ],
        validator=_validate_th_tnin,
        field_hint=r"(?<![a-z])tnin(?![a-z])|thai_?id|national_?id",
        examples=("1234567890121", "2345678901234", "3456789012347"),
    ),
]
