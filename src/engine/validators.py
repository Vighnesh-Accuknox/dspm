"""
Shared checksum / structural validators used by detectors and upstream-ported rules.
Every function takes the raw matched text and is tolerant of common separators.
"""
import re
import string
from typing import Iterable, Optional, Sequence, Tuple

from src.engine.luhn import luhn_check  # noqa: F401  (re-exported)

# ISO 3166-1 alpha-2 country codes (officially assigned)
ISO3166_ALPHA2 = frozenset(
    """
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT
MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW
SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG
UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK
""".split(),
)


def digits_only(text: str) -> str:
    return "".join(c for c in text if c.isdigit())


def sanitize(text: str, pairs: Iterable[Tuple[str, str]] = (("-", ""), (" ", ""), (".", ""), (":", ""))) -> str:
    """upstream EntityRecognizer.sanitize_value: apply replacement pairs in order."""
    for old, new in pairs:
        text = text.replace(old, new)
    return text


def all_same_digit(digits: str) -> bool:
    return bool(digits) and all(c == digits[0] for c in digits)


def is_palindrome(text: str) -> bool:
    return text == text[::-1]


def weighted_sum(digits: str, weights: Sequence[int]) -> int:
    """sum(d_i * w_i) over the leading len(weights) digits."""
    return sum(int(d) * w for d, w in zip(digits, weights))


def verhoeff_check(number: str) -> bool:
    """Verhoeff checksum (Aadhaar). Accepts digits with optional separators."""
    d = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]
    p = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]
    num = digits_only(number)
    if not num:
        return False
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = d[c][p[i % 8][int(ch)]]
    return c == 0


_IBAN_LETTERS = {ord(ch): str(i) for i, ch in enumerate(string.digits + string.ascii_uppercase)}


def iban_mod97(iban: str) -> bool:
    """ISO 13616 mod-97 check on an IBAN without separators (case-insensitive)."""
    value = sanitize(iban.upper(), (("-", ""), (" ", "")))
    if len(value) < 15 or not value[:2].isalpha() or not value[2:4].isdigit():
        return False
    rearranged = (value[4:] + value[:4]).translate(_IBAN_LETTERS)
    try:
        return int(rearranged) % 97 == 1
    except ValueError:
        return False


def luhn_valid(number: str) -> bool:
    """Luhn on the digits of number (13-19 digits)."""
    return luhn_check(digits_only(number))


def mod_check(digits: str, weights: Sequence[int], modulus: int, expected: Optional[int] = None) -> bool:
    """
    Generic weighted-modulus check: (sum(d_i * w_i)) % modulus == expected, where
    expected defaults to the digit following the weighted prefix.
    """
    if len(digits) < len(weights):
        return False
    total = weighted_sum(digits, weights)
    if expected is None:
        if len(digits) <= len(weights):
            return False
        expected = int(digits[len(weights)])
    return total % modulus == expected


def is_hex(text: str) -> bool:
    return bool(text) and re.fullmatch(r"[0-9a-fA-F]+", text) is not None


def is_valid_country_code(code: str) -> bool:
    return code.upper() in ISO3166_ALPHA2
