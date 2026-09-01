"""
upstream-ported rules for South Africa (ZA), Nigeria (NG), the Philippines (PH)
and the generic IBAN / crypto-wallet / IP / MAC / URL / UUID recognizers.

Source: upstream-analyzer predefined_recognizers (MIT):
  country_specific/south_africa/*, country_specific/nigeria/*,
  country_specific/philippines/*, generic/{crypto,iban,ip,mac,url,uuid}_recognizer.py
Patterns, scores, context words and validate_result / invalidate_result logic
are copied verbatim. Intentional deviations (documented next to the rule):

* ZA_MOBILE_NUMBER / ZA_TELEPHONE_NUMBER / PH_MOBILE_NUMBER: upstream drives
  these with python-phonenumbers' PhoneNumberMatcher and has no regex. Here
  candidates are found with regexes over the ZA / PH numbering plans and then
  validated with phonenumbers (already a dependency of the engine, see
  src/engine/layers.py); if phonenumbers is unavailable the port falls back to
  the upstream recognizer's own national-significant-number prefix classifier.
* IBAN: upstream re-validates progressively shorter capture groups of a single
  match (full match -> without the trailing 1-3 chars -> 2-6 groups only).
  run_rule() only ever sees whole matches, so the same three candidates are
  expressed as three patterns; run_rule's de-duplication keeps the longest
  candidate that validates, exactly like the upstream recognizer's group fallback.
* Detector names follow fixtures/findings-mapping.json (IP_ADDRESS is reported
  as "PII.IPAddress", IBAN_CODE as "IBAN").
"""
import ipaddress
import re
from datetime import date
from hashlib import sha256
from typing import List, Optional

from src.engine.rules import Pattern, Rule
from src.engine.validators import digits_only, iban_mod97, luhn_check, sanitize, verhoeff_check

try:  # declared in requirements.txt; guarded so a missing wheel only degrades the phone rules
    import phonenumbers
    from phonenumbers import PhoneNumberType
except ImportError:  # pragma: no cover
    phonenumbers = None
    PhoneNumberType = None

_REGIONAL = "Regional Compliance"

# ---------------------------------------------------------------------------
# South Africa - ID number (za_id_number_recognizer.py)
# ---------------------------------------------------------------------------
_ZA_ID_LENGTH = 13
_ZA_ID_BIRTH_DATE_LENGTH = 6
_ZA_ID_CITIZENSHIP_INDEX = 10
_ZA_ID_LEGACY_RACE_INDEX = 11
_ZA_ID_ALLOWED_CITIZENSHIP_VALUES = frozenset({"0", "1", "2"})
_ZA_ID_ALLOWED_LEGACY_RACE_VALUES = frozenset({"8", "9"})


def _za_id_has_valid_birth_date(date_part: str) -> bool:
    """YYMMDD; YY above the current year's last two digits means 19YY, else 20YY; never in the future."""
    month = int(date_part[2:4])
    day = int(date_part[4:6])
    year_suffix = int(date_part[:2])

    today = date.today()
    pivot = today.year % 100
    century = 1900 if year_suffix > pivot else 2000

    try:
        birth_date = date(century + year_suffix, month, day)
    except ValueError:
        return False

    return birth_date <= today


def _validate_za_id_number(pattern_text: str) -> bool:
    if len(pattern_text) != _ZA_ID_LENGTH or not pattern_text.isdigit():
        return False
    if not _za_id_has_valid_birth_date(pattern_text[:_ZA_ID_BIRTH_DATE_LENGTH]):
        return False
    if pattern_text[_ZA_ID_CITIZENSHIP_INDEX] not in _ZA_ID_ALLOWED_CITIZENSHIP_VALUES:
        return False
    if pattern_text[_ZA_ID_LEGACY_RACE_INDEX] not in _ZA_ID_ALLOWED_LEGACY_RACE_VALUES:
        return False
    # the upstream recognizer's _is_luhn_valid doubles the odd-indexed digits of the 13-digit
    # string, which is the standard Luhn implemented by luhn_check.
    return luhn_check(pattern_text)


ZA_ID_NUMBER = Rule(
    name="ZA_ID_NUMBER",
    category=_REGIONAL,
    severity="Critical",
    region="ZA",
    description="South African 13-digit identity number (YYMMDD SSSS C A Z) with date, citizenship and Luhn checks.",
    patterns=[
        Pattern("South African ID Number", r"\b\d{10}[0-2][89]\d\b", 0.2),
    ],
    context=[
        "id",
        "identity",
        "identity number",
        "id number",
        "south african id",
        "rsa id",
        "smart id",
        "national id",
    ],
    validator=_validate_za_id_number,
    field_hint=r"id_?number|(?<![a-z])id_?(?:num|no)(?![a-z])|national_?id|(?<![a-z])said(?![a-z])|rsa_?id|identity_?(?:num|no|number)",
    examples=["8001015009087", "9202201234088", "0002294321191"],
)

# ---------------------------------------------------------------------------
# South Africa - traffic register number (za_traffic_register_number_recognizer.py)
# ---------------------------------------------------------------------------
_ZA_TRN_LENGTH = 13


def _validate_za_traffic_register_number(pattern_text: str) -> bool:
    if len(pattern_text) != _ZA_TRN_LENGTH or not pattern_text.isdigit():
        return False
    return not _validate_za_id_number(pattern_text)


ZA_TRAFFIC_REGISTER_NUMBER = Rule(
    name="ZA_TRAFFIC_REGISTER_NUMBER",
    category=_REGIONAL,
    severity="High",
    region="ZA",
    description="South African eNaTIS traffic register number: 13 digits that are not a valid SA ID number.",
    patterns=[
        Pattern("South African Traffic Register Number", r"\b\d{13}\b", 0.05),
    ],
    context=[
        "traffic register",
        "traffic register number",
        "trn",
        "enatis",
        "natis",
        "vehicle register",
    ],
    validator=_validate_za_traffic_register_number,
    field_hint=r"traffic_?reg|(?<![a-z])trn(?![a-z])",
    examples=["1234567890123", "6001015000076"],
)

# ---------------------------------------------------------------------------
# South Africa - income tax number (za_income_tax_number_recognizer.py)
# ---------------------------------------------------------------------------
_ZA_TAX_NUMBER_LENGTH = 10
_ZA_TAX_ALLOWED_LEADING_DIGITS = frozenset({"0", "1", "2", "3", "9"})


def _validate_za_income_tax_number(pattern_text: str) -> bool:
    return (
        len(pattern_text) == _ZA_TAX_NUMBER_LENGTH
        and pattern_text.isdigit()
        and pattern_text[0] in _ZA_TAX_ALLOWED_LEADING_DIGITS
    )


ZA_INCOME_TAX_NUMBER = Rule(
    name="ZA_INCOME_TAX_NUMBER",
    category=_REGIONAL,
    severity="High",
    region="ZA",
    description="South African SARS income tax reference number: 10 digits starting with 0, 1, 2, 3 or 9.",
    patterns=[
        Pattern("South African Income Tax Number", r"\b[01239]\d{9}\b", 0.05),
    ],
    context=[
        "sars",
        "tax reference",
        "income tax",
        "tax number",
        "itr",
        "taxpayer",
        "tax registration",
    ],
    validator=_validate_za_income_tax_number,
    field_hint=r"tax_?(?:ref|num|no|number)|income_?tax|(?<![a-z])sars(?![a-z])",
    examples=["0123456789", "1234567890", "9123456789"],
)

# ---------------------------------------------------------------------------
# South Africa - VAT number (za_vat_number_recognizer.py)
# ---------------------------------------------------------------------------
_ZA_VAT_LENGTH = 10
_ZA_VAT_PREFIX = "4"


def _validate_za_vat_number(pattern_text: str) -> bool:
    return (
        len(pattern_text) == _ZA_VAT_LENGTH
        and pattern_text.isdigit()
        and pattern_text.startswith(_ZA_VAT_PREFIX)
    )


ZA_VAT_NUMBER = Rule(
    name="ZA_VAT_NUMBER",
    category=_REGIONAL,
    severity="Low",
    region="ZA",
    description="South African VAT registration number: 10 digits starting with 4.",
    patterns=[
        Pattern("South African VAT Number", r"\b4\d{9}\b", 0.3),
    ],
    context=[
        "vat",
        "vat number",
        "vat registration",
        "tax invoice",
        "sars",
        "value added tax",
    ],
    validator=_validate_za_vat_number,
    field_hint=r"(?<![a-z])vat(?:_?(?:num|no|number|reg|id))?(?![a-z])",
    examples=["4020269678", "4170229407"],
)

# ---------------------------------------------------------------------------
# South Africa - passport (za_passport_recognizer.py)
# ---------------------------------------------------------------------------
_ZA_PASSPORT_LENGTH = 9
_ZA_PASSPORT_ALLOWED_PREFIXES = frozenset({"A", "D", "M", "T"})


def _validate_za_passport(pattern_text: str) -> bool:
    text = pattern_text.upper()
    if len(text) != _ZA_PASSPORT_LENGTH:
        return False
    if text[0] not in _ZA_PASSPORT_ALLOWED_PREFIXES:
        return False
    return text[1:].isdigit()


ZA_PASSPORT = Rule(
    name="ZA_PASSPORT",
    category=_REGIONAL,
    severity="High",
    region="ZA",
    description="South African passport number: prefix letter A, D, M or T followed by 8 digits.",
    patterns=[
        Pattern("South African Passport", r"\b[ADMT]\d{8}\b", 0.2),
    ],
    context=[
        "passport",
        "passport number",
        "travel document",
        "dha",
        "south african passport",
        "rsa passport",
    ],
    validator=_validate_za_passport,
    field_hint=r"passport",
    examples=["A34855903", "D12345678", "T11223344"],  # pragma: allowlist secret
)

# ---------------------------------------------------------------------------
# South Africa - driver's licence (za_driver_license_recognizer.py)
# ---------------------------------------------------------------------------
_ZA_DRIVER_MIN_LENGTH = 10
_ZA_DRIVER_MAX_LENGTH = 14


def _validate_za_driver_license(pattern_text: str) -> bool:
    text = pattern_text.upper()
    if not _ZA_DRIVER_MIN_LENGTH <= len(text) <= _ZA_DRIVER_MAX_LENGTH:
        return False
    if re.fullmatch(r"\d{6,10}[A-Z0-9]{2,5}", text) is None:
        return False
    return bool(re.search(r"[A-Z]", text))


ZA_DRIVER_LICENSE = Rule(
    name="ZA_DRIVER_LICENSE",
    category=_REGIONAL,
    severity="High",
    region="ZA",
    description="South African eNaTIS driver's licence number: 6-10 digits plus 2-5 alphanumerics (10-14 chars, at least one letter).",
    patterns=[
        Pattern("South African Driver's Licence", r"\b\d{6,10}[A-Z0-9]{2,5}\b", 0.3),
    ],
    context=[
        "licence",
        "license",
        "driving licence",
        "driving license",
        "driver's licence",
        "driver's license",
        "drivers licence",
        "drivers license",
        "enatis",
        "natis",
        "licence number",
        "license number",
    ],
    validator=_validate_za_driver_license,
    field_hint=r"driv(?:er|ing)s?_?licen[cs]e|licen[cs]e_?(?:num|no|number)|(?<![a-z])dl_?(?:num|no|number)(?![a-z])",
    examples=["60390002CGBV", "4024048D4P60", "30040008X6Z6"],
)

# ---------------------------------------------------------------------------
# South Africa - licence plate (za_license_plate_recognizer.py)
# ---------------------------------------------------------------------------
_ZA_PLATE_PROVINCE_SUFFIXES = frozenset({"GP", "ZN", "WP", "EC", "NC", "FS", "LP", "MP", "NW"})
_ZA_PLATE_REPLACEMENT_PAIRS = (("-", ""), (" ", ""))


def _validate_za_license_plate(pattern_text: str) -> bool:
    sanitized = sanitize(pattern_text, _ZA_PLATE_REPLACEMENT_PAIRS).upper()

    if len(sanitized) < 5:
        return False

    suffix = sanitized[-2:]
    if suffix not in _ZA_PLATE_PROVINCE_SUFFIXES:
        return False

    body = sanitized[:-2]
    if not body or not any(char.isalpha() for char in body):
        return False

    return True


ZA_LICENSE_PLATE = Rule(
    name="ZA_LICENSE_PLATE",
    category=_REGIONAL,
    severity="Medium",
    region="ZA",
    description="South African vehicle licence plate ending in a province code (GP, ZN, WP, EC, NC, FS, LP, MP, NW).",
    patterns=[
        Pattern(
            "ZA Licence Plate (compact)",
            r"\b[A-Z]{2,4}\d{2,4}[A-Z]{0,4}(?:GP|ZN|WP|EC|NC|FS|LP|MP|NW)\b",
            0.3,
        ),
        Pattern(
            "ZA Licence Plate (spaced)",
            r"\b[A-Z]{2}\s?\d{2}\s?[A-Z]{2}\s?(?:GP|ZN|WP|EC|NC|FS|LP|MP|NW)\b",
            0.3,
        ),
        Pattern(
            "ZA Licence Plate (prefix digits)",
            r"\b[A-Z]{2,3}\s?\d{2,3}\s?(?:GP|ZN|WP|EC|NC|FS|LP|MP|NW)\b",
            0.3,
        ),
        Pattern(
            "ZA Licence Plate (EC numeric prefix)",
            r"\b\d{2,3}\s?[A-Z]{2,3}\s?EC\b",
            0.3,
        ),
    ],
    context=[
        "licence plate",
        "license plate",
        "number plate",
        "registration",
        "vehicle registration",
        "natis",
        "enatis",
        "plate number",
    ],
    validator=_validate_za_license_plate,
    field_hint=r"licen[cs]e_?plate|number_?plate|vehicle_?reg|plate_?(?:num|no|number)|(?<![a-z])plate(?![a-z])",
    examples=["KD93GKGP", "DK 28 LF GP", "GET 103 WP"],
)

# ---------------------------------------------------------------------------
# South Africa - company registration (za_company_registration_recognizer.py)
# ---------------------------------------------------------------------------
_ZA_COMPANY_LEGACY_PREFIXES = frozenset({"CK", "K", "T", "W", "B", "M", "N", "NR"})


def _za_company_validate_modern_format(text: str) -> bool:
    parts = text.split("/")
    if len(parts) != 3:
        return False
    year_part, sequence_part, type_part = parts
    if not (year_part.isdigit() and sequence_part.isdigit() and type_part.isdigit()):
        return False
    if len(year_part) != 4 or len(sequence_part) != 6 or len(type_part) != 2:
        return False
    year = int(year_part)
    return 1800 <= year <= date.today().year


def _za_company_validate_legacy_format(text: str) -> bool:
    slash_index = text.index("/")
    prefix = text[:slash_index]
    sequence = text[slash_index + 1:]
    if not sequence.isdigit() or len(sequence) != 6:
        return False
    for legacy_prefix in sorted(_ZA_COMPANY_LEGACY_PREFIXES, key=len, reverse=True):
        if prefix.startswith(legacy_prefix):
            year_part = prefix[len(legacy_prefix):]
            if len(year_part) == 4 and year_part.isdigit():
                year = int(year_part)
                return 1800 <= year <= date.today().year
    return False


def _validate_za_company_registration(pattern_text: str) -> bool:
    text = pattern_text.upper()
    parts = text.split("/")
    if len(parts) == 3 and parts[0].isdigit():
        return _za_company_validate_modern_format(text)
    if len(parts) == 2:
        return _za_company_validate_legacy_format(text)
    return False


ZA_COMPANY_REGISTRATION = Rule(
    name="ZA_COMPANY_REGISTRATION",
    category=_REGIONAL,
    severity="Low",
    region="ZA",
    description="South African CIPC company registration number: YYYY/NNNNNN/NN or a legacy CK/K/T/W/B/M/N/NR prefixed form.",
    patterns=[
        Pattern(
            "South African Company Registration (modern)",
            r"\b(?:19|20)\d{2}/\d{6}/\d{2}\b",
            0.4,
        ),
        Pattern(
            "South African Company Registration (legacy)",
            r"\b(?:CK|K|T|W|B|M|N|NR)\d{4}/\d{6}\b",
            0.3,
        ),
    ],
    context=[
        "cipc",
        "company registration",
        "registration number",
        "close corporation",
        "company reg",
        "enterprise number",
    ],
    validator=_validate_za_company_registration,
    field_hint=r"company_?reg|(?<![a-z])cipc(?![a-z])|enterprise_?(?:num|no|number)|reg(?:istration)?_?(?:num|no|number)",
    examples=["2009/199240/23", "2014/256030/07", "CK2001/123456"],
)

# ---------------------------------------------------------------------------
# South Africa - mobile and telephone numbers (za_phone_number_recognizer.py)
#
# upstream uses phonenumbers.PhoneNumberMatcher(text, "ZA", leniency=1) and
# keeps matches whose region is ZA, split by line type. The regexes below are
# this port's own (upstream has none): national 0XX XXX XXXX, bracketed area
# code (0XX) XXX XXXX and international +27 / 0027 forms with space or dash
# separators. Score 0.4 is PhoneRecognizer.SCORE; the validator never returns
# True (upstream never lifts phone numbers to 1.0) and returns False when the
# candidate is not a valid ZA number of the wanted line type.
# ---------------------------------------------------------------------------
_ZA_PHONE_SCORE = 0.4
_ZA_PHONE_CONTEXT = [
    # PhoneRecognizer.CONTEXT
    "phone",
    "number",
    "telephone",
    "cell",
    "cellphone",
    "mobile",
    "call",
    # ZaPhoneNumberRecognizer additions
    "cellular",
    "handset",
    "contact number",
    "landline",
    "tel",
    "home number",
    "work number",
    "office number",
    "sms",
    "whatsapp",
]
_ZA_PHONE_PATTERNS = [
    Pattern(
        "ZA phone (international +27)",
        r"(?<![\w+])(?:\+|00)?27[ -]?(?:\(0\)[ -]?)?[1-9]\d(?:[ -]?\d){7}(?!\w)",
        _ZA_PHONE_SCORE,
    ),
    Pattern(
        "ZA phone (bracketed area code)",
        r"(?<![\d+])\(0[1-9]\d\)[ -]?\d{3}[ -]?\d{4}(?!\w)",
        _ZA_PHONE_SCORE,
    ),
    Pattern(
        "ZA phone (national)",
        r"(?<![\w+])0[1-9]\d(?:[ -]?\d){7}(?!\w)",
        _ZA_PHONE_SCORE,
    ),
]
_ZA_REGION = "ZA"
if PhoneNumberType is not None:
    _ZA_MOBILE_TYPES = frozenset({PhoneNumberType.MOBILE, PhoneNumberType.FIXED_LINE_OR_MOBILE})
    _ZA_TELEPHONE_TYPES = frozenset(
        {
            PhoneNumberType.FIXED_LINE,
            PhoneNumberType.TOLL_FREE,
            PhoneNumberType.PREMIUM_RATE,
            PhoneNumberType.VOIP,
            PhoneNumberType.SHARED_COST,
            PhoneNumberType.PERSONAL_NUMBER,
            PhoneNumberType.UAN,
            PhoneNumberType.PAGER,
        },
    )
else:  # pragma: no cover
    _ZA_MOBILE_TYPES = _ZA_TELEPHONE_TYPES = frozenset()


def _za_classify_by_nsn_prefix(nsn: str) -> Optional[str]:
    """ZaPhoneNumberRecognizer._classify_by_nsn_prefix, verbatim."""
    if not nsn:
        return None
    first_digit = nsn[0]
    if first_digit in "67":
        return "mobile"
    if nsn.startswith("80") or nsn.startswith(("86", "87")):
        return "telephone"
    if first_digit == "8":
        return "mobile"
    if first_digit in "123459":
        return "telephone"
    return None


def _za_national_significant_number(text: str) -> str:
    """Digits of a ZA number without the +27 / 0027 country code and the trunk 0."""
    digits = digits_only(text)
    if digits.startswith("0027"):
        digits = digits[4:]
    elif text.lstrip().startswith("+") or (digits.startswith("27") and len(digits) >= 11):
        digits = digits[2:]
    if digits.startswith("0") and len(digits) == 10:
        digits = digits[1:]
    return digits if len(digits) == 9 else ""


def _za_classify(text: str) -> Optional[str]:
    """'mobile' / 'telephone' / None for a candidate, mirroring ZaPhoneNumberRecognizer."""
    if phonenumbers is None:  # pragma: no cover
        return _za_classify_by_nsn_prefix(_za_national_significant_number(text))
    try:
        parsed = phonenumbers.parse(text, _ZA_REGION)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_valid_number(parsed):  # PhoneNumberMatcher leniency=VALID
        return None
    if phonenumbers.region_code_for_number(parsed) != _ZA_REGION:
        return None
    number_type = phonenumbers.number_type(parsed)
    if number_type in _ZA_MOBILE_TYPES:
        return "mobile"
    if number_type in _ZA_TELEPHONE_TYPES:
        return "telephone"
    if number_type != PhoneNumberType.UNKNOWN:
        return None
    return _za_classify_by_nsn_prefix(str(parsed.national_number))


def _validate_za_mobile_number(pattern_text: str) -> Optional[bool]:
    return None if _za_classify(pattern_text) == "mobile" else False


def _validate_za_telephone_number(pattern_text: str) -> Optional[bool]:
    return None if _za_classify(pattern_text) == "telephone" else False


ZA_MOBILE_NUMBER = Rule(
    name="ZA_MOBILE_NUMBER",
    category="PII",
    severity="Medium",
    region="ZA",
    description="South African mobile (cellular) number in national or +27 international format (06x/07x/08x ranges).",
    patterns=_ZA_PHONE_PATTERNS,
    context=_ZA_PHONE_CONTEXT,
    validator=_validate_za_mobile_number,
    field_hint=r"mobile|cell|msisdn|whatsapp|phone",
    examples=["+27632118258", "082 560 9352", "0825609352"],
)

ZA_TELEPHONE_NUMBER = Rule(
    name="ZA_TELEPHONE_NUMBER",
    category="PII",
    severity="Medium",
    region="ZA",
    description="South African landline or service number (01x-05x geographic, 080 toll-free, 086 sharecall, 087 VoIP).",
    patterns=_ZA_PHONE_PATTERNS,
    context=_ZA_PHONE_CONTEXT,
    validator=_validate_za_telephone_number,
    field_hint=r"phone|telephone|landline|(?<![a-z])tel(?:_?(?:num|no|number))?(?![a-z])|(?<![a-z])fax",
    examples=["011 262 5500", "(011) 390-9872", "0800 123 456"],
)

# ---------------------------------------------------------------------------
# Nigeria - NIN (ng_nin_recognizer.py)
# ---------------------------------------------------------------------------
def _validate_ng_nin(pattern_text: str) -> bool:
    # Verhoeff on the digit string itself so a leading zero is preserved
    return len(pattern_text) == 11 and pattern_text.isnumeric() and verhoeff_check(pattern_text)


NG_NIN = Rule(
    name="NG_NIN",
    category=_REGIONAL,
    severity="Critical",
    region="NG",
    description="Nigerian National Identification Number: 11 digits with a Verhoeff check digit.",
    patterns=[
        Pattern("NIN (Very Weak)", r"\b\d{11}\b", 0.01),
    ],
    context=[
        "nin",
        "national identification number",
        "national identity number",
        "nimc",
        "national identity",
        "nigeria id",
        "nigerian identification",
    ],
    validator=_validate_ng_nin,
    field_hint=r"(?<![a-z])nin(?![a-z])|national_?identi(?:fication|ty)|(?<![a-z])nimc(?![a-z])",
    examples=["12345678902", "98765432102", "01234567895"],
)

# ---------------------------------------------------------------------------
# Nigeria - vehicle registration (ng_vehicle_registration_recognizer.py)
# ---------------------------------------------------------------------------
NG_VEHICLE_REGISTRATION = Rule(
    name="NG_VEHICLE_REGISTRATION",
    category=_REGIONAL,
    severity="Medium",
    region="NG",
    description="Nigerian vehicle registration plate (2011+ format): LGA code, 3-digit serial and 2-letter year/batch code (ABC-123DE).",
    patterns=[
        Pattern("Nigeria Vehicle Registration", r"\b[A-Z]{3}[- ]?\d{3}[A-Z]{2}\b", 0.5),
    ],
    context=[
        "plate number",
        "vehicle registration",
        "license plate",
        "number plate",
        "plate",
        "vehicle",
        "registration",
    ],
    field_hint=r"vehicle_?reg|licen[cs]e_?plate|number_?plate|plate_?(?:num|no|number)|(?<![a-z])plate(?![a-z])",
    examples=["APP-456CV", "ABJ-001AA", "KJA 999PZ"],
)

# ---------------------------------------------------------------------------
# Philippines - UMID (ph_umid_recognizer.py)
# ---------------------------------------------------------------------------
PH_UMID = Rule(
    name="PH_UMID",
    category=_REGIONAL,
    severity="High",
    region="PH",
    description="Philippine Unified Multi-Purpose ID / Common Reference Number: 12 digits, usually written NNNN-NNNNNNN-N.",
    patterns=[
        Pattern("UMID (with dashes)", r"\b\d{4}-\d{7}-\d\b", 0.5),
        Pattern("UMID (without dashes)", r"\b\d{12}\b", 0.3),
    ],
    context=[
        "umid",
        "unified multi-purpose id",
        "crn",
        "common reference number",
        "sss",
        "gsis",
        "philhealth",
        "pag-ibig",
        "umid number",
        "umid card",
        "unified multipurpose id",
    ],
    field_hint=r"(?<![a-z])umid(?![a-z])|(?<![a-z])crn(?![a-z])|common_?reference",
    examples=["0111-1234567-8", "001112345678"],
)

# ---------------------------------------------------------------------------
# Philippines - TIN (ph_tin_recognizer.py)
# ---------------------------------------------------------------------------
_PH_TIN_REPLACEMENT_PAIRS = (("-", ""), (" ", ""))
_PH_TIN_WEIGHTS = (9, 8, 7, 6, 5, 4, 3, 2)


def _ph_tin_is_valid(pattern_text: str) -> bool:
    """Weighted modulo 11 over the first 8 digits; the 9th digit is the check digit."""
    pattern_text = sanitize(pattern_text, _PH_TIN_REPLACEMENT_PAIRS)

    if not pattern_text.isdigit():
        return False

    if len(pattern_text) not in (9, 12):
        return False

    total_sum = 0
    for i in range(8):
        total_sum += int(pattern_text[i]) * _PH_TIN_WEIGHTS[i]

    remainder = total_sum % 11
    check_digit = int(pattern_text[8])

    return remainder == check_digit


def _invalidate_ph_tin(pattern_text: str) -> bool:
    return not _ph_tin_is_valid(pattern_text)


PH_TIN = Rule(
    name="PH_TIN",
    category=_REGIONAL,
    severity="High",
    region="PH",
    description="Philippine BIR Taxpayer Identification Number: 9 or 12 digits (XXX-XXX-XXX[-XXX]) with a weighted mod-11 check digit.",
    patterns=[
        Pattern("TIN (Low)", r"\b(\d{3}-\d{3}-\d{3}(-\d{3})?)\b", 0.05),
        Pattern("TIN (Very Low)", r"\b(\d{9}|\d{12})\b", 0.01),
    ],
    context=[
        "tin",
        "taxpayer identification number",
        "bir",
        "taxpayer id",
        "tax id",
        "rdo",
        "revenue district office",
    ],
    invalidator=_invalidate_ph_tin,
    field_hint=r"(?<![a-z])tin(?:_?(?:num|no|number))?(?![a-z])|taxpayer|tax_?id",
    examples=["000-123-456-000", "000123456", "000-123-456"],
)

# ---------------------------------------------------------------------------
# Philippines - passport (ph_passport_recognizer.py)
# ---------------------------------------------------------------------------
PH_PASSPORT = Rule(
    name="PH_PASSPORT",
    category=_REGIONAL,
    severity="High",
    region="PH",
    description="Philippine passport number: 1 letter + 7 digits + 1 letter, or 2 letters + 7 digits (no checksum).",
    patterns=[
        Pattern(
            "PH Passport (weak: 1L7D1L or 2L7D)",
            r"\b(?:[A-Z]\d{7}[A-Z]|[A-Z]{2}\d{7})\b",
            0.1,
        ),
    ],
    context=[
        "passport",
        "passport number",
        "passport no",
        "passport no.",
        "passport#",
        "passport id",
        "travel document",
        "philippine passport",
        "philippines passport",
        "pasaporte",
        "pasaporte number",
        "dfa",  # Department of Foreign Affairs
    ],
    field_hint=r"passport|pasaporte",
    examples=["P1234567A", "EB1234567"],  # pragma: allowlist secret
)

# ---------------------------------------------------------------------------
# Philippines - mobile number
#
# upstream has no dedicated recognizer; tests/test_ph_mobile_number_recognizer.py
# configures the generic PhoneRecognizer with supported_regions=["PH"] and the
# context list below. Regexes are this port's own: +63 9XX XXX XXXX and
# 09XX XXX XXXX with optional space/dash separators and bracketed prefix; a bare
# 9XXXXXXXXX is not matched (the upstream recognizer's tests expect it not to be).
# ---------------------------------------------------------------------------
_PH_REGION = "PH"


def _validate_ph_mobile_number(pattern_text: str) -> Optional[bool]:
    if phonenumbers is None:  # pragma: no cover
        return None
    try:
        parsed = phonenumbers.parse(pattern_text, _PH_REGION)
    except phonenumbers.NumberParseException:
        return False
    if not phonenumbers.is_valid_number(parsed):
        return False
    if phonenumbers.region_code_for_number(parsed) != _PH_REGION:
        return False
    return None


PH_MOBILE_NUMBER = Rule(
    name="PH_MOBILE_NUMBER",
    category="PII",
    severity="Medium",
    region="PH",
    description="Philippine mobile number in national (09XX XXX XXXX) or international (+63 9XX XXX XXXX) format.",
    patterns=[
        Pattern(
            "PH mobile (international +63)",
            r"(?<![\w+])\+63[ -]?\(?9\d{2}\)?[ -]?\d{3}[ -]?\d{4}(?!\w)",
            0.4,
        ),
        Pattern(
            "PH mobile (national)",
            r"(?<![\w+])0[ -]?\(?9\d{2}\)?[ -]?\d{3}[ -]?\d{4}(?!\w)",
            0.4,
        ),
    ],
    context=[
        "mobile",
        "phone",
        "cell",
        "cellphone",
        "telepono",
        "numero",
        "mobile number",
        "contact number",
        "numero ng telepono",
        "contact",
        "number",
        "call",
        "tawag",
        "mensahe",
        "sms",
        "whatsapp",
        "viber",
        "telegram",
        "signal",
        "celphone",
        "phone number",
        "mobile no",
    ],
    validator=_validate_ph_mobile_number,
    field_hint=r"mobile|cell|phone|telepono",
    examples=["+63 917 123 4567", "09171234567", "0917-123-4567"],
)

# ---------------------------------------------------------------------------
# IBAN (iban_recognizer.py + iban_patterns.py)
# ---------------------------------------------------------------------------
# --- iban_patterns.py, verbatim (names prefixed with an underscore) ---
# IBAN parts format
_CC = "[A-Z]{2}"  # country code
_CK = "[0-9]{2}[ ]?"  # checksum
_BOS = "^"
_EOS = "$"  # end of string

_A = "[A-Z][ ]?"
_A2 = "([A-Z][ ]?){2}"
_A3 = "([A-Z][ ]?){3}"
_A4 = "([A-Z][ ]?){4}"

_C = "[a-zA-Z0-9][ ]?"
_C2 = "([a-zA-Z0-9][ ]?){2}"
_C3 = "([a-zA-Z0-9][ ]?){3}"
_C4 = "([a-zA-Z0-9][ ]?){4}"

_N = "[0-9][ ]?"
_N2 = "([0-9][ ]?){2}"
_N3 = "([0-9][ ]?){3}"
_N4 = "([0-9][ ]?){4}"

_regex_per_country = {
    # Albania (8n, 16c) ALkk bbbs sssx cccc cccc cccc cccc
    "AL": "(AL)" + _CK + _N4 + _N4 + _C4 + _C4 + _C4 + _C4,
    # Andorra (8n, 12c) ADkk bbbb ssss cccc cccc cccc
    "AD": "(AD)" + _CK + _N4 + _N4 + _C4 + _C4 + _C4,
    # Austria (16n) ATkk bbbb bccc cccc cccc
    "AT": "(AT)" + _CK + _N4 + _N4 + _N4 + _N4,
    # Azerbaijan    (4c,20n) AZkk bbbb cccc cccc cccc cccc cccc
    "AZ": "(AZ)" + _CK + _C4 + _N4 + _N4 + _N4 + _N4 + _N4,
    # Bahrain   (4a,14c)    BHkk bbbb cccc cccc cccc cc
    "BH": "(BH)" + _CK + _A4 + _C4 + _C4 + _C4 + _C2,
    # Belarus (4c, 4n, 16c)   BYkk bbbb aaaa cccc cccc cccc cccc
    "BY": "(BY)" + _CK + _C4 + _N4 + _C4 + _C4 + _C4 + _C4,
    # Belgium (12n)   BEkk bbbc cccc ccxx
    "BE": "(BE)" + _CK + _N4 + _N4 + _N4,
    # Bosnia and Herzegovina    (16n)   BAkk bbbs sscc cccc ccxx
    "BA": "(BA)" + _CK + _N4 + _N4 + _N4 + _N4,
    # Brazil (23n,1a,1c) BRkk bbbb bbbb ssss sccc cccc ccct n
    "BR": "(BR)" + _CK + _N4 + _N4 + _N4 + _N4 + _N4 + _N3 + _A + _C,
    # Bulgaria  (4a,6n,8c)  BGkk bbbb ssss ttcc cccc cc
    "BG": "(BG)" + _CK + _A4 + _N4 + _N + _N + _C2 + _C4 + _C2,
    # Costa Rica    (18n)   CRkk 0bbb cccc cccc cccc cc (0 = always zero)
    "CR": "(CR)" + _CK + "[0]" + _N3 + _N4 + _N4 + _N4 + _N2,
    # Croatia   (17n)   HRkk bbbb bbbc cccc cccc c
    "HR": "(HR)" + _CK + _N4 + _N4 + _N4 + _N4 + _N,
    # Cyprus    (8n,16c)    CYkk bbbs ssss cccc cccc cccc cccc
    "CY": "(CY)" + _CK + _N4 + _N4 + _C4 + _C4 + _C4 + _C4,
    # Czech Republic    (20n)   CZkk bbbb ssss sscc cccc cccc
    "CZ": "(CZ)" + _CK + _N4 + _N4 + _N4 + _N4 + _N4,
    # Denmark   (14n)   DKkk bbbb cccc cccc cc
    "DK": "(DK)" + _CK + _N4 + _N4 + _N4 + _N2,
    # Dominican Republic    (4a,20n)    DOkk bbbb cccc cccc cccc cccc cccc
    "DO": "(DO)" + _CK + _A4 + _N4 + _N4 + _N4 + _N4 + _N4,
    # EAt Timor    (19n) TLkk bbbc cccc cccc cccc cxx
    "TL": "(TL)" + _CK + _N4 + _N4 + _N4 + _N4 + _N3,
    # Estonia   (16n) EEkk bbss cccc cccc cccx
    "EE": "(EE)" + _CK + _N4 + _N4 + _N4 + _N4,
    # Faroe Islands    (14n) FOkk bbbb cccc cccc cx
    "FO": "(FO)" + _CK + _N4 + _N4 + _N4 + _N2,
    # Finland   (14n) FIkk bbbb bbcc cccc cx
    "FI": "(FI)" + _CK + _N4 + _N4 + _N4 + _N2,
    # France    (10n,11c,2n) FRkk bbbb bsss sscc cccc cccc cxx
    "FR": "(FR)" + _CK + _N4 + _N4 + _N2 + _C2 + _C4 + _C4 + _C + _N2,
    # Georgia   (2c,16n)  GEkk bbcc cccc cccc cccc cc
    "GE": "(GE)" + _CK + _C2 + _N2 + _N4 + _N4 + _N4 + _N2,
    # Germany   (18n) DEkk bbbb bbbb cccc cccc cc
    "DE": "(DE)" + _CK + _N4 + _N4 + _N4 + _N4 + _N2,
    # Gibraltar (4a,15c)  GIkk bbbb cccc cccc cccc ccc
    "GI": "(GI)" + _CK + _A4 + _C4 + _C4 + _C4 + _C3,
    # Greece    (7n,16c)  GRkk bbbs sssc cccc cccc cccc ccc
    "GR": "(GR)" + _CK + _N4 + _N3 + _C + _C4 + _C4 + _C4 + _C3,
    # Greenland     (14n) GLkk bbbb cccc cccc cc
    "GL": "(GL)" + _CK + _N4 + _N4 + _N4 + _N2,
    # Guatemala (4c,20c)  GTkk bbbb mmtt cccc cccc cccc cccc
    "GT": "(GT)" + _CK + _C4 + _C4 + _C4 + _C4 + _C4 + _C4,
    # Hungary   (24n) HUkk bbbs sssx cccc cccc cccc cccx
    "HU": "(HU)" + _CK + _N4 + _N4 + _N4 + _N4 + _N4 + _N4,
    # Iceland   (22n) ISkk bbbb sscc cccc iiii iiii ii
    "IS": "(IS)" + _CK + _N4 + _N4 + _N4 + _N4 + _N4 + _N2,
    # Ireland   (4c,14n)  IEkk aaaa bbbb bbcc cccc cc
    "IE": "(IE)" + _CK + _C4 + _N4 + _N4 + _N4 + _N2,
    # Israel (19n) ILkk bbbn nncc cccc cccc ccc
    "IL": "(IL)" + _CK + _N4 + _N4 + _N4 + _N4 + _N3,
    # Italy (1a,10n,12c)  ITkk xbbb bbss sssc cccc cccc ccc
    "IT": "(IT)" + _CK + _A + _N3 + _N4 + _N3 + _C + _C3 + _C + _C4 + _C3,
    # Jordan    (4a,22n)  JOkk bbbb ssss cccc cccc cccc cccc cc
    "JO": "(JO)" + _CK + _A4 + _N4 + _N4 + _N4 + _N4 + _N4 + _N2,
    # Kazakhstan    (3n,13c)  KZkk bbbc cccc cccc cccc
    "KZ": "(KZ)" + _CK + _N3 + _C + _C4 + _C4 + _C4,
    # Kosovo    (4n,10n,2n)   XKkk bbbb cccc cccc cccc
    "XK": "(XK)" + _CK + _N4 + _N4 + _N4 + _N4,
    # Kuwait    (4a,22c)  KWkk bbbb cccc cccc cccc cccc cccc cc
    "KW": "(KW)" + _CK + _A4 + _C4 + _C4 + _C4 + _C4 + _C4 + _C2,
    # Latvia    (4a,13c)  LVkk bbbb cccc cccc cccc c
    "LV": "(LV)" + _CK + _A4 + _C4 + _C4 + _C4 + _C,
    # Lebanon   (4n,20c)  LBkk bbbb cccc cccc cccc cccc cccc
    "LB": "(LB)" + _CK + _N4 + _C4 + _C4 + _C4 + _C4 + _C4,
    # LiechteNtein (5n,12c)  LIkk bbbb bccc cccc cccc c
    "LI": "(LI)" + _CK + _N4 + _N + _C3 + _C4 + _C4 + _C,
    # Lithuania (16n) LTkk bbbb bccc cccc cccc
    "LT": "(LT)" + _CK + _N4 + _N4 + _N4 + _N4,
    # Luxembourg    (3n,13c)  LUkk bbbc cccc cccc cccc
    "LU": "(LU)" + _CK + _N3 + _C + _C4 + _C4 + _C4,
    # Malta (4a,5n,18c)   MTkk bbbb ssss sccc cccc cccc cccc ccc
    "MT": "(MT)" + _CK + _A4 + _N4 + _N + _C3 + _C4 + _C4 + _C4 + _C3,
    # Mauritania    (23n) MRkk bbbb bsss sscc cccc cccc cxx
    "MR": "(MR)" + _CK + _N4 + _N4 + _N4 + _N4 + _N4 + _N3,
    # Mauritius (4a,19n,3a)   MUkk bbbb bbss cccc cccc cccc 000m mm
    "MU": "(MU)" + _CK + _A4 + _N4 + _N4 + _N4 + _N4 + _N3 + _A,
    # Moldova   (2c,18c)  MDkk bbcc cccc cccc cccc cccc
    "MD": "(MD)" + _CK + _C4 + _C4 + _C4 + _C4 + _C4,
    # Monaco    (10n,11c,2n)  MCkk bbbb bsss sscc cccc cccc cxx
    "MC": "(MC)" + _CK + _N4 + _N4 + _N2 + _C2 + _C4 + _C4 + _C + _N2,
    # Montenegro    (18n) MEkk bbbc cccc cccc cccc xx
    "ME": "(ME)" + _CK + _N4 + _N4 + _N4 + _N4 + _N2,
    # Netherlands   (4a,10n)  NLkk bbbb cccc cccc cc
    "NL": "(NL)" + _CK + _A4 + _N4 + _N4 + _N2,
    # North Macedonia   (3n,10c,2n)   MKkk bbbc cccc cccc cxx
    "MK": "(MK)" + _CK + _N3 + _C + _C4 + _C4 + _C + _N2,
    # Norway    (11n) NOkk bbbb cccc ccx
    "NO": "(NO)" + _CK + _N4 + _N4 + _N3,
    # Pakistan  (4c,16n)  PKkk bbbb cccc cccc cccc cccc
    "PK": "(PK)" + _CK + _C4 + _N4 + _N4 + _N4 + _N4,
    # Palestinian territories   (4c,21n)  PSkk bbbb xxxx xxxx xccc cccc cccc c
    "PS": "(PS)" + _CK + _C4 + _N4 + _N4 + _N4 + _N4 + _N,
    # Poland    (24n) PLkk bbbs sssx cccc cccc cccc cccc
    "PL": "(PL)" + _CK + _N4 + _N4 + _N4 + _N4 + _N4 + _N4,
    # Portugal  (21n) PTkk bbbb ssss cccc cccc cccx x
    "PT": "(PT)" + _CK + _N4 + _N4 + _N4 + _N4 + _N,
    # Qatar (4a,21c)  QAkk bbbb cccc cccc cccc cccc cccc c
    "QA": "(QA)" + _CK + _A4 + _C4 + _C4 + _C4 + _C4 + _C,
    # Romania   (4a,16c)  ROkk bbbb cccc cccc cccc cccc
    "RO": "(RO)" + _CK + _A4 + _C4 + _C4 + _C4 + _C4,
    # San Marino    (1a,10n,12c)  SMkk xbbb bbss sssc cccc cccc ccc
    "SM": "(SM)" + _CK + _A + _N3 + _N4 + _N3 + _C + _C4 + _C4 + _C3,
    # Saudi Arabia  (2n,18c)  SAkk bbcc cccc cccc cccc cccc
    "SA": "(SA)" + _CK + _N2 + _C2 + _C4 + _C4 + _C4 + _C4,
    # Serbia    (18n) RSkk bbbc cccc cccc cccc xx
    "RS": "(RS)" + _CK + _N4 + _N4 + _N4 + _N4 + _N2,
    # Slovakia  (20n) SKkk bbbb ssss sscc cccc cccc
    "SK": "(SK)" + _CK + _N4 + _N4 + _N4 + _N4 + _N4,
    # Slovenia  (15n) SIkk bbss sccc cccc cxx
    "SI": "(SI)" + _CK + _N4 + _N4 + _N4 + _N3,
    # Spain (20n) ESkk bbbb ssss xxcc cccc cccc
    "ES": "(ES)" + _CK + _N4 + _N4 + _N4 + _N4 + _N4,
    # Sweden    (20n) SEkk bbbc cccc cccc cccc cccc
    "SE": "(SE)" + _CK + _N4 + _N4 + _N4 + _N4 + _N4,
    # Switzerland   (5n,12c)  CHkk bbbb bccc cccc cccc c
    "CH": "(CH)" + _CK + _N4 + _N + _C3 + _C4 + _C4 + _C,
    # Tunisia   (20n) TNkk bbss sccc cccc cccc cccc
    "TN": "(TN)" + _CK + _N4 + _N4 + _N4 + _N4 + _N4,
    # Turkey    (5n,17c)  TRkk bbbb bxcc cccc cccc cccc cc
    "TR": "(TR)" + _CK + _N4 + _N + _C3 + _C4 + _C4 + _C4 + _C2,
    # United Arab Emirates  (3n,16n)  AEkk bbbc cccc cccc cccc ccc
    "AE": "(AE)" + _CK + _N4 + _N4 + _N4 + _N4 + _N3,
    # United Kingdom (4a,14n) GBkk bbbb ssss sscc cccc cc
    "GB": "(GB)" + _CK + _A4 + _N4 + _N4 + _N4 + _N2,
    # Vatican City  (3n,15n)  VAkk bbbc cccc cccc cccc cc
    "VA": "(VA)" + _CK + _N4 + _N4 + _N4 + _N4 + _N2,
    # Virgin Islands, British   (4c,16n)  VGkk bbbb cccc cccc cccc cccc
    "VG": "(VG)" + _CK + _C4 + _N4 + _N4 + _N4 + _N4,
    # Egypt (25n) EGkk bbbb ssss cccc cccc cccc ccccc
    "EG": "(EG)" + _CK + _N4 + _N4 + _N4 + _N4 + _N4 + _N4 + _N,
    # Iraq  (4a,15n)  IQkk bbbb sssc cccc cccc ccc
    "IQ": "(IQ)" + _CK + _A4 + _N4 + _N4 + _N4 + _N3,
    # Libya (21n) LYkk bbbs ssss cccc cccc c
    "LY": "(LY)" + _CK + _N4 + _N4 + _N4 + _N4 + _N4 + _N,
    # Saint Lucia   (4a,24c)  LCkk bbbb cccc cccc cccc cccc cccc cccc
    "LC": "(LC)" + _CK + _A4 + _C4 + _C4 + _C4 + _C4 + _C4 + _C4,
    # Seychelles    (4a,20n,3a)   SCkk bbbb ssnn cccc cccc cccc cccm mmm
    "SC": "(SC)" + _CK + _A4 + _N4 + _N4 + _N4 + _N4 + _N4 + _A3,
    # Ukraine   (6n,19c)  UAkk bbbb bbcc cccc cccc cccc cccc c
    "UA": "(UA)" + _CK + _N4 + _N2 + _C4 + _C4 + _C4 + _C4 + _C3,
}
# --- end of iban_patterns.py ---

_IBAN_FLAGS = re.DOTALL | re.MULTILINE  # IbanRecognizer regex_flags: no IGNORECASE
_IBAN_REPLACEMENT_PAIRS = (("-", ""), (" ", ""))
_IBAN_SCORE = 0.5
# the upstream recognizer's single regex, split into its named parts so the fallback
# candidates below are guaranteed to be the same sub-expressions.
_IBAN_LOOKBEHIND = r"(?<![A-Z0-9])"
_IBAN_GROUP_1 = r"([A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]{4}){2,6})"
_IBAN_GROUP_2 = r"((?:[ -]?[A-Z0-9]{4})?)"
_IBAN_GROUP_3 = r"((?:[ -]?[A-Z0-9]{1,3})?)"
_IBAN_LOOKAHEAD = r"(?![A-Z0-9])"
_IBAN_GENERIC_REGEX = (
    r"(?<![A-Z0-9])([A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]{4}){2,6})"
    r"((?:[ -]?[A-Z0-9]{4})?)((?:[ -]?[A-Z0-9]{1,3})?)(?![A-Z0-9])"
)


def _iban_is_valid_format(iban: str) -> bool:
    """IbanRecognizer.__is_valid_format with exact_match=False (no ^/$ anchors)."""
    country_code = iban[:2]
    if country_code in _regex_per_country:
        country_regex = _regex_per_country.get(country_code, "")
        return bool(country_regex) and re.match(country_regex, iban, _IBAN_FLAGS) is not None
    return False


def _validate_iban(pattern_text: str) -> Optional[bool]:
    """
    Checksum (mod 97) and country format -> True; checksum ok but the format only
    matches once upper-cased -> None (score unchanged); otherwise False.
    """
    iban = sanitize(pattern_text, _IBAN_REPLACEMENT_PAIRS)
    if not iban_mod97(iban):
        return False
    if _iban_is_valid_format(iban):
        return True
    if _iban_is_valid_format(iban.upper()):
        return None
    return False


IBAN = Rule(
    name="IBAN",
    category="Financial Data",
    severity="High",
    region=None,
    description="International Bank Account Number: ISO 13616 mod-97 checksum plus the per-country format of the IBAN registry.",
    patterns=[
        Pattern("IBAN Generic", _IBAN_GENERIC_REGEX, _IBAN_SCORE, flags=_IBAN_FLAGS),
        # upstream group fallbacks (see module docstring): the same match
        # without the trailing 1-3 characters, then without the optional
        # seventh group as well. run_rule keeps the longest candidate that
        # validates and drops the shorter ones it contains.
        Pattern(
            "IBAN Generic (group 2 fallback)",
            _IBAN_LOOKBEHIND + _IBAN_GROUP_1 + _IBAN_GROUP_2 + _IBAN_LOOKAHEAD,
            _IBAN_SCORE,
            flags=_IBAN_FLAGS,
        ),
        Pattern(
            "IBAN Generic (group 1 fallback)",
            _IBAN_LOOKBEHIND + _IBAN_GROUP_1 + _IBAN_LOOKAHEAD,
            _IBAN_SCORE,
            flags=_IBAN_FLAGS,
        ),
    ],
    context=["iban", "bank", "transaction"],
    validator=_validate_iban,
    field_hint=r"(?<![a-z])iban(?![a-z])|bank_?account|bank_?acct",
    examples=["DE89370400440532013000", "GB29 NWBK 6016 1331 9268 19", "AL47212110090000000235698741"],
)

# ---------------------------------------------------------------------------
# Crypto wallet address (crypto_recognizer.py)
# ---------------------------------------------------------------------------
# P2PKH / P2SH validation: http://rosettacode.org/wiki/Bitcoin/address_validation#Python
# Bech32 / Bech32m reference: https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py
_BECH32 = 1
_BECH32M = 2
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"  # pragma: allowlist secret
_BECH32M_CONST = 0x2BC830A3
_BASE58_DIGITS = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # pragma: allowlist secret


def _decode_base58(bc: bytes) -> bytes:
    origlen = len(bc)
    bc = bc.lstrip(_BASE58_DIGITS[0:1])

    n = 0
    for char in bc:
        n = n * 58 + _BASE58_DIGITS.index(char)  # ValueError on a non-base58 byte
    return n.to_bytes(origlen - len(bc) + (n.bit_length() + 7) // 8, "big")


def _bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_verify_checksum(hrp, data):
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if const == 1:
        return _BECH32
    if const == _BECH32M_CONST:
        return _BECH32M
    return None


def _bech32_decode(bech):
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (bech.lower() != bech and bech.upper() != bech):
        return (None, None, None)
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None, None)
    if not all(x in _BECH32_CHARSET for x in bech[pos + 1:]):
        return (None, None, None)
    hrp = bech[:pos]
    data = [_BECH32_CHARSET.find(x) for x in bech[pos + 1:]]
    spec = _bech32_verify_checksum(hrp, data)
    if spec is None:
        return (None, None, None)
    return (hrp, data[:-6], spec)


def _validate_bech32_address(address):
    hrp, data, spec = _bech32_decode(address)
    if hrp is not None and data is not None:
        return True, spec
    return False, None


def _validate_crypto(pattern_text: str) -> bool:
    if pattern_text.startswith("1") or pattern_text.startswith("3"):
        # P2PKH or P2SH: Base58Check, last 4 bytes are a double-SHA256 checksum
        try:
            bcbytes = _decode_base58(str.encode(pattern_text))
            checksum = sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]
            return bcbytes[-4:] == checksum
        except ValueError:
            return False
    elif pattern_text.startswith("bc1"):
        # Bech32 or Bech32m
        if _validate_bech32_address(pattern_text)[0]:
            return True
    return False


CRYPTO = Rule(
    name="CRYPTO",
    category="Financial Data",
    severity="Medium",
    region=None,
    description="Bitcoin wallet address: Base58Check (1.../3...) or Bech32/Bech32m (bc1...) with checksum validation.",
    patterns=[
        Pattern("Crypto (Medium)", r"(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}", 0.5),
    ],
    context=["wallet", "btc", "bitcoin", "crypto"],
    validator=_validate_crypto,
    field_hint=r"wallet|(?<![a-z])btc(?![a-z])|bitcoin|crypto",
    examples=[
        "16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",  # pragma: allowlist secret
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",  # pragma: allowlist secret
    ],
)

# ---------------------------------------------------------------------------
# IP address (ip_recognizer.py) - reported as PII.IPAddress
# ---------------------------------------------------------------------------
def _invalidate_ip_address(pattern_text: str) -> bool:
    try:
        ipaddress.ip_interface(pattern_text)
    except ValueError:
        return True
    return False


IP_ADDRESS = Rule(
    name="PII.IPAddress",
    category="PII",
    severity="Medium",
    region=None,
    description="IPv4 / IPv6 address (incl. CIDR, zone index, IPv4-mapped and IPv4-embedded forms) validated with the ipaddress module.",
    patterns=[
        Pattern(
            "IPv4_mapped",
            r"(?<![\w:])::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:12[0-8]|1[01]\d|[1-9]?\d))?\b",
            0.6,
        ),
        Pattern(
            "IPv4_embedded",
            r"(?<![\w:])(?:(?:[0-9A-Fa-f]{1,4}:){1,5}:(?:[0-9A-Fa-f]{1,4}:){0,4}|(?:[0-9A-Fa-f]{1,4}:){6})(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:12[0-8]|1[01]\d|[1-9]?\d))?\b",
            0.6,
        ),
        Pattern(
            "IPv4",
            r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:[0-2]?\d|3[0-2]))?\b",
            0.6,
        ),
        Pattern(
            "IPv6",
            r"(?<![\w:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|:(?::[0-9A-Fa-f]{1,4}){1,7}|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?::[0-9A-Fa-f]{1,4}){1,6})(?:%[0-9a-zA-Z]+)?(?:/(?:12[0-8]|1[01]\d|[1-9]?\d))?(?![\w:]|\.\d)",
            0.6,
        ),
        Pattern(
            "IPv6_unspecified",
            r"(?<![\w:])::(?:/(?:12[0-8]|1[01]\d|[1-9]?\d))?(?![\w:])",
            0.1,
        ),
    ],
    context=["ip", "ipv4", "ipv6"],
    invalidator=_invalidate_ip_address,
    field_hint=r"(?<![a-z])ip(?:v[46])?(?:_?addr(?:ess)?)?(?![a-z])|remote_?addr|client_?ip|source_?ip|src_?ip|dest_?ip|host_?ip|x_?forwarded_?for",
    examples=["192.168.0.1", "2001:db8::1", "::ffff:192.0.2.1"],
)

# ---------------------------------------------------------------------------
# MAC address (mac_recognizer.py)
# ---------------------------------------------------------------------------
def _invalidate_mac_address(pattern_text: str) -> bool:
    cleaned = re.sub(r"[:\-.]", "", pattern_text)

    # All characters must be valid hex
    if re.fullmatch(r"[0-9A-Fa-f]{12}", cleaned) is None:
        return True

    # Broadcast (FF:FF:FF:FF:FF:FF) and all-zero addresses are not identifying
    if cleaned.upper() == "FFFFFFFFFFFF" or cleaned.upper() == "000000000000":
        return True

    return False


MAC_ADDRESS = Rule(
    name="MAC_ADDRESS",
    category="PII",
    severity="Medium",
    region=None,
    description="MAC address in colon, hyphen or Cisco dotted notation (broadcast and all-zero addresses excluded).",
    patterns=[
        Pattern(
            "MAC_COLON_OR_HYPHEN",
            r"\b[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}\b",
            0.6,
        ),
        Pattern(
            "MAC_CISCO_DOT",
            r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b",
            0.6,
        ),
    ],
    context=["mac", "mac address", "hardware address", "physical address", "ethernet"],
    invalidator=_invalidate_mac_address,
    field_hint=r"mac_?addr|(?<![a-z])mac(?![a-z])|hardware_?addr|physical_?addr|hw_?addr",
    examples=["00:1A:2B:3C:4D:5E", "00-1A-2B-3C-4D-5E", "0012.3456.789A"],
)

# ---------------------------------------------------------------------------
# URL (url_recognizer.py) - disabled by default (pure technical identifier)
# ---------------------------------------------------------------------------
# CommonRegex, Copyright (c) 2014 Madison May, MIT - https://github.com/madisonmay/CommonRegex
_BASE_URL_REGEX = r"((www\d{0,3}[.])?[a-z0-9.\-]{1,253}[.](?:(?:com)|(?:edu)|(?:gov)|(?:int)|(?:mil)|(?:net)|(?:onl)|(?:org)|(?:pro)|(?:red)|(?:tel)|(?:uno)|(?:xxx)|(?:academy)|(?:accountant)|(?:accountants)|(?:actor)|(?:adult)|(?:africa)|(?:agency)|(?:airforce)|(?:apartments)|(?:app)|(?:archi)|(?:army)|(?:art)|(?:asia)|(?:associates)|(?:attorney)|(?:auction)|(?:audio)|(?:auto)|(?:autos)|(?:baby)|(?:band)|(?:bar)|(?:bargains)|(?:beer)|(?:berlin)|(?:best)|(?:bet)|(?:bid)|(?:bike)|(?:bio)|(?:black)|(?:blackfriday)|(?:blog)|(?:blue)|(?:boats)|(?:bond)|(?:boo)|(?:boston)|(?:bot)|(?:boutique)|(?:build)|(?:builders)|(?:business)|(?:buzz)|(?:cab)|(?:cafe)|(?:cam)|(?:camera)|(?:camp)|(?:capital)|(?:car)|(?:cards)|(?:care)|(?:careers)|(?:cars)|(?:casa)|(?:cash)|(?:casino)|(?:catering)|(?:center)|(?:ceo)|(?:cfd)|(?:charity)|(?:chat)|(?:cheap)|(?:christmas)|(?:church)|(?:city)|(?:claims)|(?:cleaning)|(?:click)|(?:clinic)|(?:clothing)|(?:cloud)|(?:club)|(?:codes)|(?:coffee)|(?:college)|(?:com)|(?:community)|(?:company)|(?:computer)|(?:condos)|(?:construction)|(?:consulting)|(?:contact)|(?:contractors)|(?:cooking)|(?:cool)|(?:coupons)|(?:courses)|(?:credit)|(?:creditcard)|(?:cricket)|(?:cruises)|(?:cyou)|(?:dad)|(?:dance)|(?:date)|(?:dating)|(?:day)|(?:degree)|(?:delivery)|(?:democrat)|(?:dental)|(?:dentist)|(?:desi)|(?:design)|(?:dev)|(?:diamonds)|(?:diet)|(?:digital)|(?:direct)|(?:directory)|(?:discount)|(?:doctor)|(?:dog)|(?:domains)|(?:download)|(?:earth)|(?:eco)|(?:education)|(?:email)|(?:energy)|(?:engineer)|(?:engineering)|(?:enterprises)|(?:equipment)|(?:esq)|(?:estate)|(?:events)|(?:exchange)|(?:expert)|(?:exposed)|(?:express)|(?:fail)|(?:faith)|(?:family)|(?:fans)|(?:farm)|(?:fashion)|(?:feedback)|(?:film)|(?:finance)|(?:financial)|(?:fish)|(?:fishing)|(?:fit)|(?:fitness)|(?:flights)|(?:florist)|(?:flowers)|(?:football)|(?:forsale)|(?:foundation)|(?:fun)|(?:fund)|(?:furniture)|(?:futbol)|(?:fyi)|(?:gallery)|(?:game)|(?:games)|(?:garden)|(?:gay)|(?:gdn)|(?:gifts)|(?:gives)|(?:giving)|(?:glass)|(?:global)|(?:gmbh)|(?:gold)|(?:golf)|(?:graphics)|(?:gratis)|(?:green)|(?:gripe)|(?:group)|(?:guide)|(?:guitars)|(?:guru)|(?:hair)|(?:hamburg)|(?:haus)|(?:health)|(?:healthcare)|(?:help)|(?:hiphop)|(?:hockey)|(?:holdings)|(?:holiday)|(?:homes)|(?:horse)|(?:hospital)|(?:host)|(?:hosting)|(?:house)|(?:how)|(?:icu)|(?:info)|(?:ink)|(?:institute)|(?:insure)|(?:international)|(?:investments)|(?:irish)|(?:jewelry)|(?:jetzt)|(?:juegos)|(?:kaufen)|(?:kids)|(?:kitchen)|(?:kiwi)|(?:krd)|(?:kyoto)|(?:land)|(?:lat)|(?:law)|(?:lawyer)|(?:lease)|(?:legal)|(?:lgbt)|(?:life)|(?:lighting)|(?:limited)|(?:limo)|(?:link)|(?:live)|(?:loan)|(?:loans)|(?:lol)|(?:london)|(?:love)|(?:ltd)|(?:ltda)|(?:luxury)|(?:maison)|(?:management)|(?:market)|(?:marketing)|(?:markets)|(?:mba)|(?:media)|(?:melbourne)|(?:meme)|(?:memorial)|(?:men)|(?:miami)|(?:mobi)|(?:moda)|(?:moe)|(?:mom)|(?:money)|(?:monster)|(?:mortgage)|(?:motorcycles)|(?:mov)|(?:movie)|(?:nagoya)|(?:name)|(?:navy)|(?:network)|(?:new)|(?:news)|(?:ngo)|(?:ninja)|(?:now)|(?:nyc)|(?:observer)|(?:okinawa)|(?:one)|(?:ong)|(?:onl)|(?:online)|(?:organic)|(?:osaka)|(?:page)|(?:paris)|(?:partners)|(?:parts)|(?:party)|(?:pet)|(?:phd)|(?:photo)|(?:photography)|(?:photos)|(?:pics)|(?:pictures)|(?:pink)|(?:pizza)|(?:place)|(?:plumbing)|(?:plus)|(?:poker)|(?:porn)|(?:press)|(?:pro)|(?:productions)|(?:prof)|(?:promo)|(?:properties)|(?:property)|(?:protection)|(?:pub)|(?:quest)|(?:racing)|(?:recipes)|(?:red)|(?:rehab)|(?:reise)|(?:reisen)|(?:rent)|(?:rentals)|(?:repair)|(?:report)|(?:republican)|(?:rest)|(?:restaurant)|(?:review)|(?:reviews)|(?:rip)|(?:rocks)|(?:rodeo)|(?:rsvp)|(?:run)|(?:saarland)|(?:sale)|(?:salon)|(?:sarl)|(?:sbs)|(?:school)|(?:schule)|(?:science)|(?:services)|(?:sex)|(?:sexy)|(?:sh)|(?:shoes)|(?:shop)|(?:shopping)|(?:show)|(?:singles)|(?:site)|(?:skin)|(?:soccer)|(?:social)|(?:software)|(?:solar)|(?:solutions)|(?:soy)|(?:space)|(?:spiegel)|(?:study)|(?:style)|(?:sucks)|(?:supply)|(?:support)|(?:surf)|(?:surgery)|(?:systems)|(?:tax)|(?:taxi)|(?:team)|(?:tech)|(?:technology)|(?:tel)|(?:theater)|(?:tips)|(?:tires)|(?:today)|(?:tools)|(?:top)|(?:tours)|(?:town)|(?:toys)|(?:trade)|(?:training)|(?:tube)|(?:uk)|(?:university)|(?:uno)|(?:vacations)|(?:ventures)|(?:vet)|(?:video)|(?:villas)|(?:vin)|(?:vip)|(?:vision)|(?:vlaanderen)|(?:vodka)|(?:vote)|(?:voting)|(?:voyage)|(?:wales)|(?:wang)|(?:watch)|(?:webcam)|(?:website)|(?:wedding)|(?:wiki)|(?:wine)|(?:work)|(?:works)|(?:world)|(?:wtf)|(?:xyz)|(?:yoga)|(?:yokohama)|(?:you)|(?:zone)|(?:ac)|(?:ad)|(?:ae)|(?:af)|(?:ag)|(?:ai)|(?:al)|(?:am)|(?:an)|(?:ao)|(?:aq)|(?:ar)|(?:as)|(?:at)|(?:au)|(?:aw)|(?:ax)|(?:az)|(?:ba)|(?:bb)|(?:bd)|(?:be)|(?:bf)|(?:bg)|(?:bh)|(?:bi)|(?:bj)|(?:bm)|(?:bn)|(?:bo)|(?:br)|(?:bs)|(?:bt)|(?:bv)|(?:bw)|(?:by)|(?:bz)|(?:ca)|(?:cc)|(?:cd)|(?:cf)|(?:cg)|(?:ch)|(?:ci)|(?:ck)|(?:cl)|(?:cm)|(?:cn)|(?:co)|(?:cr)|(?:cu)|(?:cv)|(?:cw)|(?:cx)|(?:cy)|(?:cz)|(?:de)|(?:dj)|(?:dk)|(?:dm)|(?:do)|(?:dz)|(?:ec)|(?:ee)|(?:eg)|(?:er)|(?:es)|(?:et)|(?:eu)|(?:fi)|(?:fj)|(?:fk)|(?:fm)|(?:fo)|(?:fr)|(?:ga)|(?:gb)|(?:gd)|(?:ge)|(?:gf)|(?:gg)|(?:gh)|(?:gi)|(?:gl)|(?:gm)|(?:gn)|(?:gp)|(?:gq)|(?:gr)|(?:gs)|(?:gt)|(?:gu)|(?:gw)|(?:gy)|(?:hk)|(?:hm)|(?:hn)|(?:hr)|(?:ht)|(?:hu)|(?:id)|(?:ie)|(?:il)|(?:im)|(?:in)|(?:io)|(?:iq)|(?:ir)|(?:is)|(?:it)|(?:je)|(?:jm)|(?:jo)|(?:jp)|(?:ke)|(?:kg)|(?:kh)|(?:ki)|(?:km)|(?:kn)|(?:kp)|(?:kr)|(?:kw)|(?:ky)|(?:kz)|(?:la)|(?:lb)|(?:lc)|(?:li)|(?:lk)|(?:lr)|(?:ls)|(?:lt)|(?:lu)|(?:lv)|(?:ly)|(?:ma)|(?:mc)|(?:md)|(?:me)|(?:mg)|(?:mh)|(?:mk)|(?:ml)|(?:mm)|(?:mn)|(?:mo)|(?:mp)|(?:mq)|(?:mr)|(?:ms)|(?:mt)|(?:mu)|(?:mv)|(?:mw)|(?:mx)|(?:my)|(?:mz)|(?:na)|(?:nc)|(?:ne)|(?:nf)|(?:ng)|(?:ni)|(?:nl)|(?:no)|(?:np)|(?:nr)|(?:nu)|(?:nz)|(?:om)|(?:pa)|(?:pe)|(?:pf)|(?:pg)|(?:ph)|(?:pk)|(?:pl)|(?:pm)|(?:pn)|(?:pr)|(?:ps)|(?:pt)|(?:pw)|(?:py)|(?:qa)|(?:re)|(?:ro)|(?:rs)|(?:ru)|(?:rw)|(?:sa)|(?:sb)|(?:sc)|(?:sd)|(?:se)|(?:sg)|(?:sh)|(?:si)|(?:sj)|(?:sk)|(?:sl)|(?:sm)|(?:sn)|(?:so)|(?:sr)|(?:st)|(?:su)|(?:sv)|(?:sx)|(?:sy)|(?:sz)|(?:tc)|(?:td)|(?:tf)|(?:tg)|(?:th)|(?:tj)|(?:tk)|(?:tl)|(?:tm)|(?:tn)|(?:to)|(?:tp)|(?:tr)|(?:tt)|(?:tv)|(?:tw)|(?:tz)|(?:ua)|(?:ug)|(?:uk)|(?:us)|(?:uy)|(?:uz)|(?:va)|(?:vc)|(?:ve)|(?:vg)|(?:vi)|(?:vn)|(?:vu)|(?:wf)|(?:ws)|(?:ye)|(?:yt)|(?:za)|(?:zm)|(?:zw))(?:/[^\s()<>\"']*)?)"  # noqa: E501

URL = Rule(
    name="URL",
    category="PII",
    severity="Low",
    region=None,
    description="Web URL (with or without scheme, optionally quoted) whose host ends in a known TLD.",
    patterns=[
        Pattern("Standard Url", "(?i)(?:https?://)" + _BASE_URL_REGEX, 0.6),
        Pattern("Non schema URL", "(?i)" + _BASE_URL_REGEX, 0.5),
        Pattern("Quoted URL", r'(?i)["\'](https?://' + _BASE_URL_REGEX + r')["\']', 0.6),
        Pattern("Quoted Non-schema URL", r'(?i)["\'](' + _BASE_URL_REGEX + r')["\']', 0.5),
    ],
    context=["url", "website", "link"],
    field_hint=r"(?<![a-z])url(?![a-z])|(?<![a-z])uri(?![a-z])|link|href|website|homepage",
    enabled=False,
    examples=["https://www.microsoft.com/", "microsoft.com"],
)

# ---------------------------------------------------------------------------
# UUID (uuid_recognizer.py) - disabled by default (pure technical identifier)
# ---------------------------------------------------------------------------
_UUID_VALID_VERSIONS = {"1", "2", "3", "4", "5", "6", "7", "8"}  # RFC 4122 v1-5, RFC 9562 v6-8
_UUID_VALID_VARIANT_PREFIXES = {"8", "9", "a", "b"}  # RFC 4122 variant bits
_NIL_UUID = "00000000-0000-0000-0000-000000000000"


def _invalidate_uuid(pattern_text: str) -> bool:
    if pattern_text.lower() == _NIL_UUID:
        return True

    groups = pattern_text.split("-")
    if len(groups) != 5 or any(not g for g in groups):
        return True

    version_nibble = groups[2][0].lower()
    if version_nibble not in _UUID_VALID_VERSIONS:
        return True

    variant_nibble = groups[3][0].lower()
    if variant_nibble not in _UUID_VALID_VARIANT_PREFIXES:
        return True

    return False


UUID = Rule(
    name="UUID",
    category="Technical Identifier",
    severity="Low",
    region=None,
    description="Hyphenated RFC 4122 / RFC 9562 UUID (versions 1-8, valid variant bits, nil UUID excluded).",
    patterns=[
        Pattern(
            "UUID (hyphenated)",
            r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b",
            0.5,
        ),
    ],
    context=["uuid", "guid", "unique identifier"],
    invalidator=_invalidate_uuid,
    field_hint=r"uuid|guid",
    enabled=False,
    examples=["550e8400-e29b-41d4-a716-446655440000", "6fa459ea-ee8a-3ca4-894e-db77e160355e"],
)

RULES: List[Rule] = [
    ZA_ID_NUMBER,
    ZA_PASSPORT,
    ZA_DRIVER_LICENSE,
    ZA_TRAFFIC_REGISTER_NUMBER,
    ZA_INCOME_TAX_NUMBER,
    ZA_VAT_NUMBER,
    ZA_COMPANY_REGISTRATION,
    ZA_LICENSE_PLATE,
    ZA_MOBILE_NUMBER,
    ZA_TELEPHONE_NUMBER,
    NG_NIN,
    NG_VEHICLE_REGISTRATION,
    PH_UMID,
    PH_TIN,
    PH_PASSPORT,
    PH_MOBILE_NUMBER,
    IBAN,
    CRYPTO,
    IP_ADDRESS,
    MAC_ADDRESS,
    URL,
    UUID,
]
