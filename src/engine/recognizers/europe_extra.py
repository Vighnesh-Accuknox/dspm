"""
European national identifiers beyond the ported packs: FR NL BE CH AT IE PT LU
DK NO IS CZ SK HU RO GR BG HR RS SI LT EE LV RU UA, plus ES / GB additions.

Every rule with a public check-digit algorithm carries a validator: True
(score 1.0) when the checksum holds, False (dropped) when it does not, None
(pattern score kept) where the algorithm is not authoritative for every number
(Danish CPR after 2007, Latvian new-format codes, UK UTR). Patterns are
compiled case-insensitively by the rule engine, so validators upper-case.
"""
from typing import Optional

from src.engine.rules import Pattern, Rule
from src.engine.validators import digits_only, sanitize, verhoeff_check

_REGIONAL = "Regional Compliance"
_FINANCIAL = "Financial Data"
_MONTH_DAYS = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _plain_luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _weighted(digits: str, weights) -> int:
    return sum(int(d) * w for d, w in zip(digits, weights))


def _valid_day_month(dd: int, mm: int) -> bool:
    return 1 <= mm <= 12 and 1 <= dd <= _MONTH_DAYS[mm - 1]


# --------------------------------------------------------------------------- France
def _validate_fr_nir(text: str) -> bool:
    v = sanitize(text.upper(), ((" ", ""), (".", ""), ("-", "")))
    if len(v) != 15:
        return False
    body, key = v[:13], v[13:]
    body = body[:5] + body[5:7].replace("2A", "19").replace("2B", "18") + body[7:]
    if not body.isdigit() or not key.isdigit():
        return False
    return int(key) == 97 - (int(body) % 97)


# --------------------------------------------------------------------------- Netherlands
def _validate_nl_bsn(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 9 or len(set(v)) == 1:
        return False
    total = sum(int(v[i]) * (9 - i) for i in range(8)) - int(v[8])
    return total % 11 == 0


# --------------------------------------------------------------------------- Belgium
def _validate_be_national_number(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 11:
        return False
    mm, dd = int(v[2:4]) % 20, int(v[4:6])
    if mm > 12 or dd > 31:
        return False
    base, check = v[:9], int(v[9:])
    return check in (97 - int(base) % 97, 97 - int("2" + base) % 97)


# --------------------------------------------------------------------------- Switzerland
def _validate_ch_ahv(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 13 or not v.startswith("756"):
        return False
    total = sum(int(v[i]) * (1 if i % 2 == 0 else 3) for i in range(12))
    return (10 - total % 10) % 10 == int(v[12])


# --------------------------------------------------------------------------- Austria
def _validate_at_svnr(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 10 or not _valid_day_month(int(v[4:6]), int(v[6:8])):
        return False
    check = _weighted(v, (3, 7, 9, 0, 5, 8, 4, 2, 1, 6)) % 11
    return check != 10 and check == int(v[3])


# --------------------------------------------------------------------------- Ireland
_PPS_LETTERS = "WABCDEFGHIJKLMNOPQRSTUV"  # pragma: allowlist secret


def _validate_ie_pps(text: str) -> bool:
    v = text.upper()
    if not (8 <= len(v) <= 9) or not v[:7].isdigit() or not v[7:].isalpha():
        return False
    total = _weighted(v[:7], (8, 7, 6, 5, 4, 3, 2))
    if len(v) == 9:
        total += 9 * (ord(v[8]) - 64)
    return v[7] == _PPS_LETTERS[total % 23]


# --------------------------------------------------------------------------- Portugal
def _validate_pt_nif(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 9 or v[0] not in "1235689":
        return False
    r = _weighted(v, (9, 8, 7, 6, 5, 4, 3, 2)) % 11
    return int(v[8]) == (0 if r < 2 else 11 - r)


# --------------------------------------------------------------------------- Luxembourg
def _validate_lu_national_id(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 13 or not _valid_day_month(int(v[6:8]), int(v[4:6])):
        return False
    return _plain_luhn(v[:12]) and verhoeff_check(v)


# --------------------------------------------------------------------------- Denmark
def _validate_dk_cpr(text: str) -> Optional[bool]:
    v = digits_only(text)
    if len(v) != 10 or not _valid_day_month(int(v[0:2]), int(v[2:4])):
        return False
    # the modulus-11 rule stopped being guaranteed in 2007: a pass is proof, a failure is not
    return True if _weighted(v, (4, 3, 2, 7, 6, 5, 4, 3, 2, 1)) % 11 == 0 else None


# --------------------------------------------------------------------------- Norway
def _validate_no_fodselsnummer(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 11:
        return False
    d = [int(c) for c in v]
    dd, mm = d[0] * 10 + d[1], d[2] * 10 + d[3]
    if dd > 40:
        dd -= 40  # D-number
    if mm > 40:
        mm -= 40  # H-number
    if not _valid_day_month(dd, mm):
        return False
    k1 = 11 - (_weighted(v, (3, 7, 6, 1, 8, 9, 4, 5, 2)) % 11)
    if k1 == 11:
        k1 = 0
    if k1 == 10 or k1 != d[9]:
        return False
    k2 = 11 - (_weighted(v, (5, 4, 3, 2, 7, 6, 5, 4, 3, 2)) % 11)
    if k2 == 11:
        k2 = 0
    return k2 != 10 and k2 == d[10]


# --------------------------------------------------------------------------- Iceland
def _validate_is_kennitala(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 10:
        return False
    dd = int(v[0:2])
    if dd > 40:
        dd -= 40  # company numbers
    if not _valid_day_month(dd, int(v[2:4])):
        return False
    c = 11 - (_weighted(v, (3, 2, 7, 6, 5, 4, 3, 2)) % 11)
    if c == 11:
        c = 0
    return c != 10 and c == int(v[8]) and v[9] in "089"


# --------------------------------------------------------------------------- Czech Republic / Slovakia
def _validate_rodne_cislo(text: str) -> Optional[bool]:
    v = digits_only(text)
    if len(v) == 9:
        return None  # pre-1954 numbers carry no check digit
    if len(v) != 10:
        return False
    mm = int(v[2:4])
    for offset in (70, 50, 20):
        if mm > offset:
            mm -= offset
            break
    if not _valid_day_month(int(v[4:6]), mm):
        return False
    return int(v) % 11 == 0


# --------------------------------------------------------------------------- Hungary
def _validate_hu_taj(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 9:
        return False
    total = sum(int(v[i]) * (3 if i % 2 == 0 else 7) for i in range(8))
    return total % 10 == int(v[8])


# --------------------------------------------------------------------------- Romania
def _validate_ro_cnp(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 13 or v[0] == "0" or not _valid_day_month(int(v[5:7]), int(v[3:5])):
        return False
    r = _weighted(v, (2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9)) % 11
    return int(v[12]) == (1 if r == 10 else r)


# --------------------------------------------------------------------------- Greece
def _validate_gr_amka(text: str) -> bool:
    v = digits_only(text)
    return len(v) == 11 and _valid_day_month(int(v[0:2]), int(v[2:4])) and _plain_luhn(v)


# --------------------------------------------------------------------------- Bulgaria
def _validate_bg_egn(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 10:
        return False
    mm = int(v[2:4])
    if mm > 40:
        mm -= 40
    elif mm > 20:
        mm -= 20
    if not _valid_day_month(int(v[4:6]), mm):
        return False
    r = _weighted(v, (2, 4, 8, 5, 10, 9, 7, 3, 6)) % 11
    return int(v[9]) == (0 if r == 10 else r)


# --------------------------------------------------------------------------- Croatia
def _validate_hr_oib(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 11:
        return False
    a = 10
    for ch in v[:10]:
        a = (a + int(ch)) % 10
        if a == 0:
            a = 10
        a = (a * 2) % 11
    check = 11 - a
    if check == 10:
        check = 0
    return check == int(v[10])


# --------------------------------------------------------------------------- Serbia / Slovenia (JMBG / EMSO)
def _validate_jmbg(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 13 or not _valid_day_month(int(v[0:2]), int(v[2:4])):
        return False
    m = 11 - (_weighted(v, (7, 6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2)) % 11)
    if m == 10:
        return False
    if m == 11:
        m = 0
    return m == int(v[12])


# --------------------------------------------------------------------------- Lithuania / Estonia
def _validate_baltic_personal_code(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 11 or not _valid_day_month(int(v[5:7]), int(v[3:5])):
        return False
    r = _weighted(v, (1, 2, 3, 4, 5, 6, 7, 8, 9, 1)) % 11
    if r == 10:
        r = _weighted(v, (3, 4, 5, 6, 7, 8, 9, 1, 2, 3)) % 11
        if r == 10:
            r = 0
    return r == int(v[10])


# --------------------------------------------------------------------------- Latvia
def _validate_lv_personas_kods(text: str) -> Optional[bool]:
    v = digits_only(text)
    if len(v) != 11:
        return False
    if v.startswith("32"):
        return None  # 2017+ format without a birth date or public check rule
    if not _valid_day_month(int(v[0:2]), int(v[2:4])):
        return False
    total = _weighted(v, (1, 6, 3, 7, 9, 10, 5, 8, 4, 2))
    return True if ((1101 - total) % 11) % 10 == int(v[10]) else None


# --------------------------------------------------------------------------- Russia
def _validate_ru_inn(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 12:
        return False
    n11 = (_weighted(v, (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)) % 11) % 10
    n12 = (_weighted(v, (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)) % 11) % 10
    return n11 == int(v[10]) and n12 == int(v[11])


def _validate_ru_snils(text: str) -> Optional[bool]:
    v = digits_only(text)
    if len(v) != 11:
        return False
    number, check = v[:9], int(v[9:])
    if int(number) <= 1001998:
        return None  # numbers up to 001-001-998 are not checked
    total = sum(int(number[i]) * (9 - i) for i in range(9))
    if total < 100:
        expected = total
    elif total in (100, 101):
        expected = 0
    else:
        expected = total % 101
        if expected == 100:
            expected = 0
    return expected == check


# --------------------------------------------------------------------------- Ukraine
def _validate_ua_rntrc(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 10:
        return False
    return (_weighted(v, (-1, 5, 7, 9, 4, 6, 10, 5, 7)) % 11) % 10 == int(v[9])


# --------------------------------------------------------------------------- Spain (social security)
def _validate_es_nuss(text: str) -> bool:
    v = digits_only(text)
    return len(v) == 12 and int(v[:10]) % 97 == int(v[10:])


# --------------------------------------------------------------------------- United Kingdom (UTR)
def _validate_gb_utr(text: str) -> Optional[bool]:
    v = digits_only(text)
    if len(v) != 10:
        return False
    r = _weighted(v[1:], (6, 7, 8, 9, 10, 5, 4, 3, 2)) % 11
    return True if v[0] == "21987654321"[r] else None


def _rule(name, region, description, patterns, context, validator=None, field_hint=None, examples=(), category=_REGIONAL, severity="Critical"):
    return Rule(
        name=name, category=category, severity=severity, region=region, description=description,
        patterns=patterns, context=context, validator=validator, field_hint=field_hint, examples=list(examples),
    )


RULES = [
    _rule(
        "FR_NIR", "FR", "French social security number (NIR / INSEE): 13 digits + 2-digit key = 97 - (number mod 97), Corsica 2A/2B mapped to 19/18.",
        [
            Pattern("NIR (formatted)", r"\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|[2-9]\d)\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}\s?\d{2}\b", 0.4),
        ],
        ["nir", "insee", "sécurité sociale", "securite sociale", "numéro de sécurité", "social security", "carte vitale", "assuré", "numéro ss"],
        _validate_fr_nir, r"(?<![a-z])nir(?![a-z])|insee|secu|securite_?sociale|numero_?ss|sec_?soc", ["1 85 05 78 006 084 91", "291062A00412319"],  # pragma: allowlist secret
    ),
    _rule(
        "FR_PASSPORT", "FR", "French passport number: 2 digits, 2 letters, 5 digits (needs context).",
        [Pattern("FR passport (weak)", r"\b\d{2}[A-Z]{2}\d{5}\b", 0.1)],
        ["passport", "passeport", "travel document"], None, r"passport|passeport", ["12CB34567"], severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "NL_BSN", "NL", "Dutch citizen service number (BSN): 9 digits passing the 11-proef.",
        [Pattern("BSN (formatted)", r"\b\d{4}[. ]\d{2}[. ]\d{3}\b", 0.3), Pattern("BSN (weak)", r"\b\d{9}\b", 0.05)],
        ["bsn", "burgerservicenummer", "burger service nummer", "sofinummer", "sofi", "citizen service number", "sofi-nummer"],
        _validate_nl_bsn, r"(?<![a-z])bsn(?![a-z])|burgerservice|sofi", ["327440430", "9823.38.430"],  # pragma: allowlist secret
    ),
    _rule(
        "BE_NATIONAL_NUMBER", "BE", "Belgian national register number: YY.MM.DD-XXX.CC with check 97 - (number mod 97), 2000+ births prefixed by 2.",
        [Pattern("Rijksregister (formatted)", r"\b\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}\b", 0.5), Pattern("Rijksregister (weak)", r"\b\d{11}\b", 0.05)],
        ["rijksregisternummer", "rijksregister", "numéro national", "numero national", "national number", "registre national", "insz", "niss", "nn"],
        _validate_be_national_number, r"rijksregister|(?<![a-z])insz(?![a-z])|(?<![a-z])niss(?![a-z])|national_?number|numero_?national|registre_?national", ["85.07.30-839.95", "05.07.30-035.24"],  # pragma: allowlist secret
    ),
    _rule(
        "CH_AHV", "CH", "Swiss AHV/AVS social insurance number: 756.XXXX.XXXX.XC with an EAN-13 check digit.",
        [Pattern("AHV (formatted)", r"\b756\.\d{4}\.\d{4}\.\d{2}\b", 0.5), Pattern("AHV (weak)", r"\b756\d{10}\b", 0.2)],
        ["ahv", "avs", "ahv-nummer", "versichertennummer", "numéro avs", "social security", "sozialversicherungsnummer"],
        _validate_ch_ahv, r"(?<![a-z])ahv(?![a-z])|(?<![a-z])avs(?![a-z])|versicherten", ["756.0930.6547.71", "7566844558419"],  # pragma: allowlist secret
    ),
    _rule(
        "AT_SVNR", "AT", "Austrian social insurance number (SVNR): 3-digit serial, check digit, DDMMYY; weighted modulus-11 check.",
        [Pattern("SVNR", r"\b\d{4}\s?(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}\b", 0.3)],
        ["sozialversicherungsnummer", "svnr", "sv-nummer", "versicherungsnummer", "social security", "sozialversicherung"],
        _validate_at_svnr, r"svnr|sozialversicherung|sv_?nummer|versicherungsnummer", ["7014010180", "4408 300785"],  # pragma: allowlist secret
    ),
    _rule(
        "IE_PPS", "IE", "Irish Personal Public Service number: 7 digits + 1-2 letters, modulus-23 check letter.",
        [Pattern("PPS", r"\b\d{7}[A-Z]{1,2}\b", 0.3)],
        ["pps", "ppsn", "personal public service", "revenue", "social welfare", "pps number"],
        _validate_ie_pps, r"(?<![a-z])pps(?:n)?(?![a-z])", ["1869536B"],  # pragma: allowlist secret
    ),
    _rule(
        "PT_NIF", "PT", "Portuguese tax identification number (NIF / NIPC): 9 digits with a modulus-11 check digit.",
        [Pattern("NIF (formatted)", r"\b[1235689]\d{2}\s\d{3}\s\d{3}\b", 0.3), Pattern("NIF (weak)", r"\b[1235689]\d{8}\b", 0.05)],
        ["nif", "número de identificação fiscal", "numero de identificacao fiscal", "contribuinte", "número de contribuinte", "tax number", "nipc"],
        _validate_pt_nif, r"(?<![a-z])nif(?![a-z])|contribuinte|(?<![a-z])nipc(?![a-z])", ["207512280", "165 170 336"], severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "LU_NATIONAL_ID", "LU", "Luxembourg national identification number (matricule): YYYYMMDD + 3 digits + Luhn + Verhoeff check digits.",
        [Pattern("Matricule", r"\b(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{5}\b", 0.3)],
        ["matricule", "numéro d'identification national", "numero d'identification", "ccss", "national identification number", "luxembourg"],
        _validate_lu_national_id, r"matricule|(?<![a-z])ccss(?![a-z])", ["1985073037685"],  # pragma: allowlist secret
    ),
    _rule(
        "DK_CPR", "DK", "Danish CPR number: DDMMYY-SSSS; the historical modulus-11 check proves a number but no longer disproves one.",
        [Pattern("CPR (formatted)", r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}-\d{4}\b", 0.4), Pattern("CPR (weak)", r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{6}\b", 0.05)],
        ["cpr", "cpr-nummer", "cpr-nr", "personnummer", "civil registration"],
        _validate_dk_cpr, r"(?<![a-z])cpr(?![a-z])|personnummer", ["300785-6023", "3007850424"],  # pragma: allowlist secret
    ),
    _rule(
        "NO_FODSELSNUMMER", "NO", "Norwegian national identity number (fødselsnummer / D-number): DDMMYY + 5 digits with two modulus-11 check digits.",
        [Pattern("Fødselsnummer", r"\b(?:0[1-9]|[12]\d|3[01]|[4-6]\d|7[01])(?:0[1-9]|1[0-2]|4[1-9]|5[0-2])\d{7}\b", 0.3)],
        ["fødselsnummer", "fodselsnummer", "personnummer", "d-nummer", "national identity number", "fnr"],
        _validate_no_fodselsnummer, r"f(?:ø|o)dselsnummer|personnummer|d_?nummer|(?<![a-z])fnr(?![a-z])", ["30078508864"],  # pragma: allowlist secret
    ),
    _rule(
        "IS_KENNITALA", "IS", "Icelandic kennitala: DDMMYY-NNCM with a modulus-11 check digit and century digit 0/8/9.",
        [Pattern("Kennitala (formatted)", r"\b(?:0[1-9]|[12]\d|3[01]|[4-6]\d|7[01])(?:0[1-9]|1[0-2])\d{2}-\d{4}\b", 0.4), Pattern("Kennitala (weak)", r"\b(?:0[1-9]|[12]\d|3[01]|[4-6]\d|7[01])(?:0[1-9]|1[0-2])\d{6}\b", 0.05)],
        ["kennitala", "kt", "kt.", "icelandic id", "national id"],
        _validate_is_kennitala, r"kennitala|(?<![a-z])kt(?![a-z])", ["300785-3529", "3007850690"],  # pragma: allowlist secret
    ),
    _rule(
        "CZ_RODNE_CISLO", "CZ", "Czech birth number (rodné číslo): YYMMDD/XXXX divisible by 11; women carry month + 50.",
        [Pattern("Rodné číslo (formatted)", r"\b\d{2}(?:0[1-9]|1[0-2]|2[1-9]|3[0-2]|5[1-9]|6[0-2]|7[1-9]|8[0-2])(?:0[1-9]|[12]\d|3[01])/\d{3,4}\b", 0.5), Pattern("Rodné číslo (weak)", r"\b\d{2}(?:0[1-9]|1[0-2]|5[1-9]|6[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}\b", 0.05)],
        ["rodné číslo", "rodne cislo", "rodné", "birth number", "rč", "r.č.", "personal number"],
        _validate_rodne_cislo, r"rodne_?cislo|rodn|birth_?number|(?<![a-z])rc(?![a-z])", ["850730/3387", "8557307440"],  # pragma: allowlist secret
    ),
    _rule(
        "SK_RODNE_CISLO", "SK", "Slovak birth number (rodné číslo): YYMMDD/XXXX divisible by 11; women carry month + 50.",
        [Pattern("Rodné číslo (formatted)", r"\b\d{2}(?:0[1-9]|1[0-2]|2[1-9]|3[0-2]|5[1-9]|6[0-2]|7[1-9]|8[0-2])(?:0[1-9]|[12]\d|3[01])/\d{3,4}\b", 0.5), Pattern("Rodné číslo (weak)", r"\b\d{2}(?:0[1-9]|1[0-2]|5[1-9]|6[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}\b", 0.05)],
        ["rodné číslo", "rodne cislo", "rodné", "birth number", "rč", "r.č.", "personal number"],
        _validate_rodne_cislo, r"rodne_?cislo|rodn|birth_?number|(?<![a-z])rc(?![a-z])", ["850730/4949"],  # pragma: allowlist secret
    ),
    _rule(
        "HU_TAJ", "HU", "Hungarian social insurance number (TAJ): 9 digits; odd positions x3 + even positions x7, mod 10 = check digit.",
        [Pattern("TAJ (formatted)", r"\b\d{3}[ -]\d{3}[ -]\d{3}\b", 0.2), Pattern("TAJ (weak)", r"\b\d{9}\b", 0.05)],
        ["taj", "taj szám", "tajszám", "tajszam", "társadalombiztosítási", "social insurance"],
        _validate_hu_taj, r"(?<![a-z])taj(?![a-z])", ["158-691-589", "629 721 843"],  # pragma: allowlist secret
    ),
    _rule(
        "RO_CNP", "RO", "Romanian personal numeric code (CNP): S YYMMDD JJ NNN C, weighted modulus-11 check (10 -> 1).",
        [Pattern("CNP", r"\b[1-9]\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|[1-4]\d|5[12])\d{4}\b", 0.3)],
        ["cnp", "cod numeric personal", "personal numeric code", "buletin"],
        _validate_ro_cnp, r"(?<![a-z])cnp(?![a-z])|cod_?numeric", ["1850730129001"],  # pragma: allowlist secret
    ),
    _rule(
        "GR_AMKA", "GR", "Greek social security number (AMKA): DDMMYY + 5 digits with a Luhn check digit.",
        [Pattern("AMKA", r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}\d{5}\b", 0.2)],
        ["amka", "αμκα", "social security", "ασφάλισης", "αριθμός μητρώου"],
        _validate_gr_amka, r"(?<![a-z])amka(?![a-z])", ["30078564025"],  # pragma: allowlist secret
    ),
    _rule(
        "BG_EGN", "BG", "Bulgarian unified civil number (EGN): YYMMDD RRR C with a weighted modulus-11 check; month + 40 for 2000+ births.",
        [Pattern("EGN", r"\b\d{2}(?:0[1-9]|1[0-2]|2[1-9]|3[0-2]|4[1-9]|5[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}\b", 0.3)],
        ["egn", "егн", "единен граждански номер", "unified civil number", "civil number"],
        _validate_bg_egn, r"(?<![a-z])egn(?![a-z])", ["8507309252", "0547303161"],  # pragma: allowlist secret
    ),
    _rule(
        "HR_OIB", "HR", "Croatian personal identification number (OIB): 11 digits, ISO 7064 MOD 11,10 check.",
        [Pattern("OIB (weak)", r"\b\d{11}\b", 0.05)],
        ["oib", "osobni identifikacijski broj", "personal identification number"],
        _validate_hr_oib, r"(?<![a-z])oib(?![a-z])", ["59699813869"],  # pragma: allowlist secret
    ),
    _rule(
        "RS_JMBG", "RS", "Serbian (and Bosnian, Montenegrin, Macedonian) unique master citizen number (JMBG): 13 digits with a weighted modulus-11 check.",
        [Pattern("JMBG", r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{3}\d{2}\d{3}\d\b", 0.3)],
        ["jmbg", "jedinstveni matični broj", "maticni broj", "matični broj", "јмбг"],
        _validate_jmbg, r"(?<![a-z])jmbg(?![a-z])|maticni", ["3007985715268"],  # pragma: allowlist secret
    ),
    _rule(
        "SI_EMSO", "SI", "Slovenian unique master citizen number (EMŠO): 13 digits with a weighted modulus-11 check.",
        [Pattern("EMŠO", r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{3}\d{2}\d{3}\d\b", 0.3)],
        ["emšo", "emso", "enotna matična številka", "maticna stevilka"],
        _validate_jmbg, r"(?<![a-z])em[sš]o(?![a-z])|maticna", ["3007985509927"],  # pragma: allowlist secret
    ),
    _rule(
        "LT_ASMENS_KODAS", "LT", "Lithuanian personal code (asmens kodas): G YYMMDD NNN C with a two-pass weighted modulus-11 check.",
        [Pattern("Asmens kodas", r"\b[1-6]\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}\b", 0.3)],
        ["asmens kodas", "asmens", "personal code", "a.k."],
        _validate_baltic_personal_code, r"asmens|personal_?code", ["38507305736"],  # pragma: allowlist secret
    ),
    _rule(
        "EE_ISIKUKOOD", "EE", "Estonian personal identification code (isikukood): G YYMMDD NNN C with a two-pass weighted modulus-11 check.",
        [Pattern("Isikukood", r"\b[1-8]\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}\b", 0.3)],
        ["isikukood", "personal identification code", "ik", "personal code"],
        _validate_baltic_personal_code, r"isikukood|(?<![a-z])ik(?![a-z])", ["48507303471"],  # pragma: allowlist secret
    ),
    _rule(
        "LV_PERSONAS_KODS", "LV", "Latvian personal code (personas kods): DDMMYY-XNNNC; the pre-2017 check digit proves a number, the 32-prefixed format has none.",
        [Pattern("Personas kods (formatted)", r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}-[0-2]\d{4}\b", 0.4), Pattern("Personas kods (new)", r"\b32\d{4}-\d{5}\b", 0.3)],
        ["personas kods", "personal code", "pk", "personu kods"],
        _validate_lv_personas_kods, r"personas_?kods|personal_?code", ["300785-10631", "320001-97321"],  # pragma: allowlist secret
    ),
    _rule(
        "RU_INN", "RU", "Russian individual taxpayer number (INN): 12 digits with two weighted modulus-11 check digits.",
        [Pattern("INN (weak)", r"\b\d{12}\b", 0.05)],
        ["inn", "инн", "идентификационный номер налогоплательщика", "taxpayer number", "налогоплательщика"],
        _validate_ru_inn, r"(?<![a-z])inn(?![a-z])|инн", ["877177211053"], severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "RU_SNILS", "RU", "Russian pension insurance number (SNILS): XXX-XXX-XXX YY with a modulus-101 check.",
        [Pattern("SNILS (formatted)", r"\b\d{3}-\d{3}-\d{3}[ -]?\d{2}\b", 0.5), Pattern("SNILS (weak)", r"\b\d{11}\b", 0.05)],
        ["snils", "снилс", "страховой номер", "pension insurance", "страховое свидетельство"],
        _validate_ru_snils, r"snils|снилс", ["602-167-309 49", "765-194-237-30"],  # pragma: allowlist secret
    ),
    _rule(
        "UA_RNTRC", "UA", "Ukrainian taxpayer registration number (RNTRC / IPN): 10 digits with a weighted modulus-11 check.",
        [Pattern("RNTRC (weak)", r"\b\d{10}\b", 0.05)],
        ["rntrc", "ipn", "рнокпп", "ідентифікаційний код", "ідентифікаційний номер", "taxpayer", "ipn code"],
        _validate_ua_rntrc, r"rntrc|(?<![a-z])ipn(?![a-z])|рнокпп", ["0735771566"], severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "ES_NUSS", "ES", "Spanish social security number (NUSS / NAF): 2-digit province + 8 digits + 2 check digits (number mod 97).",
        [Pattern("NUSS (formatted)", r"\b\d{2}[ /-]\d{8}[ /-]\d{2}\b", 0.4), Pattern("NUSS (weak)", r"\b\d{12}\b", 0.05)],
        ["seguridad social", "número de la seguridad social", "nuss", "naf", "social security", "afiliación"],
        _validate_es_nuss, r"(?<![a-z])nuss(?![a-z])|(?<![a-z])naf(?![a-z])|seguridad_?social", ["28-74663217-26", "28/17420861/86"],  # pragma: allowlist secret
    ),
    _rule(
        "GB_UTR", "GB", "UK unique taxpayer reference (UTR): 10 digits; the leading check digit proves a number when the modulus-11 rule holds.",
        [Pattern("UTR (weak)", r"\b\d{5}\s?\d{5}\b", 0.05)],
        ["utr", "unique taxpayer reference", "self assessment", "hmrc", "taxpayer reference"],
        _validate_gb_utr, r"(?<![a-z])utr(?![a-z])|taxpayer_?ref", ["5129497082", "19375 27152"], severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "GB_SORT_CODE", "GB", "UK bank sort code: NN-NN-NN, reported only next to banking context or a bank account.",
        [Pattern("Sort code", r"\b\d{2}-\d{2}-\d{2}\b", 0.3)],
        ["sort code", "sortcode", "sort-code", "bank", "account number", "branch"],
        None, r"sort_?code", ["12-34-56"], category=_FINANCIAL, severity="Medium",  # pragma: allowlist secret
    ),
]
