"""
Asia-Pacific identifiers: JP CN HK TW ID MY VN PK LK NZ, plus Australian and
Indian additions (IHI, BSB, IFSC, UPI). Validators follow the public
check-digit algorithms; date-only identifiers validate their embedded date.
"""
from typing import Optional

from src.engine.rules import Pattern, Rule
from src.engine.validators import digits_only

_REGIONAL = "Regional Compliance"
_FINANCIAL = "Financial Data"
_PHI = "Healthcare Data (PHI)"
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


def _valid_day_month(dd: int, mm: int) -> bool:
    return 1 <= mm <= 12 and 1 <= dd <= _MONTH_DAYS[mm - 1]


# --------------------------------------------------------------------------- Japan
def _validate_jp_my_number(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 12:
        return False
    p = [int(c) for c in reversed(v[:11])]  # p1 = rightmost body digit
    total = sum(p[n - 1] * ((n + 1) if n <= 6 else (n - 5)) for n in range(1, 12))
    r = total % 11
    return int(v[11]) == (0 if r <= 1 else 11 - r)


# --------------------------------------------------------------------------- China
def _validate_cn_resident_id(text: str) -> bool:
    v = text.upper()
    if len(v) != 18 or not v[:17].isdigit():
        return False
    if not _valid_day_month(int(v[12:14]), int(v[10:12])) or not 1900 <= int(v[6:10]) <= 2100:
        return False
    total = sum(int(c) * w for c, w in zip(v[:17], (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)))
    return v[17] == "10X98765432"[total % 11]


# --------------------------------------------------------------------------- Hong Kong
def _validate_hk_hkid(text: str) -> bool:
    v = text.upper().replace("(", "").replace(")", "")
    letters = v[:-7] if len(v) == 9 else v[:-7]
    body = v[len(letters):]
    if len(body) != 7 or not body[:6].isdigit() or body[6] not in "0123456789A" or not 1 <= len(letters) <= 2 or not letters.isalpha():
        return False
    values = [36] * (2 - len(letters)) + [ord(c) - 55 for c in letters] + [int(c) for c in body[:6]]
    total = sum(val * w for val, w in zip(values, (9, 8, 7, 6, 5, 4, 3, 2)))
    check = (11 - total % 11) % 11
    return body[6] == ("A" if check == 10 else str(check))


# --------------------------------------------------------------------------- Taiwan
_TW_LETTERS = {
    "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15, "G": 16, "H": 17, "I": 34, "J": 18, "K": 19, "L": 20, "M": 21,
    "N": 22, "O": 35, "P": 23, "Q": 24, "R": 25, "S": 26, "T": 27, "U": 28, "V": 29, "W": 32, "X": 30, "Y": 31, "Z": 33,
}


def _validate_tw_national_id(text: str) -> bool:
    v = text.upper()
    if len(v) != 10 or v[0] not in _TW_LETTERS or not v[1:].isdigit():
        return False
    n = _TW_LETTERS[v[0]]
    total = (n // 10) + (n % 10) * 9 + sum(int(c) * w for c, w in zip(v[1:9], (8, 7, 6, 5, 4, 3, 2, 1))) + int(v[9])
    return total % 10 == 0


# --------------------------------------------------------------------------- Indonesia
def _validate_id_nik(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 16:
        return False
    dd = int(v[6:8])
    if dd > 40:
        dd -= 40
    return _valid_day_month(dd, int(v[8:10]))


# --------------------------------------------------------------------------- Malaysia
_MY_PLACE_CODES = set(range(1, 17)) | set(range(21, 60)) | set(range(60, 69)) | {71, 72} | set(range(74, 79)) | set(range(82, 94)) | {98, 99}


def _validate_my_mykad(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 12:
        return False
    return _valid_day_month(int(v[4:6]), int(v[2:4])) and int(v[6:8]) in _MY_PLACE_CODES


# --------------------------------------------------------------------------- Sri Lanka
def _validate_lk_nic(text: str) -> bool:
    v = text.upper()
    if len(v) == 10 and v[:9].isdigit() and v[9] in "VX":
        doy = int(v[2:5])
    elif len(v) == 12 and v.isdigit():
        doy = int(v[4:7])
    else:
        return False
    if doy > 500:
        doy -= 500
    return 1 <= doy <= 366


# --------------------------------------------------------------------------- New Zealand
def _validate_nz_ird(text: str) -> bool:
    v = digits_only(text)
    if len(v) == 8:
        v = "0" + v
    if len(v) != 9 or not 10_000_000 <= int(v) <= 150_000_000:
        return False
    r = sum(int(d) * w for d, w in zip(v[:8], (3, 2, 7, 6, 5, 4, 3, 2))) % 11
    c = 0 if r == 0 else 11 - r
    if c == 10:
        r = sum(int(d) * w for d, w in zip(v[:8], (7, 4, 3, 2, 5, 2, 7, 6))) % 11
        c = 0 if r == 0 else 11 - r
        if c == 10:
            return False
    return c == int(v[8])


_NHI_LETTERS = "ABCDEFGHJKLMNPQRSTUVWXYZ"  # pragma: allowlist secret


def _validate_nz_nhi(text: str) -> Optional[bool]:
    v = text.upper()
    if len(v) != 7 or any(c not in _NHI_LETTERS for c in v[:3]):
        return False
    if not v[3:].isdigit():
        return None  # 2022+ format (two digits + two letters) uses a different check
    total = sum((_NHI_LETTERS.index(c) + 1) * w for c, w in zip(v[:3], (7, 6, 5))) + sum(int(c) * w for c, w in zip(v[3:6], (4, 3, 2)))
    r = total % 11
    if r == 0:
        return False
    check = 11 - r
    return check != 10 and check == int(v[6])


# --------------------------------------------------------------------------- Australia (IHI)
def _validate_au_ihi(text: str) -> bool:
    v = digits_only(text)
    return len(v) == 16 and v.startswith("800360") and _plain_luhn(v)


def _rule(name, region, description, patterns, context, validator=None, field_hint=None, examples=(), category=_REGIONAL, severity="Critical"):
    return Rule(
        name=name, category=category, severity=severity, region=region, description=description,
        patterns=patterns, context=context, validator=validator, field_hint=field_hint, examples=list(examples),
    )


RULES = [
    _rule(
        "JP_MY_NUMBER", "JP", "Japanese individual number (My Number): 12 digits with a weighted modulus-11 check digit.",
        [Pattern("My Number (formatted)", r"\b\d{4}[ -]\d{4}[ -]\d{4}\b", 0.3), Pattern("My Number (weak)", r"\b\d{12}\b", 0.05)],
        ["my number", "mynumber", "マイナンバー", "個人番号", "individual number", "kojin bango"],
        _validate_jp_my_number, r"my_?number|kojin|個人番号|マイナンバー", ["6648-5526-0102", "305145228528"],  # pragma: allowlist secret
    ),
    _rule(
        "JP_PASSPORT", "JP", "Japanese passport number: 2 letters + 7 digits; needs context.",
        [Pattern("JP passport (weak)", r"\b[A-Z]{2}\d{7}\b", 0.1)],
        ["passport", "パスポート", "旅券", "travel document"], None, r"passport|旅券", ["TK1234567"], severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "CN_RESIDENT_ID", "CN", "Chinese resident identity card number: 6-digit region + birth date + sequence + ISO 7064 MOD 11-2 check.",
        [Pattern("Resident ID", r"\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dX]\b", 0.5)],
        ["身份证", "居民身份证", "id card", "resident identity", "national id", "sfz", "shenfenzheng", "证件号"],
        _validate_cn_resident_id, r"(?<![a-z])sfz(?![a-z])|shenfen|id_?card|身份证|证件号", ["110105194912315912", "440302198507306218"],  # pragma: allowlist secret
    ),
    _rule(
        "HK_HKID", "HK", "Hong Kong identity card number: 1-2 letters + 6 digits + check digit (modulus 11, A for 10).",
        [Pattern("HKID", r"\b[A-Z]{1,2}\d{6}\(?[\dA]\)?(?![A-Z0-9])", 0.5)],
        ["hkid", "hong kong identity", "identity card", "身份證", "hkid number"],
        _validate_hk_hkid, r"hkid|identity_?card|身份證", ["U100503(8)", "XB9814272"],  # pragma: allowlist secret
    ),
    _rule(
        "TW_NATIONAL_ID", "TW", "Taiwanese national identification number: 1 letter + 9 digits with a weighted modulus-10 check.",
        [Pattern("National ID", r"\b[A-Z][12]\d{8}\b", 0.4)],
        ["national id", "身分證", "身分證字號", "id number", "arc", "national identification"],
        _validate_tw_national_id, r"national_?id|身分證|id_?number", ["P184145123", "B293059079"],  # pragma: allowlist secret
    ),
    _rule(
        "ID_NIK", "ID", "Indonesian population identity number (NIK): 6-digit region + DDMMYY (women: day + 40) + 4-digit sequence.",
        [Pattern("NIK", r"\b\d{6}(?:0[1-9]|[12]\d|3[01]|4[1-9]|[56]\d|7[01])(?:0[1-9]|1[0-2])\d{2}\d{4}\b", 0.2)],
        ["nik", "nomor induk kependudukan", "ktp", "e-ktp", "kartu tanda penduduk"],
        _validate_id_nik, r"(?<![a-z])nik(?![a-z])|(?<![a-z])ktp(?![a-z])", ["3171013007851796", "3171017007854858"],  # pragma: allowlist secret
    ),
    _rule(
        "MY_MYKAD", "MY", "Malaysian identity card number (MyKad / NRIC): YYMMDD-PB-####, place-of-birth code validated.",
        [Pattern("MyKad (formatted)", r"\b\d{6}-\d{2}-\d{4}\b", 0.4), Pattern("MyKad (weak)", r"\b\d{12}\b", 0.05)],
        ["mykad", "ic number", "nric", "kad pengenalan", "no. kp", "no kp", "identity card"],
        _validate_my_mykad, r"mykad|(?<![a-z])ic_?(?:no|number)(?![a-z])|nric|kad_?pengenalan|no_?kp", ["850730-14-6563", "850730141380"],  # pragma: allowlist secret
    ),
    _rule(
        "VN_CCCD", "VN", "Vietnamese citizen identity number (CCCD): 3-digit province + century/gender digit + 2-digit year + 6 digits; needs context.",
        [Pattern("CCCD", r"\b0(?:0[1-9]|[1-8]\d|9[0-6])[0-3]\d{2}\d{6}\b", 0.2)],
        ["cccd", "cmnd", "căn cước công dân", "can cuoc cong dan", "chứng minh nhân dân", "citizen id", "so cccd"],
        None, r"cccd|cmnd|can_?cuoc|chung_?minh", ["001085445493"],  # pragma: allowlist secret
    ),
    _rule(
        "PK_CNIC", "PK", "Pakistani computerised national identity card number (CNIC): XXXXX-XXXXXXX-X; no public check digit.",
        [Pattern("CNIC (formatted)", r"\b\d{5}-\d{7}-\d\b", 0.5), Pattern("CNIC (weak)", r"\b\d{13}\b", 0.05)],
        ["cnic", "nadra", "national identity card", "shanakhti card", "nic number"],
        None, r"cnic|nadra|national_?id", ["47569-2034040-8"],  # pragma: allowlist secret
    ),
    _rule(
        "LK_NIC", "LK", "Sri Lankan national identity card number: old 9 digits + V/X or new 12 digits; day-of-year validated (women + 500).",
        [Pattern("NIC (old)", r"\b\d{9}[VX]\b", 0.4), Pattern("NIC (new)", r"\b(?:19|20)\d{2}\d{8}\b", 0.2)],
        ["nic", "national identity card", "identity card", "nic number"],
        _validate_lk_nic, r"(?<![a-z])nic(?![a-z])|identity_?card", ["851238112V", "198512340989"],  # pragma: allowlist secret
    ),
    _rule(
        "NZ_IRD", "NZ", "New Zealand inland revenue number (IRD): 8-9 digits with a two-pass weighted modulus-11 check.",
        [Pattern("IRD (formatted)", r"\b\d{2,3}-\d{3}-\d{3}\b", 0.3), Pattern("IRD (weak)", r"\b\d{8,9}\b", 0.05)],
        ["ird", "inland revenue", "ird number", "tax number"],
        _validate_nz_ird, r"(?<![a-z])ird(?![a-z])|inland_?revenue", ["49-091-850", "49091508"], severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "NZ_NHI", "NZ", "New Zealand national health index number (NHI): 3 letters + 4 digits (modulus-11 check) or 2 digits + 2 letters.",
        [Pattern("NHI", r"\b[A-HJ-NP-Z]{3}\d{2}(?:\d{2}|[A-HJ-NP-Z]{2})\b", 0.3)],
        ["nhi", "national health index", "health index", "nhi number", "patient"],
        _validate_nz_nhi, r"(?<![a-z])nhi(?![a-z])|health_?index", ["ZYC4527"], category=_PHI, severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "AU_IHI", "AU", "Australian individual healthcare identifier (IHI): 16 digits starting 800360 with a Luhn check digit.",
        [Pattern("IHI (formatted)", r"\b8003[ ]?60\d{2}[ ]?\d{4}[ ]?\d{4}\b", 0.5), Pattern("IHI", r"\b800360\d{10}\b", 0.4)],
        ["ihi", "individual healthcare identifier", "healthcare identifier", "medicare", "my health record"],
        _validate_au_ihi, r"(?<![a-z])ihi(?![a-z])|healthcare_?identifier", ["8003 6012 3456 7852"], category=_PHI, severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "AU_BSB", "AU", "Australian bank-state-branch code (BSB): NNN-NNN; reported only next to banking context.",
        [Pattern("BSB", r"\b\d{3}-\d{3}\b", 0.2)],
        ["bsb", "bank state branch", "bsb number", "account number", "bank"],
        None, r"(?<![a-z])bsb(?![a-z])", ["062-000"], category=_FINANCIAL, severity="Medium",  # pragma: allowlist secret
    ),
    _rule(
        "IN_IFSC", "IN", "Indian financial system code (IFSC): 4-letter bank code, 0, 6-character branch code.",
        [Pattern("IFSC", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", 0.3)],
        ["ifsc", "ifsc code", "bank", "branch", "neft", "rtgs", "imps"],
        None, r"ifsc", ["HDFC0001234"], category=_FINANCIAL, severity="Low",  # pragma: allowlist secret
    ),
    _rule(
        "IN_UPI_ID", "IN", "Indian UPI virtual payment address: handle@bank-psp (okaxis, ybl, paytm, upi ...).",
        [
            Pattern(
                "UPI VPA",
                r"\b[a-z0-9._-]{3,50}@(?:okaxis|okhdfcbank|okicici|oksbi|ybl|upi|paytm|ibl|axl|apl|fbl|hdfcbank|icici|sbi|axisbank|kotak|barodampay|jio|airtel|pnb|yesbank|indus|federal|idbi|kbl|cnrb|boi|iob|uco|ptaxis|ptyes|ptsbi)\b",
                0.6,
            ),
        ],
        ["upi", "vpa", "virtual payment address", "upi id", "payment"],
        None, r"(?<![a-z])upi(?![a-z])|(?<![a-z])vpa(?![a-z])", ["rahul.sharma@okaxis", "9876543210@ybl"], category=_FINANCIAL, severity="Medium",  # pragma: allowlist secret
    ),
]
