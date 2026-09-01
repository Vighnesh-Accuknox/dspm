"""Middle East and Africa identifiers: AE SA IL EG GH (NG, ZA, TR live in the ported packs)."""
from src.engine.rules import Pattern, Rule
from src.engine.validators import digits_only

_REGIONAL = "Regional Compliance"
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


def _validate_ae_emirates_id(text: str) -> bool:
    v = digits_only(text)
    return len(v) == 15 and v.startswith("784") and _plain_luhn(v)


def _validate_sa_national_id(text: str) -> bool:
    v = digits_only(text)
    return len(v) == 10 and v[0] in "12" and _plain_luhn(v)


def _validate_il_teudat_zehut(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 9:
        return False
    total = 0
    for i, ch in enumerate(v):
        n = int(ch) * (1 if i % 2 == 0 else 2)
        if n > 9:
            n -= 9
        total += n
    return total % 10 == 0


_EG_GOVERNORATES = set(range(1, 36)) | {88}


def _validate_eg_national_id(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 14 or v[0] not in "23":
        return False
    mm, dd = int(v[3:5]), int(v[5:7])
    return 1 <= mm <= 12 and 1 <= dd <= _MONTH_DAYS[mm - 1] and int(v[7:9]) in _EG_GOVERNORATES


def _rule(name, region, description, patterns, context, validator=None, field_hint=None, examples=(), severity="Critical"):
    return Rule(
        name=name, category=_REGIONAL, severity=severity, region=region, description=description,
        patterns=patterns, context=context, validator=validator, field_hint=field_hint, examples=list(examples),
    )


RULES = [
    _rule(
        "AE_EMIRATES_ID", "AE", "UAE Emirates ID: 784-YYYY-NNNNNNN-C, 15 digits with a Luhn check digit.",
        [Pattern("Emirates ID (formatted)", r"\b784-(?:19|20)\d{2}-\d{7}-\d\b", 0.6), Pattern("Emirates ID", r"\b784(?:19|20)\d{2}\d{8}\b", 0.3)],
        ["emirates id", "emirates identity", "eid", "uae id", "هوية", "الهوية الإماراتية", "identity card"],
        _validate_ae_emirates_id, r"emirates_?id|(?<![a-z])eid(?![a-z])|uae_?id", ["784-1990-1311311-5", "784199043739756"],  # pragma: allowlist secret
    ),
    _rule(
        "SA_NATIONAL_ID", "SA", "Saudi national ID / Iqama: 10 digits starting 1 (citizen) or 2 (resident) with a Luhn check digit.",
        [Pattern("Saudi ID (weak)", r"\b[12]\d{9}\b", 0.05)],
        ["iqama", "national id", "saudi id", "هوية", "رقم الهوية", "residence id", "absher", "id number"],
        _validate_sa_national_id, r"iqama|national_?id|saudi_?id|هوية", ["1166543411", "2615200215"],  # pragma: allowlist secret
    ),
    _rule(
        "IL_TEUDAT_ZEHUT", "IL", "Israeli identity number (Teudat Zehut): 9 digits with a Luhn-style check.",
        [Pattern("Teudat Zehut (weak)", r"\b\d{9}\b", 0.05), Pattern("Teudat Zehut (formatted)", r"\b\d{2}-\d{7}\b", 0.2)],
        ["teudat zehut", "t.z.", "tz", "id number", "מספר זהות", "תעודת זהות", "israeli id", "מספר ת.ז."],
        _validate_il_teudat_zehut, r"teudat|(?<![a-z])tz(?![a-z])|israeli_?id|זהות", ["796033975"],  # pragma: allowlist secret
    ),
    _rule(
        "EG_NATIONAL_ID", "EG", "Egyptian national ID: 14 digits - century, birth date, governorate code, sequence, check.",
        [Pattern("Egyptian ID", r"\b[23]\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|[12]\d|3[0-5]|88)\d{5}\b", 0.3)],
        ["national id", "الرقم القومي", "egyptian id", "id number", "بطاقة الرقم القومي"],
        _validate_eg_national_id, r"national_?id|egypt|القومي", ["29007300159955", "30112028824568"],  # pragma: allowlist secret
    ),
    _rule(
        "GH_GHANA_CARD", "GH", "Ghana Card personal identification number: GHA-XXXXXXXXX-X.",
        [Pattern("Ghana Card", r"\bGHA-\d{9}-\d\b", 0.6)],
        ["ghana card", "ghanacard", "nia", "personal identification", "pin"],
        None, r"ghana_?card|(?<![a-z])nia(?![a-z])", ["GHA-657105083-6"],  # pragma: allowlist secret
    ),
]
