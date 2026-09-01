"""
Latin-American, Canadian and additional US identifiers: BR MX AR CL, Ontario
health cards, US EIN and alien registration numbers. Validators follow the
public check-digit algorithms (True / False) or return None where the
algorithm is not authoritative (Mexican RFC homoclave).
"""
from itertools import cycle
from typing import Optional

from src.engine.rules import Pattern, Rule
from src.engine.validators import digits_only

_REGIONAL = "Regional Compliance"
_PHI = "Healthcare Data (PHI)"


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


def _mod11_check(digits: str, weights) -> int:
    r = 11 - (sum(int(d) * w for d, w in zip(digits, weights)) % 11)
    return 0 if r >= 10 else r


# --------------------------------------------------------------------------- Brazil
def _validate_br_cpf(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 11 or len(set(v)) == 1:
        return False
    c1 = _mod11_check(v[:9], range(10, 1, -1))
    c2 = _mod11_check(v[:10], range(11, 1, -1))
    return int(v[9]) == c1 and int(v[10]) == c2


def _validate_br_cnpj(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 14 or len(set(v)) == 1:
        return False
    c1 = _mod11_check(v[:12], (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2))
    c2 = _mod11_check(v[:13], (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2))
    return int(v[12]) == c1 and int(v[13]) == c2


# --------------------------------------------------------------------------- Mexico
_CURP_TABLE = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"
_RFC_TABLE = "0123456789ABCDEFGHIJKLMN&OPQRSTUVWXYZ Ñ"


def _validate_mx_curp(text: str) -> bool:
    v = text.upper()
    if len(v) != 18 or any(c not in _CURP_TABLE for c in v[:17]) or not v[17].isdigit():
        return False
    total = sum(_CURP_TABLE.index(c) * (18 - i) for i, c in enumerate(v[:17]))
    return (10 - total % 10) % 10 == int(v[17])


def _validate_mx_rfc(text: str) -> Optional[bool]:
    v = text.upper()
    if len(v) == 12:
        v = " " + v
    if len(v) != 13 or any(c not in _RFC_TABLE for c in v):
        return False
    total = sum(_RFC_TABLE.index(c) * (13 - i) for i, c in enumerate(v[:12]))
    r = total % 11
    expected = "0" if r == 0 else ("A" if r == 1 else str(11 - r))
    return True if v[12] == expected else None


# --------------------------------------------------------------------------- Argentina
def _validate_ar_cuit(text: str) -> bool:
    v = digits_only(text)
    if len(v) != 11:
        return False
    r = 11 - (sum(int(d) * w for d, w in zip(v[:10], (5, 4, 3, 2, 7, 6, 5, 4, 3, 2))) % 11)
    if r == 11:
        r = 0
    return r != 10 and r == int(v[10])


# --------------------------------------------------------------------------- Chile
def _validate_cl_rut(text: str) -> bool:
    v = text.upper().replace(".", "")
    body, sep, dv = v.rpartition("-")
    if not sep or not body.isdigit() or len(dv) != 1:
        return False
    total = sum(int(d) * w for d, w in zip(reversed(body), cycle((2, 3, 4, 5, 6, 7))))
    r = 11 - (total % 11)
    expected = "0" if r == 11 else ("K" if r == 10 else str(r))
    return dv == expected


# --------------------------------------------------------------------------- Canada (Ontario health card)
def _validate_ca_ohip(text: str) -> bool:
    v = digits_only(text)
    return len(v) == 10 and _plain_luhn(v)


def _rule(name, region, description, patterns, context, validator=None, field_hint=None, examples=(), category=_REGIONAL, severity="Critical"):
    return Rule(
        name=name, category=category, severity=severity, region=region, description=description,
        patterns=patterns, context=context, validator=validator, field_hint=field_hint, examples=list(examples),
    )


RULES = [
    _rule(
        "BR_CPF", "BR", "Brazilian natural-person registry number (CPF): 11 digits with two modulus-11 check digits.",
        [Pattern("CPF (formatted)", r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", 0.5), Pattern("CPF (weak)", r"\b\d{11}\b", 0.05)],
        ["cpf", "cadastro de pessoas físicas", "cadastro de pessoa fisica", "receita federal", "cpf number"],
        _validate_br_cpf, r"(?<![a-z])cpf(?![a-z])", ["823.855.915-45", "78902476995"],  # pragma: allowlist secret
    ),
    _rule(
        "BR_CNPJ", "BR", "Brazilian legal-entity registry number (CNPJ): 14 digits with two modulus-11 check digits.",
        [Pattern("CNPJ (formatted)", r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b", 0.5), Pattern("CNPJ (weak)", r"\b\d{14}\b", 0.05)],
        ["cnpj", "cadastro nacional da pessoa jurídica", "cadastro nacional", "receita federal"],
        _validate_br_cnpj, r"(?<![a-z])cnpj(?![a-z])", ["30.220.890/0001-08"], severity="Low",  # pragma: allowlist secret
    ),
    _rule(
        "MX_CURP", "MX", "Mexican population registry code (CURP): 18 characters with a modulus-10 check digit over a 37-symbol alphabet.",
        [
            Pattern(
                "CURP",
                r"\b[A-Z]{4}\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[HM](?:AS|BC|BS|CC|CL|CM|CS|CH|DF|DG|GT|GR|HG|JC|MC|MN|MS|NT|NL|OC|PL|QT|QR|SP|SL|SR|TC|TS|TL|VZ|YN|ZS|NE)[B-DF-HJ-NP-TV-Z]{3}[0-9A-Z]\d\b",
                0.6,
            ),
        ],
        ["curp", "clave única de registro de población", "clave unica de registro", "registro de población"],
        _validate_mx_curp, r"(?<![a-z])curp(?![a-z])", ["GOMK850730HDFRRL09", "PEHJ920115MJCRRN07"],  # pragma: allowlist secret
    ),
    _rule(
        "MX_RFC", "MX", "Mexican federal taxpayer registry (RFC): 4 letters + birth date + homoclave; the check character proves a number when it holds.",
        [Pattern("RFC (persona física)", r"\b[A-Z]{4}\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[A-Z0-9]{2}[0-9A]\b", 0.3)],
        ["rfc", "registro federal de contribuyentes", "contribuyente", "sat"],
        _validate_mx_rfc, r"(?<![a-z])rfc(?![a-z])", ["GOMA850730RB8", "PEHJ92011580A"], severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "AR_CUIT", "AR", "Argentine tax / labour identification (CUIT / CUIL): XX-XXXXXXXX-X with a weighted modulus-11 check digit.",
        [Pattern("CUIT (formatted)", r"\b(?:20|23|24|27|30|33|34)-\d{8}-\d\b", 0.5), Pattern("CUIT (weak)", r"\b(?:20|23|24|27|30|33|34)\d{9}\b", 0.1)],
        ["cuit", "cuil", "clave única de identificación tributaria", "clave unica de identificacion", "afip"],
        _validate_ar_cuit, r"(?<![a-z])cui[tl](?![a-z])", ["20-49837081-1", "27-09248096-3"],  # pragma: allowlist secret
    ),
    _rule(
        "AR_DNI", "AR", "Argentine national identity document number (DNI): 7-8 digits, dotted thousands; needs context.",
        [Pattern("DNI (formatted)", r"\b\d{1,2}\.\d{3}\.\d{3}\b", 0.3), Pattern("DNI (weak)", r"\b\d{7,8}\b", 0.01)],
        ["dni", "documento nacional de identidad", "documento", "identidad"],
        None, r"(?<![a-z])dni(?![a-z])|documento_?nacional", ["12.345.678"], severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "CL_RUT", "CL", "Chilean national identity / tax number (RUT / RUN): 7-8 digits + modulus-11 check digit (0-9 or K).",
        [Pattern("RUT (formatted)", r"\b\d{1,2}\.\d{3}\.\d{3}-[\dK]\b", 0.5), Pattern("RUT", r"\b\d{7,8}-[\dK]\b", 0.3)],
        ["rut", "run", "rol único tributario", "rol unico tributario", "rol único nacional", "cédula de identidad"],
        _validate_cl_rut, r"(?<![a-z])ru[tn](?![a-z])", ["12.345.671-8", "12345679-3"],  # pragma: allowlist secret
    ),
    _rule(
        "CA_OHIP", "CA", "Ontario health card number: 10 digits (Luhn) with a two-letter version code.",
        [Pattern("OHIP", r"\b\d{4}[ -]?\d{3}[ -]?\d{3}[ -]?[A-Z]{2}\b", 0.4)],
        ["ohip", "health card", "health number", "ontario health", "health card number"],
        _validate_ca_ohip, r"(?<![a-z])ohip(?![a-z])|health_?card|health_?number", ["6559-466-773-OB", "5639153716NB"], category=_PHI, severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "US_EIN", "US", "US employer identification number (EIN): NN-NNNNNNN with an IRS-issued prefix; needs tax context.",
        [Pattern("EIN", r"\b(?:0[1-6]|1[0-6]|2[0-7]|3\d|4[0-8]|5\d|6[0-8]|7[1-7]|8[0-8]|9[0-5]|9[89])-\d{7}\b", 0.3)],
        ["ein", "employer identification", "employer id", "federal tax", "tax id", "tin", "fein"],
        None, r"(?<![a-z])f?ein(?![a-z])|employer_?id|tax_?id", ["12-3456789"], severity="Medium",  # pragma: allowlist secret
    ),
    _rule(
        "US_ALIEN_REGISTRATION", "US", "US alien registration number (A-Number): A followed by 8-9 digits; needs immigration context.",
        [Pattern("A-Number", r"\bA[- ]?\d{8,9}\b", 0.1)],
        ["alien", "a-number", "a number", "uscis", "immigration", "green card", "registration number", "naturalization"],
        None, r"alien|a_?number|uscis|immigration", ["A12345678"], severity="High",  # pragma: allowlist secret
    ),
]
