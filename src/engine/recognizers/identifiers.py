"""
Generic device, document, location and clinical identifiers that run for every
region: IMEI, ICCID, VIN, passport MRZ, geographic coordinates, ICD-10 and NDC
codes, medical record numbers. Everything here is `context: required` in the
detector policy - weak shapes only surface through a column name, a keyword
or column density.
"""
from typing import Optional

from src.engine.rules import Pattern, Rule
from src.engine.validators import digits_only

_PII = "PII"
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


def _validate_imei(text: str) -> bool:
    v = digits_only(text)
    return len(v) == 15 and len(set(v)) > 2 and _plain_luhn(v)


def _validate_iccid(text: str) -> bool:
    v = digits_only(text)
    return 19 <= len(v) <= 20 and v.startswith("89") and _plain_luhn(v)


_VIN_VALUES = {
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8, "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7,
    "R": 9, "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def _validate_vin(text: str) -> bool:
    v = text.upper()
    if len(v) != 17 or v.isdigit() or v.isalpha():
        return False
    total = 0
    for ch, w in zip(v, _VIN_WEIGHTS):
        value = int(ch) if ch.isdigit() else _VIN_VALUES.get(ch)
        if value is None:
            return False
        total += value * w
    r = total % 11
    return v[8] == ("X" if r == 10 else str(r))


def _mrz_check(segment: str) -> int:
    total = 0
    for ch, w in zip(segment, (7, 3, 1) * 20):
        if ch == "<":
            value = 0
        elif ch.isdigit():
            value = int(ch)
        else:
            value = ord(ch) - 55
        total += value * w
    return total % 10


def _validate_passport_mrz(text: str) -> Optional[bool]:
    v = text.upper()
    if v.startswith("P<") or (v.startswith("P") and v[1:2].isalpha() and "<<" in v):
        return None  # line 1 (names) carries no check digit
    if len(v) < 28 or not v[9].isdigit():
        return False
    return _mrz_check(v[:9]) == int(v[9]) and _mrz_check(v[13:19]) == int(v[19]) and _mrz_check(v[21:27]) == int(v[27])


def _validate_geo(text: str) -> Optional[bool]:
    try:
        lat, lon = (float(part.strip()) for part in text.split(","))
    except ValueError:
        return False
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return False
    return None if (lat, lon) != (0.0, 0.0) else False


def _rule(name, description, patterns, context, validator=None, field_hint=None, examples=(), category=_PII, severity="Low"):
    return Rule(
        name=name, category=category, severity=severity, region=None, description=description,
        patterns=patterns, context=context, validator=validator, field_hint=field_hint, examples=list(examples),
    )


RULES = [
    _rule(
        "IMEI", "Mobile equipment identity (IMEI): 15 digits with a Luhn check digit.",
        [Pattern("IMEI (formatted)", r"\b\d{2}[- ]\d{6}[- ]\d{6}[- ]\d\b", 0.3), Pattern("IMEI (weak)", r"\b\d{15}\b", 0.05)],
        ["imei", "device id", "handset", "equipment identity", "device identifier"],
        _validate_imei, r"imei|device_?id|handset", ["35-845422-110932-2", "352318504122227"],  # pragma: allowlist secret
    ),
    _rule(
        "ICCID", "SIM card serial (ICCID): 19-20 digits starting 89 with a Luhn check digit.",
        [Pattern("ICCID", r"\b89\d{17,18}\b", 0.3)],
        ["iccid", "sim", "sim card", "sim serial", "sim number"],
        _validate_iccid, r"iccid|(?<![a-z])sim(?![a-z])", ["8944753862346631701"],  # pragma: allowlist secret
    ),
    _rule(
        "VIN", "Vehicle identification number: 17 characters (no I/O/Q) whose 9th character is the North-American check digit.",
        [Pattern("VIN", r"\b[A-HJ-NPR-Z0-9]{8}[0-9X][A-HJ-NPR-Z0-9]{8}\b", 0.2)],
        ["vin", "vehicle identification", "chassis", "chassis number", "frame number", "vehicle"],
        _validate_vin, r"(?<![a-z])vin(?![a-z])|chassis|vehicle_?id", ["1HGCM82643C675372", "WVWZZZ3C69E848035"],  # pragma: allowlist secret
    ),
    _rule(
        "PASSPORT_MRZ", "Passport machine-readable zone: line 1 (P< issuer names) and line 2 (number, nationality, birth date, expiry with check digits).",
        [
            Pattern("MRZ line 1", r"P[<A-Z][A-Z]{3}[A-Z]{2,30}<<[A-Z<]{4,}", 0.7),
            Pattern("MRZ line 2", r"\b[A-Z0-9<]{9}\d[A-Z]{3}\d{6}\d[MF<]\d{6}\d[A-Z0-9<]{14,15}\d{1,2}\b", 0.7),
        ],
        ["passport", "mrz", "machine readable", "travel document"],
        _validate_passport_mrz, r"passport|mrz", ["P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "L898902C36UTO7408122F1204159ZE184226B<<<<<10"], category=_REGIONAL, severity="High",  # pragma: allowlist secret
    ),
    _rule(
        "GEO_COORDINATES", "Geographic coordinates: latitude, longitude pair with 4+ decimals; reported next to location context.",
        [Pattern("lat,lon", r"(?<![\d.-])-?(?:[0-8]?\d\.\d{4,}|90\.0+),\s?-?(?:1[0-7]\d\.\d{4,}|[0-9]?\d\.\d{4,}|180\.0+)(?![\d.])", 0.5)],
        ["lat", "lng", "lon", "latitude", "longitude", "gps", "coordinates", "geo", "location", "geolocation"],
        _validate_geo, r"(?<![a-z])lat(?![a-z])|(?<![a-z])l(?:o?n|ng)(?![a-z])|latitude|longitude|(?<![a-z])geo(?![a-z])|gps|coord|location", ["12.9716, 77.5946", "-33.8688,151.2093"],  # pragma: allowlist secret
    ),
    _rule(
        "ICD10_CODE", "ICD-10 diagnosis code (letter + 2 digits + optional decimals); only meaningful under a diagnosis column or keyword.",
        [Pattern("ICD-10", r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b", 0.1)],
        ["icd", "icd-10", "icd10", "diagnosis", "diagnosis code", "dx", "dx code"],
        None, r"icd|diagnos|(?<![a-z])dx(?![a-z])", ["E11.9", "J45"], category=_PHI, severity="Medium",  # pragma: allowlist secret
    ),
    _rule(
        "NDC_CODE", "US national drug code (NDC): 4-5 / 3-4 / 1-2 digit segments; only meaningful under a drug column or keyword.",
        [Pattern("NDC", r"\b\d{4,5}-\d{3,4}-\d{1,2}\b", 0.1)],
        ["ndc", "drug code", "medication", "drug", "prescribed", "rx"],
        None, r"(?<![a-z])ndc(?![a-z])|drug_?code|medication", ["0002-3227-30"], category=_PHI, severity="Low",  # pragma: allowlist secret
    ),
    _rule(
        "MEDICAL_RECORD_NUMBER", "Medical record number labelled MRN (6-10 digits) or in an MRN-named column.",
        [Pattern("MRN (labelled)", r"\bMRN[:# ]?\s?\d{6,10}\b", 0.6), Pattern("MRN (weak)", r"\b\d{6,10}\b", 0.01)],
        ["mrn", "medical record", "medical record number", "patient id", "chart number"],
        None, r"(?<![a-z])mrn(?![a-z])|medical_?record|patient_?(?:id|number|no)|chart_?(?:no|number)", ["MRN: 12345678", "MRN 4587120"], category=_PHI, severity="High",  # pragma: allowlist secret
    ),
]
