"""
upstream recognizers for Germany (DE), Sweden (SE), Finland (FI) and Poland (PL)
expressed as native src.engine.rules.Rule objects.

Pattern names, regexes, scores, context words and validate_result logic are
ported verbatim from upstream-analyzer's ``predefined_recognizers/country_specific``
packages (the upstream analyzer project MIT). Additions on top
of upstream: ``field_hint`` (regex over lower-cased column names), ``examples``,
``description`` and the category / severity from fixtures/findings-mapping.json.

Scoring is identical to upstream: a validator returning True lifts the match to
1.0, False drops it, None keeps the pattern score (context words then add 0.35).
"""
import re
from collections import Counter
from datetime import datetime
from typing import List, Optional

from src.engine.rules import Pattern, Rule

REGIONAL = "Regional Compliance"
PHI = "Healthcare Data (PHI)"
PII = "PII"


# ---------------------------------------------------------------------------
# Shared checksum helpers (private - validators.py has no equivalent)
# ---------------------------------------------------------------------------


def _icao_9303_check(text: str) -> bool:
    """
    ICAO Doc 9303 check digit: weights 7,3,1 repeating over text[:-1], letters
    mapped A=10..Z=35; the sum modulo 10 must equal the trailing digit.
    Caller guarantees text is upper-cased and ends with a digit.
    """
    weights = (7, 3, 1)
    total = 0
    for i, c in enumerate(text[:-1]):
        if c.isdigit():
            value = int(c)
        elif "A" <= c <= "Z":
            value = ord(c) - ord("A") + 10
        else:
            return False
        total += value * weights[i % 3]
    return (total % 10) == int(text[-1])


def _iso7064_mod11_10_check_digit(digits: str) -> int:
    """ISO 7064 Mod 11,10 check digit (BZSt variant) over a digit string."""
    product = 10
    for d in digits:
        total = (int(d) + product) % 10
        if total == 0:
            total = 10
        product = (total * 2) % 11
    check = 11 - product
    return 0 if check == 10 else check


def _se_luhn_valid(number: str) -> bool:
    """Luhn exactly as implemented by the upstream recognizer's Swedish recognizers."""
    digits = [int(d) for d in number]
    checksum = digits[-1]
    luhn_sum = 0
    for i, d in enumerate(reversed(digits[:-1])):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        luhn_sum += d
    return (luhn_sum + checksum) % 10 == 0


# ---------------------------------------------------------------------------
# Germany - validators
# ---------------------------------------------------------------------------


def _validate_de_bsnr(pattern_text: str) -> Optional[bool]:
    """BSNR has no public check digit: only reject malformed / all-zero input."""
    pattern_text = pattern_text.strip()
    if len(pattern_text) != 9 or not pattern_text.isdigit():
        return False
    if pattern_text == "000000000":
        return False
    return None


_KVNR_RE = re.compile(r"^[A-Z]\d{9}$")


def _validate_de_health_insurance(pattern_text: str) -> Optional[bool]:
    """KVNR check digit per § 290 SGB V Anlage 1 (GKV-Spitzenverband)."""
    pattern_text = pattern_text.upper().strip()
    if len(pattern_text) != 10:
        return False
    if not _KVNR_RE.match(pattern_text):
        return False

    letter_val = str(ord(pattern_text[0]) - ord("A") + 1).zfill(2)
    # Letter expanded to 2 digits + 8 data digits = 10 effective digits
    effective = letter_val + pattern_text[1:9]
    check_digit = int(pattern_text[9])
    factors = [1, 2, 1, 2, 1, 2, 1, 2, 1, 2]

    total = 0
    for digit_char, factor in zip(effective, factors):
        product = int(digit_char) * factor
        if product >= 10:
            product = (product // 10) + (product % 10)
        total += product
    return (total % 10) == check_digit


def _validate_de_id_card(pattern_text: str) -> Optional[bool]:
    """nPA: ICAO 9303 check digit; legacy 'T + 8 digits' has none -> None."""
    pattern_text = pattern_text.upper().strip()
    if len(pattern_text) != 9:
        return False
    if pattern_text[0] == "T" and pattern_text[1:].isdigit():
        return None
    if not pattern_text[-1].isdigit():
        return False
    return _icao_9303_check(pattern_text)


def _validate_de_lanr(pattern_text: str) -> Optional[bool]:
    """LANR check digit (KBV Arztnummern-Richtlinie): weights 4,9 on digits 1-6."""
    pattern_text = pattern_text.strip()
    if len(pattern_text) != 9 or not pattern_text.isdigit():
        return False
    weights = [4, 9, 4, 9, 4, 9]
    total = sum(int(d) * w for d, w in zip(pattern_text[:6], weights))
    expected_check = (10 - total % 10) % 10
    return int(pattern_text[6]) == expected_check


_ICAO_FORBIDDEN = frozenset("ABDEIOQSU")


def _validate_de_passport(pattern_text: str) -> Optional[bool]:
    """Reisepass: ICAO 9303 check digit over the restricted ICAO charset."""
    pattern_text = pattern_text.upper().strip()
    if len(pattern_text) != 9 or not pattern_text[-1].isdigit():
        return False
    if any(c in _ICAO_FORBIDDEN for c in pattern_text[:-1]):
        return False
    return _icao_9303_check(pattern_text)


_RVNR_RE = re.compile(r"^\d{8}[A-Z]\d{3}$")


def _validate_de_social_security(pattern_text: str) -> Optional[bool]:
    """Rentenversicherungsnummer check digit per VKVV § 4 plus birth-date ranges."""
    pattern_text = pattern_text.upper().strip()
    if len(pattern_text) != 12:
        return False
    if not _RVNR_RE.match(pattern_text):
        return False

    day = int(pattern_text[2:4])
    month = int(pattern_text[4:6])
    if not (1 <= day <= 31 or 51 <= day <= 81):
        return False
    if not 1 <= month <= 12:
        return False

    letter_val = str(ord(pattern_text[8]) - ord("A") + 1).zfill(2)
    effective = pattern_text[:8] + letter_val + pattern_text[9:11]
    check_digit = int(pattern_text[11])
    weights = [2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1]

    total = 0
    for digit_char, weight in zip(effective, weights):
        product = int(digit_char) * weight
        total += (product // 10) + (product % 10)
    return (total % 10) == check_digit


def _validate_de_tax_id(pattern_text: str) -> Optional[bool]:
    """Steuer-IdNr.: ISO 7064 Mod 11,10 plus the BZSt digit-repetition rule."""
    if len(pattern_text) != 11 or not pattern_text.isdigit():
        return False
    if pattern_text[0] == "0":
        return False
    digits = [int(d) for d in pattern_text]
    # Post-2016 BZSt rule: no digit may appear more than three times in
    # positions 1-10 (also rejects the all-identical case).
    if max(Counter(digits[:10]).values()) > 3:
        return False
    return _iso7064_mod11_10_check_digit(pattern_text[:10]) == digits[10]


_VAT_NORMALIZATION_STRIP = re.compile(r"[\s.\-]")


def _validate_de_vat_id(pattern_text: str, strict_checksum: bool = False) -> Optional[bool]:
    """
    USt-IdNr.: normalise (upper-case, strip whitespace / dots / dashes), then
    tri-state - True on ISO 7064 Mod 11,10 pass, False on structural failure,
    None on checksum failure (upstream default: the BZSt algorithm is not
    published, so a checksum miss keeps the pattern score instead of dropping).
    """
    normalized = _VAT_NORMALIZATION_STRIP.sub("", pattern_text.upper())
    if len(normalized) != 11 or not normalized.startswith("DE"):
        return False
    digits = normalized[2:]
    if not digits.isdigit():
        return False
    if _iso7064_mod11_10_check_digit(digits[:8]) == int(digits[8]):
        return True
    return False if strict_checksum else None


# ---------------------------------------------------------------------------
# Sweden / Finland / Poland - validators
# ---------------------------------------------------------------------------


def _validate_se_organisationsnummer(pattern_text: str) -> Optional[bool]:
    """Organisationsnummer: 10 digits, third digit >= 2, Luhn."""
    num = "".join(filter(str.isdigit, pattern_text))
    if len(num) != 10:
        return False
    try:
        if int(num[2]) < 2:
            return False
    except (ValueError, IndexError):
        return False
    return _se_luhn_valid(num)


def _validate_se_personnummer(pattern_text: str) -> Optional[bool]:
    """Personnummer: last 10 digits, plausible date (samordningsnummer aware), Luhn."""
    num = "".join(filter(str.isdigit, pattern_text))[-10:]
    if len(num) != 10:
        return False
    try:
        month = int(num[2:4])
        day = int(num[4:6])
        if day >= 61:  # samordningsnummer uses day + 60
            day -= 60
        if not (1 <= month <= 12 and 1 <= day <= 31):
            return False
    except (ValueError, IndexError):
        return False
    return _se_luhn_valid(num)


_FI_CENTURY_BY_SEPARATOR = {
    "+": 1800,
    "-": 1900, "Y": 1900, "X": 1900, "W": 1900, "V": 1900, "U": 1900,
    "A": 2000, "B": 2000, "C": 2000, "D": 2000, "E": 2000, "F": 2000,
}

_FI_CONTROL_CHARACTERS = "0123456789ABCDEFHJKLMNPRSTUVWXY"  # pragma: allowlist secret


def _validate_fi_personal_identity_code(pattern_text: str) -> Optional[bool]:
    """Henkilötunnus: real date (century from the separator) and control character."""
    if len(pattern_text) != 11:
        return False
    date_part = pattern_text[0:6]
    century = _FI_CENTURY_BY_SEPARATOR.get(pattern_text[6], 2000)
    try:
        datetime(century + int(date_part[4:6]), int(date_part[2:4]), int(date_part[0:2]))
    except ValueError:
        return False
    individual_number = pattern_text[7:10]
    control_character = pattern_text[-1].upper()
    number_to_check = int(date_part + individual_number)
    return _FI_CONTROL_CHARACTERS[number_to_check % 31] == control_character


def _validate_pl_pesel(pattern_text: str) -> Optional[bool]:
    """PESEL check digit: (10 - weighted sum % 10) % 10 with weights 1,3,7,9 repeating."""
    if len(pattern_text) != 11 or not pattern_text.isdigit():
        return False
    digits = [int(digit) for digit in pattern_text]
    weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
    weighted_sum = sum(d * w for d, w in zip(digits[:10], weights))
    check_digit = (10 - weighted_sum % 10) % 10
    return check_digit == digits[10]


# ---------------------------------------------------------------------------
# Germany - rules
# ---------------------------------------------------------------------------

DE_BSNR = Rule(
    name="DE_BSNR",
    category=PHI,
    severity="Low",
    region="DE",
    description="German Betriebsstättennummer (BSNR), 9-digit practice / site-of-care number (§ 75 Abs. 7 SGB V).",
    patterns=[
        Pattern("Betriebsstättennummer BSNR (9 digits)", r"\b\d{9}\b", 0.2),
    ],
    context=[
        "betriebsstättennummer",
        "betriebsstätten-nummer",
        "bsnr",
        "betriebsstätte",
        "praxisnummer",
        "arztpraxis",
        "praxis",
        "kassenärztliche vereinigung",
        "kv-nummer",
        "kv nummer",
        "praxisadresse",
        "praxisstandort",
        "nebenbetriebsstätte",
        "hauptbetriebsstätte",
        "behandlungsort",
        "vertragsarztpraxis",
    ],
    validator=_validate_de_bsnr,
    field_hint=r"(?<![a-z])bsnr(?![a-z])|betriebsst(ae|ä)tten_?(nr|nummer)|praxis_?(nr|nummer)",
    examples=["021234568", "521234567", "711234567"],
)

DE_FUEHRERSCHEIN = Rule(
    name="DE_FUEHRERSCHEIN",
    category=REGIONAL,
    severity="High",
    region="DE",
    description="German Führerscheinnummer (driving licence number), post-2013 EU format: 2 letters + 8 digits + check character.",
    patterns=[
        Pattern("Führerscheinnummer (Post-2013 EU-Format, 11 Zeichen)", r"\b[A-Z]{2}\d{8}[A-Z0-9]\b", 0.35),
    ],
    context=[
        "führerscheinnummer",
        "führerschein",
        "fahrerlaubnis",
        "fahrerlaubnisnummer",
        "fahrerlaubnisklasse",
        "führerscheininhaber",
        "fev",
        "kba",
        "kraftfahrt-bundesamt",
        "driving licence",
        "driving license",
        "driver's license",
        "licence number",
        "license number",
        "dokument nr",
        "dokument-nr",
        "feld 5",
    ],
    field_hint=r"f(ue|ü)hrerschein|fahrerlaubnis|driv(er|ing)s?_?licen[cs]e|licen[cs]e_?(nr|no|number)(?![a-z])",
    examples=["BO12345678A", "MU12345678B", "HH98765432C"],
)

DE_HANDELSREGISTER = Rule(
    name="DE_HANDELSREGISTER",
    category=REGIONAL,
    severity="Low",
    region="DE",
    description="German Handelsregisternummer (commercial register number), HRA/HRB + 1-6 digits (§§ 9, 14 HGB).",
    patterns=[
        Pattern("Handelsregisternummer HRA/HRB", r"\bHR[AB]\s*\d{1,6}\b", 0.5),
    ],
    context=[
        "handelsregister",
        "handelsregisternummer",
        "amtsgericht",
        "registergericht",
        "hra",
        "hrb",
        "hr-nummer",
        "registerauszug",
        "handelsregistereintrag",
        "firma",
        "gesellschaft",
        "gmbh",
        "ag",
        "ug",
        "kg",
        "ohg",
        "einzelkaufmann",
        "einzelkauffrau",
        "handelsregisterblattnummer",
    ],
    field_hint=r"handelsregister|(?<![a-z])(hrb|hra|hr_?nr|hr_?nummer)(?![a-z])|commercial_?register|trade_?register",
    examples=["HRB 123456", "HRA 12345"],
)

DE_HEALTH_INSURANCE = Rule(
    name="DE_HEALTH_INSURANCE",
    category=PHI,
    severity="High",
    region="DE",
    description="German Krankenversichertennummer (KVNR), letter + 9 digits with GKV check digit (§ 290 SGB V).",
    patterns=[
        Pattern("Krankenversicherungsnummer KVNR (letter + 9 digits)", r"\b[A-Z]\d{9}\b", 0.3),
    ],
    context=[
        "krankenversicherungsnummer",
        "krankenversichertennummer",
        "versichertennummer",
        "kvnr",
        "krankenkasse",
        "krankenversicherung",
        "gesundheitskarte",
        "egk",
        "elektronische gesundheitskarte",
        "gkv",
        "gesetzliche krankenversicherung",
        "krankenversicherungsausweis",
        "versichertenausweis",
        "versichertenkarte",
        "aok",
        "tkk",
        "barmer",
        "dak",
    ],
    validator=_validate_de_health_insurance,
    field_hint=r"krankenversich|versicherten_?(nr|nummer)|health_?insurance|(?<![a-z])(kvnr|kv_?nr|egk)(?![a-z])",
    examples=["A000500015", "C000500021", "M123456785"],
)

DE_ID_CARD = Rule(
    name="DE_ID_CARD",
    category=REGIONAL,
    severity="High",
    region="DE",
    description="German Personalausweisnummer: nPA (ICAO charset + check digit) or legacy 'T' + 8 digits.",
    patterns=[
        Pattern(
            "Personalausweisnummer nPA (ICAO charset + check digit)",
            r"\b[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{7}[0-9]\b",
            0.4,
        ),
        Pattern("Personalausweisnummer alt (T + 8 Ziffern)", r"\bT\d{8}\b", 0.5),
    ],
    context=[
        "personalausweis",
        "ausweis",
        "personalausweisnummer",
        "ausweisnummer",
        "ausweisdokument",
        "dokumentennummer",
        "seriennummer",
        "npa",
        "neuer personalausweis",
        "personalausweisgesetz",
        "pauwsg",
        "bundespersonalausweis",
        "identity card",
        "national id",
    ],
    validator=_validate_de_id_card,
    field_hint=r"personalausweis|ausweis_?(nr|nummer|no)|id_?card|identity_?card|national_?id(?![a-z])|(?<![a-z])npa(?![a-z])",
    examples=["L01X00T44", "C01234565", "T22000129"],
)

DE_KFZ = Rule(
    name="DE_KFZ",
    category=REGIONAL,
    severity="Medium",
    region="DE",
    description="German KFZ-Kennzeichen (vehicle registration plate): district code, 1-2 letters, 1-4 digits, optional E/H suffix.",
    patterns=[
        Pattern(
            "KFZ-Kennzeichen (mit Leerzeichen)",
            r"(?<![\w-])[A-ZÄÖÜ]{1,3}\s[A-Z]{1,2}\s\d{1,4}[EH]?(?!\w)",
            0.3,
        ),
        Pattern(
            "KFZ-Kennzeichen (mit Bindestrich)",
            r"(?<![\w-])[A-ZÄÖÜ]{1,3}-[A-Z]{1,2}-\d{1,4}[EH]?(?!\w)",
            0.3,
        ),
        Pattern(
            "KFZ-Kennzeichen (Bindestrich + Leerzeichen)",
            r"(?<![\w-])[A-ZÄÖÜ]{1,3}-[A-Z]{1,2}\s\d{1,4}[EH]?(?!\w)",
            0.3,
        ),
        Pattern(
            "KFZ-Kennzeichen (ASCII only, mit Leerzeichen)",
            r"(?<![\w-])[A-Z]{1,3}\s[A-Z]{1,2}\s\d{1,4}[EH]?(?!\w)",
            0.2,
        ),
        Pattern(
            "KFZ-Kennzeichen (ASCII only, Bindestrich + Leerzeichen)",
            r"(?<![\w-])[A-Z]{1,3}-[A-Z]{1,2}\s\d{1,4}[EH]?(?!\w)",
            0.2,
        ),
    ],
    context=[
        "kennzeichen",
        "kfz-kennzeichen",
        "kraftfahrzeugkennzeichen",
        "nummernschild",
        "fahrzeugkennzeichen",
        "zulassung",
        "kfz",
        "fahrzeug",
        "auto",
        "pkw",
        "lkw",
        "fahrzeugschein",
        "fahrzeugbrief",
        "zulassungsbescheinigung",
        "amtliches kennzeichen",
    ],
    field_hint=r"kennzeichen|nummernschild|(license|licence|number|registration)_?plate|plate_?(nr|no|number)|(?<![a-z])kfz(?![a-z])",
    examples=["B AB 1234", "HH-AB-1234", "KA EF 12H"],
)

DE_LANR = Rule(
    name="DE_LANR",
    category=PHI,
    severity="Low",
    region="DE",
    description="German Lebenslange Arztnummer (LANR), 9-digit lifetime physician number with KBV check digit.",
    patterns=[
        Pattern("Lebenslange Arztnummer LANR (9 digits)", r"\b\d{9}\b", 0.3),
    ],
    context=[
        "arztnummer",
        "lanr",
        "lebenslange arztnummer",
        "arzt-nr",
        "arzt nr",
        "arzt-nummer",
        "vertragsarzt",
        "kassenarzt",
        "niedergelassener arzt",
        "kbv",
        "kassenärztliche vereinigung",
        "kv-nummer",
        "rezept",
        "verschreibung",
        "behandelnder arzt",
        "hausarzt",
        "facharzt",
    ],
    validator=_validate_de_lanr,
    field_hint=r"(?<![a-z])lanr(?![a-z])|arzt_?(nr|nummer)|lebenslange_?arztnummer|physician_?(id|number|no)(?![a-z])",
    examples=["123456601", "234567701", "987654401"],
)

DE_PASSPORT = Rule(
    name="DE_PASSPORT",
    category=REGIONAL,
    severity="High",
    region="DE",
    description="German Reisepassnummer, 9 characters from the ICAO 9303 charset ending in a check digit (PassG § 4).",
    patterns=[
        Pattern(
            "Reisepassnummer (Strict ICAO charset)",
            r"\b[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{7}[0-9]\b",
            0.4,
        ),
    ],
    context=[
        "reisepass",
        "pass",
        "passnummer",
        "reisepassnummer",
        "passport",
        "passport number",
        "pass-nr",
        "dokumentennummer",
        "bundesrepublik deutschland",
        "ausweisdokument",
        "mrz",
    ],
    validator=_validate_de_passport,
    field_hint=r"reisepass|passport|pass_?(nr|nummer|no|number)(?![a-z])",
    examples=["C01234565", "F12345671", "C01X00T41"],
)

DE_PLZ = Rule(
    name="DE_PLZ",
    category=PII,
    severity="Low",
    region="DE",
    description="German Postleitzahl (postal code), 5 digits in 01001-99998; very low base confidence, context required.",
    patterns=[
        Pattern(
            "Postleitzahl (5 digits, very low base confidence – context required)",
            r"\b(?!01000\b|99999\b)(0[1-9]\d{3}|[1-9]\d{4})\b",
            0.05,
        ),
    ],
    context=[
        "plz",
        "postleitzahl",
        "postanschrift",
        "adresse",
        "wohnort",
        "ort",
        "wohnanschrift",
        "lieferadresse",
        "rechnungsadresse",
        "straße",
        "strasse",
        "hausnummer",
        "postfach",
        "bundesland",
        "gemeinde",
        "stadt",
        "dorf",
    ],
    field_hint=r"(?<![a-z])plz(?![a-z])|postleitzahl|postal_?code|post_?code|zip_?code|(?<![a-z])zip(?![a-z])",
    examples=["10115", "80331", "22085"],
)

DE_SOCIAL_SECURITY = Rule(
    name="DE_SOCIAL_SECURITY",
    category=REGIONAL,
    severity="Critical",
    region="DE",
    description="German Rentenversicherungsnummer (RVNR / Sozialversicherungsnummer), 12 characters with VKVV § 4 check digit.",
    patterns=[
        Pattern(
            "Rentenversicherungsnummer (Strict, with birth date structure)",
            r"\b\d{2}"
            r"(0[1-9]|[12]\d|3[01]|5[1-9]|[67]\d|8[01])"  # day: 01-31 or 51-81
            r"(0[1-9]|1[0-2])"                              # month 01-12
            r"\d{2}"                                  # year
            r"[A-Z]"                                  # surname initial
            r"\d{2}"                                  # serial
            r"[0-9]\b",                               # check digit
            0.5,
        ),
        Pattern("Rentenversicherungsnummer (Relaxed)", r"\b\d{8}[A-Z]\d{3}\b", 0.3),
    ],
    context=[
        "rentenversicherungsnummer",
        "sozialversicherungsnummer",
        "versicherungsnummer",
        "rvnr",
        "svnr",
        "sv-nummer",
        "rente",
        "rentenversicherung",
        "deutsche rentenversicherung",
        "drv",
        "sozialversicherung",
        "sozialversicherungsausweis",
        "rentenausweis",
    ],
    validator=_validate_de_social_security,
    field_hint=r"sozialversicherung|rentenversicherung|social_?security|(?<![a-z])(svnr|rvnr|sv_?nr|rv_?nr)(?![a-z])",
    examples=["15070649C103", "65070803A019", "20151090B023"],  # pragma: allowlist secret
)

DE_TAX_ID = Rule(
    name="DE_TAX_ID",
    category=REGIONAL,
    severity="High",
    region="DE",
    description="German Steueridentifikationsnummer (Steuer-IdNr.), 11 digits with ISO 7064 Mod 11,10 check digit (§ 139b AO).",
    patterns=[
        Pattern("Steueridentifikationsnummer (High)", r"\b[1-9]\d{10}\b", 0.5),
    ],
    context=[
        "steueridentifikationsnummer",
        "steuer-id",
        "steuerid",
        "steuerliche identifikationsnummer",
        "steuerliche identifikation",
        "persönliche identifikationsnummer",
        "steuer identifikation",
        "idnr",
        "steuer-idnr",
        "steuernummer",
        "bzst",
    ],
    validator=_validate_de_tax_id,
    field_hint=r"steuer_?id|steuerliche_?identifikation|tax_?id|(?<![a-z])idnr(?![a-z])",
    examples=["12345678903", "98765432106"],
)

DE_TAX_NUMBER = Rule(
    name="DE_TAX_NUMBER",
    category=REGIONAL,
    severity="High",
    region="DE",
    description="German Steuernummer: ELSTER 13-digit unified format or state-specific slash-separated formats (§ 139a AO).",
    patterns=[
        Pattern("Steuernummer ELSTER (bundeseinheitlich, 13-stellig)", r"\b(0[1-9]|1[0-6])\d{11}\b", 0.5),
        Pattern("Steuernummer mit Schrägstrich (Bayern/BW: 3/3/5)", r"(?<!\w)\d{3}/\d{3}/\d{5}(?!\w)", 0.4),
        Pattern(
            "Steuernummer mit Schrägstrich (NW: 3/4/4 oder allgemein 2-3/3-4/4-5)",
            r"(?<!\w)\d{2,3}/\d{3,4}/\d{4,5}(?!\w)",
            0.2,
        ),
    ],
    context=[
        "steuernummer",
        "steuer-nr",
        "steuer nr",
        "st.-nr",
        "st-nr",
        "finanzamt",
        "umsatzsteuer",
        "einkommensteuer",
        "körperschaftsteuer",
        "gewerbesteuer",
        "steuerveranlagung",
        "steuerbescheid",
    ],
    field_hint=r"steuer_?nummer|steuer_?nr|(?<![a-z])st_?nr(?![a-z])|tax_?(number|num|no)(?![a-z])",
    examples=["0281508150123", "123/456/78901", "12/345/6789"],
)

DE_VAT_ID = Rule(
    name="DE_VAT_ID",
    category=REGIONAL,
    severity="Low",
    region="DE",
    description="German Umsatzsteuer-Identifikationsnummer (USt-IdNr.), 'DE' + 9 digits, separators tolerated (§ 27a UStG).",
    patterns=[
        Pattern("Umsatzsteuer-Identifikationsnummer USt-IdNr. (DE + 9 digits)", r"\bDE\d{9}\b", 0.5),
        Pattern(
            "Umsatzsteuer-Identifikationsnummer USt-IdNr. (with separators)",
            r"\bDE[\s.\-]?\d{3}[\s.\-]?\d{3}[\s.\-]?\d{3}\b",
            0.4,
        ),
    ],
    context=[
        "umsatzsteuer-identifikationsnummer",
        "umsatzsteueridentifikationsnummer",
        "ust-idnr",
        "ust-id",
        "ustidnr",
        "umsatzsteuer-id",
        "mehrwertsteuer",
        "vat",
        "vat-id",
        "vat id",
        "steueridentifikation",
        "bzst",
        "bundeszentralamt für steuern",
        "finanzamt",
        "invoice",
        "rechnung",
    ],
    validator=_validate_de_vat_id,  # upstream default: heuristic (non-strict) checksum
    field_hint=r"ust_?id|umsatzsteuer_?id|vat_?(id|nr|no|number)(?![a-z])|mwst_?(id|nr)(?![a-z])|(?<![a-z])uid(?![a-z])",
    examples=["DE136695976", "DE 136 695 976", "DE129273398"],
)

# ---------------------------------------------------------------------------
# Sweden / Finland / Poland - rules
# ---------------------------------------------------------------------------

SE_ORGANISATIONSNUMMER = Rule(
    name="SE_ORGANISATIONSNUMMER",
    category=REGIONAL,
    severity="Low",
    region="SE",
    description="Swedish Organisationsnummer (company registration number), 10 digits with Luhn check digit.",
    patterns=[
        Pattern("Swedish Organisationsnummer (Medium)", r"\b\d{6}[-]?\d{4}\b", 0.6),
        Pattern("Swedish Organisationsnummer (Weak)", r"\d{6}[-]?\d{4}", 0.2),
    ],
    context=[
        "organisationsnummer",
        "orgnr",
        "org nr",
        "företagsnummer",
    ],
    validator=_validate_se_organisationsnummer,
    field_hint=r"organisationsnummer|organi[sz]ation_?number|org_?(nr|no|number|nummer)(?![a-z])|f(oe|ö)retagsnummer",
    examples=["212000-0142", "556703-7485"],
)

SE_PERSONNUMMER = Rule(
    name="SE_PERSONNUMMER",
    category=REGIONAL,
    severity="Critical",
    region="SE",
    description="Swedish Personnummer (personal identity number), YY(YY)MMDD[-+]NNNC with date check and Luhn check digit.",
    patterns=[
        Pattern("Swedish Personnummer (Medium)", r"\b(\d{6,8})([-+]?)\d{4}\b", 0.5),
        Pattern("Swedish Personnummer (Very Weak)", r"(\d{6,8})([-+]?)\d{4}", 0.1),
    ],
    context=[
        "personnummer",
        "svenskt personnummer",
        "svensk id",
        "ssn",
        "personal identity number",
        "samordningsnummer",
    ],
    validator=_validate_se_personnummer,
    field_hint=r"personnummer|person_?nr|personal_?(identity_?)?number|samordningsnummer|(?<![a-z])pnr(?![a-z])",
    examples=["198712202384", "871220-2384", "19910924-2397"],
)

FI_PERSONAL_IDENTITY_CODE = Rule(
    name="FI_PERSONAL_IDENTITY_CODE",
    category=REGIONAL,
    severity="Critical",
    region="FI",
    description="Finnish Henkilötunnus (personal identity code), DDMMYY + century separator + NNN + control character.",
    patterns=[
        Pattern(
            "Finnish Personal Identity Code (Medium)",
            r"\b(\d{6})([-+ABCDEFYXWVU])(\d{3})([0123456789ABCDEFHJKLMNPRSTUVWXY])\b",
            0.5,
        ),
        Pattern(
            "Finnish Personal Identity Code (Very Weak)",
            r"(\d{6})([-+ABCDEFYXWVU])(\d{3})([0123456789ABCDEFHJKLMNPRSTUVWXY])",
            0.1,
        ),
    ],
    context=["hetu", "henkilötunnus", "personbeteckningen", "personal identity code"],
    validator=_validate_fi_personal_identity_code,
    field_hint=r"henkil(oe|ö|o)tunnus|personal_?identity_?code|personbeteckning|(?<![a-z])hetu",
    examples=["010594Y9032", "131052-308T", "020504A902E"],
)

PL_PESEL = Rule(
    name="PL_PESEL",
    category=REGIONAL,
    severity="Critical",
    region="PL",
    description="Polish PESEL national identification number, 11 digits encoding the birth date with a weighted check digit.",
    patterns=[
        Pattern(
            "PESEL",
            r"[0-9]{2}([02468][1-9]|[13579][012])(0[1-9]|1[0-9]|2[0-9]|3[01])[0-9]{5}",
            0.4,
        ),
    ],
    context=["PESEL"],
    validator=_validate_pl_pesel,
    field_hint=r"pesel",
    examples=["44051401458", "02070803628"],
)


RULES: List[Rule] = [
    DE_BSNR,
    DE_FUEHRERSCHEIN,
    DE_HANDELSREGISTER,
    DE_HEALTH_INSURANCE,
    DE_ID_CARD,
    DE_KFZ,
    DE_LANR,
    DE_PASSPORT,
    DE_PLZ,
    DE_SOCIAL_SECURITY,
    DE_TAX_ID,
    DE_TAX_NUMBER,
    DE_VAT_ID,
    SE_ORGANISATIONSNUMMER,
    SE_PERSONNUMMER,
    FI_PERSONAL_IDENTITY_CODE,
    PL_PESEL,
]
