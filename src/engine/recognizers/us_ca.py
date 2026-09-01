"""
upstream recognizers for the United States and Canada, ported to the native
Rule engine (src/engine/rules.py).

Source (MIT, the upstream analyzer project):
  upstream analyzer/predefined_recognizers/country_specific/us/*.py
  upstream analyzer/predefined_recognizers/country_specific/canada/*.py

Pattern names, regexes, scores and CONTEXT lists are copied verbatim from
upstream; validate_result / invalidate_result are ported as module-private
functions (including their replacement_pairs sanitisation).

Intentional deviations:
  * us_healthcare_admin_recognizers.py anchors identifiers on their label with
    a variable-width lookbehind. upstream runs on the `regex` package; Python's
    `re` only accepts fixed-width lookbehinds, so _labelled() emulates the
    lookbehind with an alternation of fixed-width ones (whitespace runs are
    bounded, see there). The original regexes are quoted next to each pattern.
  * field_hint regexes use (?<![a-z]) / (?![a-z]) instead of \\b because "_"
    is a word character ("customer_ssn" would not match r"\\bssn\\b").
"""
import re
from typing import Dict, List, Sequence

from src.engine.rules import Pattern, Rule
from src.engine.validators import all_same_digit, digits_only, sanitize

_REGIONAL = "Regional Compliance"
_FINANCIAL = "Financial Data"
_PII = "PII"
_PHI = "Healthcare Data (PHI)"


def _luhn(digits: str) -> bool:
    """Plain Luhn (CaSinRecognizer._luhn_valid / UsNpiRecognizer Luhn step)."""
    total = 0
    for i, digit in enumerate(reversed(digits)):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# --------------------------------------------------------------------------
# ABA routing number  (aba_routing_recognizer.py)
# --------------------------------------------------------------------------
_ABA_REPLACEMENT_PAIRS = (("-", ""),)


def _validate_aba_routing(text: str) -> bool:
    """AbaRoutingRecognizer.validate_result: weights 3,7,1 repeating, sum % 10 == 0."""
    value = sanitize(text, _ABA_REPLACEMENT_PAIRS)
    if len(value) < 9 or not value[:9].isdigit():
        return False
    total = 0
    for idx, m in enumerate((3, 7, 1, 3, 7, 1, 3, 7, 1)):
        total += int(value[idx]) * m
    return total % 10 == 0


# --------------------------------------------------------------------------
# Medical license / DEA certificate number  (medical_license_recognizer.py)
# --------------------------------------------------------------------------
_MEDICAL_LICENSE_REPLACEMENT_PAIRS = (("-", ""), (" ", ""))


def _validate_medical_license(text: str) -> bool:
    """MedicalLicenseRecognizer.validate_result: DEA check digit over the 7 digits."""
    value = sanitize(text, _MEDICAL_LICENSE_REPLACEMENT_PAIRS)
    number = value[2:]
    if not number.isdigit():
        return False
    digits = [int(dig) for dig in number]
    checksum = digits.pop()
    even_digits = digits[-1::-2]
    odd_digits = digits[-2::-2]
    checksum *= -1
    checksum += 2 * sum(even_digits) + sum(odd_digits)
    return checksum % 10 == 0


# --------------------------------------------------------------------------
# US NPI  (us_npi_recognizer.py)
# --------------------------------------------------------------------------
_NPI_REPLACEMENT_PAIRS = (("-", ""), (" ", ""))


def _validate_us_npi(text: str) -> bool:
    """UsNpiRecognizer.validate_result: Luhn over "80840" + NPI (CMS spec)."""
    value = sanitize(text, _NPI_REPLACEMENT_PAIRS)
    if not value.isdigit():
        return False
    return _luhn("80840" + value)


def _invalidate_us_npi(text: str) -> bool:
    """UsNpiRecognizer.invalidate_result: all body digits identical (1111111112)."""
    value = sanitize(text, _NPI_REPLACEMENT_PAIRS)
    if value:
        body = value[:-1] if len(value) > 1 else value
        if body and len(set(body)) == 1:
            return True
    return False


# --------------------------------------------------------------------------
# US SSN  (us_ssn_recognizer.py)
# --------------------------------------------------------------------------
def _invalidate_us_ssn(text: str) -> bool:
    """UsSsnRecognizer.invalidate_result."""
    # if there are delimiters, make sure both delimiters are the same
    delimiters = {c for c in text if c in (".", "-", " ")}
    if len(delimiters) > 1:
        return True
    only_digits = digits_only(text)
    if all_same_digit(only_digits):
        return True
    if only_digits[3:5] == "00" or only_digits[5:] == "0000":
        # groups cannot be all zeros
        return True
    if only_digits[:3] in ("000", "666"):
        # area number (first group) is never issued by the SSA
        return True
    if only_digits in ("123456789", "987654320", "078051120"):
        # canonical sample/placeholder SSNs published for examples
        return True
    return False


# --------------------------------------------------------------------------
# CA SIN  (ca_sin_recognizer.py)
# --------------------------------------------------------------------------
def _invalidate_ca_sin(text: str) -> bool:
    """CaSinRecognizer.invalidate_result: Luhn failure invalidates."""
    return not _luhn(digits_only(text))


# --------------------------------------------------------------------------
# US healthcare administrative identifiers (us_healthcare_admin_recognizers.py)
#
# upstream anchors every identifier on its label with a variable-width lookbehind
#
#   (?<=\b(?:LABEL)(?:\s*(?:#|no\.?|number|id)\s*:?\s*|\s*:\s*|\s+))BODY
#
# which Python's re rejects ("look-behind requires fixed-width pattern"). The
# emulation below groups label and separator variants by width and ORs one
# fixed-width lookbehind per width. Bounds of the emulation: blank runs inside a
# label are a single blank; the separator between label and identifier is 1-3
# blank/colon characters, or a keyword (#, no, no., number, id) with 0-2 leading
# blanks and 0-3 trailing blank/colon characters. Spans, scores and context are
# unchanged.
# --------------------------------------------------------------------------
_SEPARATOR_KEYWORDS = ("#", "no", "no.", "number", "id")  # (?:#|no\.?|number|id)
_MAX_RUN = 3


def _separator_fragments() -> Dict[int, List[str]]:
    """Fixed-width regex fragments emulating the label/identifier separator, by width."""
    by_width: Dict[int, List[str]] = {}

    def add(width: int, fragment: str) -> None:
        by_width.setdefault(width, []).append(fragment)

    for run in range(1, _MAX_RUN + 1):  # \s+  and  \s*:\s*
        add(run, r"[\s:]{%d}" % run)
    for lead in range(0, _MAX_RUN):  # \s* before the keyword
        for keyword in _SEPARATOR_KEYWORDS:
            for tail in range(0, _MAX_RUN + 1):  # \s*:?\s* after the keyword
                fragment = re.escape(keyword)
                if lead:
                    fragment = r"\s{%d}" % lead + fragment
                if tail:
                    fragment += r"[\s:]{%d}" % tail
                add(lead + len(keyword) + tail, fragment)
    return by_width


def _literal(label: str) -> str:
    """'medical claim' -> r'medical\\sclaim' (a blank stands for the upstream recognizer's \\s+)."""
    return re.escape(label).replace("\\ ", r"\s")


def _labelled(labels: Sequence[str], body: str) -> str:
    """
    Regex matching `body` only when it directly follows one of `labels` plus a
    separator, i.e. the upstream recognizer's (?<=\\b(?:labels)(?:separator))body built from
    fixed-width lookbehinds. `body` doubles as a lookahead gate so the lookbehind
    alternation is only evaluated where an identifier could start.
    """
    by_width: Dict[int, List[str]] = {}
    for label in labels:
        by_width.setdefault(len(label), []).append(_literal(label))
    label_groups = ["(?:%s)" % "|".join(frags) for _, frags in sorted(by_width.items())]

    branches = []
    for width, separators in sorted(_separator_fragments().items()):
        label_lookbehinds = "|".join(r"(?<=\b%s.{%d})" % (group, width) for group in label_groups)
        branches.append(r"(?<=(?:%s))(?:%s)" % ("|".join(separators), label_lookbehinds))
    return r"(?=%s)(?:%s)%s" % (body, "|".join(branches), body)


# The IRS prefix list excludes 00, 07-09, 17-19, 28-29, 49, 69-70, 78-79, 89, and 96-97.
_VALID_EIN_PREFIX = r"(?:0[1-6]|1[0-6]|2[0-7]|3[0-9]|4[0-8]|5[0-9]|6[0-8]|7[1-7]|8[0-8]|9[0-5]|9[89])"

_PROVIDER_TAX_LABELS = [
    # (?:(?:billing|rendering|healthcare)\s+provider|provider\s+organization|provider)\s+
    # (?:tax\s*(?:id|number|identification\s+number)|tin|ein)
    f"{head} {tail}"
    for head in ("billing provider", "rendering provider", "healthcare provider", "provider organization", "provider")
    for tail in (
        "tax id", "taxid", "tax number", "taxnumber",
        "tax identification number", "taxidentification number", "tin", "ein",
    )
] + ["billing provider"]


# --------------------------------------------------------------------------
# US MBI regex building blocks  (us_mbi_recognizer.py)
# --------------------------------------------------------------------------
_MBI_VALID_LETTERS = "ACDEFGHJKMNPQRTUVWXY"  # A-Z excluding S, L, O, I, B, Z
_MBI_NUM = "[0-9]"
_MBI_ALPHA = f"[{_MBI_VALID_LETTERS}]"
_MBI_ALPHANUM = f"[0-9{_MBI_VALID_LETTERS}]"
# Pos: 1 NUM, 2 ALPHA, 3 ALPHANUM, 4 NUM, 5 ALPHA, 6 ALPHANUM, 7 NUM, 8 ALPHA, 9 ALPHA, 10 NUM, 11 NUM
_MBI_NO_DASH = (
    f"{_MBI_NUM}{_MBI_ALPHA}{_MBI_ALPHANUM}{_MBI_NUM}"
    f"{_MBI_ALPHA}{_MBI_ALPHANUM}{_MBI_NUM}"
    f"{_MBI_ALPHA}{_MBI_ALPHA}{_MBI_NUM}{_MBI_NUM}"
)
_MBI_WITH_DASH = (
    f"{_MBI_NUM}{_MBI_ALPHA}{_MBI_ALPHANUM}{_MBI_NUM}-"
    f"{_MBI_ALPHA}{_MBI_ALPHANUM}{_MBI_NUM}-"
    f"{_MBI_ALPHA}{_MBI_ALPHA}{_MBI_NUM}{_MBI_NUM}"
)


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
RULES: List[Rule] = [
    # ---------------------------------------------------------------- US
    Rule(
        name="US SSN",
        category=_REGIONAL,
        severity="Critical",
        region="US",
        description="US Social Security Number (UsSsnRecognizer): AAA-GG-SSSS with delimiter, group and sample-number checks.",
        patterns=[
            Pattern("SSN1 (very weak)", r"\b([0-9]{5})-([0-9]{4})\b", 0.05),
            Pattern("SSN2 (very weak)", r"\b([0-9]{3})-([0-9]{6})\b", 0.05),
            Pattern("SSN3 (very weak)", r"\b(([0-9]{3})-([0-9]{2})-([0-9]{4}))\b", 0.05),
            Pattern("SSN4 (very weak)", r"\b[0-9]{9}\b", 0.05),
            Pattern("SSN5 (medium)", r"\b([0-9]{3})[- .]([0-9]{2})[- .]([0-9]{4})\b", 0.5),
        ],
        context=["social", "security", "ssn", "ssns", "ssid"],
        invalidator=_invalidate_us_ssn,
        field_hint=r"(?<![a-z])ssns?(?![a-z])|social_?security|social_?sec(?![a-z])|(?<![a-z])ss_?(num|no|number)(?![a-z])",
        examples=["219-09-9999", "987-65-4321", "078 05 1123"],
    ),
    Rule(
        name="US_ITIN",
        category=_REGIONAL,
        severity="High",
        region="US",
        description="US Individual Taxpayer Identification Number (UsItinRecognizer): 9NN-GG-NNNN with an ITIN group range.",
        patterns=[
            Pattern(
                "Itin (very weak)",
                r"\b9\d{2}[- ](5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))\d{4}\b|\b9\d{2}(5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))[- ]\d{4}\b",
                0.05,
            ),
            Pattern("Itin (weak)", r"\b9\d{2}(5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))\d{4}\b", 0.3),
            Pattern("Itin (medium)", r"\b9\d{2}[- ](5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))[- ]\d{4}\b", 0.5),
        ],
        context=["individual", "taxpayer", "itin", "tax", "payer", "taxid", "tin"],
        field_hint=r"(?<![a-z])itin(?![a-z])|taxpayer_?id|tax_?id(?![a-z])",
        examples=["911-70-1234", "911701234"],
    ),
    Rule(
        name="US_PASSPORT",
        category=_REGIONAL,
        severity="High",
        region="US",
        description="US passport number (UsPassportRecognizer): 9 digits or letter + 8 digits (next generation).",
        patterns=[
            Pattern("Passport (very weak)", r"(\b[0-9]{9}\b)", 0.05),
            Pattern("Passport Next Generation (very weak)", r"(\b[A-Z][0-9]{8}\b)", 0.1),
        ],
        context=["us", "united", "states", "passport", "passport#", "travel", "document"],
        field_hint=r"passport",
        examples=["912803456", "A12803456"], #pragma: allowlist secret
    ),
    Rule(
        name="US_DRIVER_LICENSE",
        category=_REGIONAL,
        severity="High",
        region="US",
        description="US driver license number (UsLicenseRecognizer): state alphanumeric formats plus a very weak digits-only form.",
        patterns=[
            Pattern(
                "Driver License - Alphanumeric (weak)",
                r"\b([A-Z][0-9]{3,6}|[A-Z][0-9]{5,9}|[A-Z][0-9]{6,8}|[A-Z][0-9]{4,8}|[A-Z][0-9]{9,11}|[A-Z]{1,2}[0-9]{5,6}|H[0-9]{8}|V[0-9]{6}|X[0-9]{8}|A-Z]{2}[0-9]{2,5}|[A-Z]{2}[0-9]{3,7}|[0-9]{2}[A-Z]{3}[0-9]{5,6}|[A-Z][0-9]{13,14}|[A-Z][0-9]{18}|[A-Z][0-9]{6}R|[A-Z][0-9]{9}|[A-Z][0-9]{1,12}|[0-9]{9}[A-Z]|[A-Z]{2}[0-9]{6}[A-Z]|[0-9]{8}[A-Z]{2}|[0-9]{3}[A-Z]{2}[0-9]{4}|[A-Z][0-9][A-Z][0-9][A-Z]|[0-9]{7,8}[A-Z])\b",
                0.3,
            ),
            Pattern("Driver License - Digits (very weak)", r"\b([0-9]{6,14}|[0-9]{16})\b", 0.01),
        ],
        context=["driver", "license", "permit", "lic", "identification", "dls", "cdls", "lic#", "driving"],
        field_hint=r"driv(er|ing)s?_?licen[cs]e|(?<![a-z])dl_?(num|no|number|id)(?![a-z])|(?<![a-z])dln(?![a-z])",
        examples=["H12234567"],
    ),
    Rule(
        name="Bank Account",
        category=_FINANCIAL,
        severity="High",
        region="US",
        description="US bank account number (UsBankRecognizer): 8-17 digits, relies on banking context words.",
        patterns=[Pattern("Bank Account (weak)", r"\b[0-9]{8,17}\b", 0.05)],
        context=["check", "account", "account#", "acct", "bank", "save", "debit"],
        field_hint=r"bank_?acc(oun)?t|(checking|savings|deposit)_?acc(oun)?t|acc(oun)?t_?(num|no|number)(?![a-z])|(?<![a-z])acct(?![a-z])",
        examples=["945456787654"],
    ),
    Rule(
        name="ABA_ROUTING_NUMBER",
        category=_FINANCIAL,
        severity="Low",
        region="US",
        description="ABA routing transit number (AbaRoutingRecognizer): 9 digits with the 3-7-1 weighted checksum.",
        patterns=[
            Pattern("ABA routing number (weak)", r"\b[0123678]\d{8}\b", 0.05),
            Pattern("ABA routing number", r"\b[0123678]\d{3}-\d{4}-\d\b", 0.3),
        ],
        context=["aba", "routing", "abarouting", "association", "bankrouting"],
        validator=_validate_aba_routing,
        field_hint=r"routing|(?<![a-z])aba(?![a-z])|(?<![a-z])rtn(?![a-z])",
        examples=["121000358", "3222-7162-7"],
    ),
    Rule(
        name="MEDICAL_LICENSE",
        category=_PHI,
        severity="Low",
        region="US",
        description="US DEA certificate / medical license number (MedicalLicenseRecognizer): 2 letters + 7 digits with DEA check digit.",
        patterns=[
            Pattern(
                "USA DEA Certificate Number (weak)",
                r"[abcdefghjklmprstuxABCDEFGHJKLMPRSTUX]{1}[a-zA-Z]{1}\d{7}|"
                r"[abcdefghjklmprstuxABCDEFGHJKLMPRSTUX]{1}9\d{7}",
                0.4,
            ),
        ],
        context=["medical", "certificate", "DEA"],
        validator=_validate_medical_license,
        field_hint=r"(?<![a-z])dea(?![a-z])|medical_?licen[cs]e",
        examples=["GL0285191", "BB1388568", "K92993548"],
    ),
    Rule(
        name="US_NPI",
        category=_PHI,
        severity="Low",
        region="US",
        description="US National Provider Identifier (UsNpiRecognizer): 10 digits starting 1/2, Luhn over 80840-prefixed number.",
        patterns=[
            Pattern("NPI (weak)", r"\b[12]\d{9}\b", 0.1),
            Pattern("NPI (medium)", r"\b[12]\d{3}[ -]\d{3}[ -]\d{3}\b", 0.4),
        ],
        context=["npi", "national provider", "provider", "npi number", "provider id", "provider identifier", "taxonomy"],
        validator=_validate_us_npi,
        invalidator=_invalidate_us_npi,
        field_hint=r"(?<![a-z])npi(?![a-z])|national_?provider",
        examples=["1234567893", "1234-567-893"],
    ),
    Rule(
        name="US_MBI",
        category=_PHI,
        severity="High",
        region="US",
        description="US Medicare Beneficiary Identifier (UsMbiRecognizer): 11 positions typed C A AN N A AN N A A N N, optional dashes.",
        patterns=[
            Pattern("MBI (weak)", rf"\b{_MBI_NO_DASH}\b", 0.3),
            Pattern("MBI (medium)", rf"\b{_MBI_WITH_DASH}\b", 0.5),
        ],
        context=["medicare", "mbi", "beneficiary", "cms", "medicaid", "hic", "hicn"],
        field_hint=r"(?<![a-z])mbi(?![a-z])|medicare|beneficiary_?(id|num|no|number)",
        examples=["1EG4-TE5-MK73", "1EG4TE5MK73"],
    ),
    Rule(
        name="US_HEALTH_INSURANCE_MEMBER_ID",
        category=_PHI,
        severity="High",
        region="US",
        description="US health insurance member/subscriber ID (UsHealthInsuranceMemberIdRecognizer): 6-20 char alphanumeric, needs insurance context.",
        patterns=[
            Pattern(
                "Health insurance member ID (weak)",
                r"\b(?=[A-Z0-9-]{6,20}\b)(?=[A-Z0-9-]*[A-Z])"
                r"(?=[A-Z0-9-]*\d)[A-Z]{1,5}-?[A-Z0-9]{5,14}\b",
                0.1,
            ),
        ],
        context=["member", "subscriber", "insurance", "policy"],
        field_hint=r"member_?(id|num|no|number)|subscriber_?(id|num|no|number)|insurance_?(id|num|no|number)|policy_?(num|no|number)",
        examples=["ABC123456789", "ZX-987654321", "HPN12345A9"], #pragma: allowlist secret
    ),
    Rule(
        name="US_PRIOR_AUTHORIZATION_NUMBER",
        category=_PHI,
        severity="High",
        region="US",
        description="US healthcare prior authorization number (UsPriorAuthorizationNumberRecognizer): label-anchored digits or PA- prefix.",
        patterns=[
            # upstream: (?<=\b(?:prior\s+authorization|prior\s+auth|preauthorization|pre-auth|authorization)
            #           (?:\s*(?:#|no\.?|number|id)\s*:?\s*|\s*:\s*|\s+))(?:PA-?)?\d{6,12}\b
            Pattern(
                "Prior authorization number (labelled)",
                _labelled(
                    ["prior authorization", "prior auth", "preauthorization", "pre-auth", "authorization"],
                    r"(?:PA-?)?\d{6,12}\b",
                ),
                0.35,
            ),
            Pattern("Prior authorization number (weak prefixed)", r"\bPA-?\d{6,12}\b", 0.1),
        ],
        context=["authorization", "auth", "preauthorization", "approval"],
        field_hint=r"prior_?auth|pre_?auth|authorization_?(num|no|number|id|code)|(?<![a-z])auth_?(num|no|number)(?![a-z])",
        examples=["PA-987654321"],
    ),
    Rule(
        name="US_CLAIM_NUMBER",
        category=_PHI,
        severity="High",
        region="US",
        description="US healthcare claim number (UsClaimNumberRecognizer): label-anchored digits or CLM- prefix.",
        patterns=[
            # upstream: (?<=\b(?:claim|medical\s+claim|healthcare\s+claim)
            #           (?:\s*(?:#|no\.?|number|id)\s*:?\s*|\s*:\s*|\s+))(?:CLM-?)?\d{6,15}\b
            Pattern(
                "Claim number (labelled)",
                _labelled(["claim", "medical claim", "healthcare claim"], r"(?:CLM-?)?\d{6,15}\b"),
                0.35,
            ),
            Pattern("Claim number (weak prefixed)", r"\bCLM-?\d{6,15}\b", 0.1),
        ],
        context=["claim", "billing"],
        field_hint=r"claim_?(num|no|number|id|ref)|(?<![a-z])clm_?(num|no|number|id)?(?![a-z])",
        examples=["CLM456789123"],
    ),
    Rule(
        name="US_PRESCRIPTION_NUMBER",
        category=_PHI,
        severity="High",
        region="US",
        description="US prescription number (UsPrescriptionNumberRecognizer): Rx/prescription label-anchored digits or RX- prefix.",
        patterns=[
            # upstream: (?<=\brx(?:\s*(?:#|no\.?|number|id)\s*:?\s*|\s*:\s*|\s+))(?:RX-?)?\d{6,12}\b
            Pattern("Prescription number (Rx labelled)", _labelled(["rx"], r"(?:RX-?)?\d{6,12}\b"), 0.6),
            # upstream: (?<=\bprescription(?:\s*(?:#|no\.?|number|id)\s*:?\s*|\s*:\s*|\s+))(?:RX-?)?\d{6,12}\b
            Pattern("Prescription number (labelled)", _labelled(["prescription"], r"(?:RX-?)?\d{6,12}\b"), 0.35),
            Pattern("Prescription number (weak prefixed)", r"\bRX-?\d{6,12}\b", 0.1),
        ],
        context=["prescription", "pharmacy", "medication"],
        field_hint=r"prescription_?(num|no|number|id)|(?<![a-z])rx_?(num|no|number|id)?(?![a-z])",
        examples=["RX789456123"],
    ),
    Rule(
        name="US_REFERRAL_NUMBER",
        category=_PHI,
        severity="High",
        region="US",
        description="US healthcare referral number (UsReferralNumberRecognizer): label-anchored digits or REF-/INF- prefix.",
        patterns=[
            # upstream: (?<=\b(?:referral|infusion\s+referral)
            #           (?:\s*(?:#|no\.?|number|id)\s*:?\s*|\s*:\s*|\s+))(?:(?:REF|INF)-?)?\d{6,12}\b
            Pattern(
                "Referral number (labelled)",
                _labelled(["referral", "infusion referral"], r"(?:(?:REF|INF)-?)?\d{6,12}\b"),
                0.35,
            ),
            Pattern("Referral number (weak prefixed)", r"\b(?:REF|INF)-?\d{6,12}\b", 0.1),
        ],
        context=["referral", "infusion", "specialty", "referring"],
        field_hint=r"referral_?(num|no|number|id)",
        examples=["INF2025001234", "REF123456"],
    ),
    Rule(
        name="US_PROVIDER_TAX_ID",
        category=_PHI,
        severity="High",
        region="US",
        description="US healthcare provider tax ID (UsProviderTaxIdRecognizer): IRS EIN format NN-NNNNNNN with a valid prefix.",
        patterns=[
            # upstream: (?<=\b(?:(?:(?:billing|rendering|healthcare)\s+provider|provider\s+organization|provider)\s+
            #           (?:tax\s*(?:id|number|identification\s+number)|tin|ein)|billing\s+provider)
            #           (?:\s*(?:#|no\.?|number|id)\s*:?\s*|\s*:\s*|\s+))VALID_EIN_PREFIX-\d{7}\b
            Pattern(
                "Provider tax ID (labelled)",
                _labelled(_PROVIDER_TAX_LABELS, _VALID_EIN_PREFIX + r"-\d{7}\b"),
                0.35,
            ),
            Pattern("Provider tax ID (weak valid EIN)", r"\b" + _VALID_EIN_PREFIX + r"-\d{7}\b", 0.1),
        ],
        context=["tax", "tin", "ein", "billing"],
        field_hint=r"provider_?(tax_?id|tin|ein)|billing_?provider|(?<![a-z])(tin|ein)(?![a-z])",
        examples=["12-3456789", "20-1234567"],
    ),
    # ---------------------------------------------------------------- CA
    Rule(
        name="CA SIN",
        category=_REGIONAL,
        severity="Critical",
        region="CA",
        description="Canadian Social Insurance Number (CaSinRecognizer): 9 digits, first digit 1-7/9, Luhn check digit.",
        patterns=[
            Pattern("SIN (weak)", r"\b[1-79]\d{8}\b", 0.05),
            Pattern("SIN (medium)", r"\b[1-79]\d{2}([- ])\d{3}\1\d{3}\b", 0.5),
        ],
        context=[
            "sin",
            "sin number",
            "social insurance",
            "social insurance number",
            "canada",
            # French equivalents
            "nas",
            "numéro nas",
            "numéro d'assurance sociale",
            "assurance sociale",
        ],
        invalidator=_invalidate_ca_sin,
        field_hint=r"(?<![a-z])sin(?![a-z])|social_?insurance|assurance_?sociale|numero_?nas",
        examples=["130 692 544", "347-677-452", "130692544"],
    ),
    Rule(
        name="CA_POSTAL_CODE",
        category=_PII,
        severity="Low",
        region="CA",
        description="Canadian postal code (CaPostalCodeRecognizer): A1A 1A1, letters D/F/I/O/Q/U never used, W/Z not first.",
        patterns=[
            Pattern(
                "CA Postal Code (strict, with space)",
                r"\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z] \d[ABCEGHJ-NPRSTV-Z]\d\b",
                0.3,
            ),
            Pattern(
                "CA Postal Code (weak, no space)",
                r"\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z]\d[ABCEGHJ-NPRSTV-Z]\d\b",
                0.1,
            ),
        ],
        context=[
            "postal code",
            "postcode",
            "zip",
            "canada",
            "ontario",
            "quebec",
            "alberta",
            "british columbia",
            # French equivalents
            "code postal",
        ],
        field_hint=r"postal_?code|post_?code|code_?postal|(?<![a-z])zip_?(code)?(?![a-z])",
        examples=["K1A 0A1", "M5V 3A8", "K1A0A1"],
    ),
]
