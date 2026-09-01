"""
Rule-based recognizers (pattern score + context + validator, native implementation).

A Rule is a set of regex patterns with per-pattern confidence scores, optional
context words that raise the confidence when found next to a match, and optional
validator / invalidator callables (checksums, structural checks). Scoring:

  * pattern match             -> score = pattern.score
  * validator(match)   True   -> score = 1.0 ; False -> match dropped ; None -> unchanged
  * invalidator(match) True   -> match dropped
  * context word near match   -> score += context_boost (0.35), floored at
                                 min_score_with_context (0.4), capped at 1.0
  * column / field name       -> treated as context too (structured data); a
                                 field_hint regex match lifts the score to
                                 FIELD_HINT_SCORE (0.85) unless a validator said False

run_rule() returns every match with score > 0 so callers (and tests) can reason
about confidence; DetectionEngine applies the reporting threshold.

Country-specific patterns live in src/engine/recognizers/ (see that package's
docstring for the licence attribution).
"""
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

# Default flags for rule patterns: case-insensitive, multiline, dotall
RULE_FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL

# Score given when the column/field name itself names the entity ("ssn", "passport_no")
FIELD_HINT_SCORE = 0.85

# How far around a match context words are looked for (whole words)
CONTEXT_PREFIX_WORDS = 5
CONTEXT_SUFFIX_WORDS = 3
CONTEXT_WINDOW_CHARS = 120

# Unicode-aware: 'führerschein' and 'henkilötunnus' are words too; '_' splits
_WORD_RE = re.compile(r"[^\W_]+|#")
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_FIELD_SPLIT_RE = re.compile(r"[\W_]+")


@dataclass(frozen=True)
class Pattern:
    """A regex with a confidence score in [0, 1]."""

    name: str
    regex: str
    score: float
    flags: int = RULE_FLAGS

    def __post_init__(self):
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"Pattern '{self.name}': score {self.score} not in [0, 1]")
        object.__setattr__(self, "compiled", _compile(self.regex, self.flags))  # fail fast on bad regex


_COMPILED: Dict[tuple, "re.Pattern"] = {}


def _compile(regex: str, flags: int) -> "re.Pattern":
    key = (regex, flags)
    pat = _COMPILED.get(key)
    if pat is None:
        pat = re.compile(regex, flags)
        _COMPILED[key] = pat
    return pat


Validator = Callable[[str], Optional[bool]]


@dataclass
class Rule:
    """
    A recognizer: detector name + patterns + context + validation.

    name        detector name reported (must exist in fixtures/findings-mapping.json)
    category    finding category ("Regional Compliance", "PII", "Financial Data", ...)
    severity    Critical | High | Medium | Low
    patterns    regexes with scores (strongest first is conventional, order is irrelevant)
    context     words that raise confidence when found near a match or in the field name
    region      ISO-3166 alpha-2 pack the rule belongs to (US, GB, DE, ...); None = generic
    validator   callable(match_text) -> True (valid, score 1.0) / False (drop) / None
    invalidator callable(match_text) -> True to drop the match
    field_hint  regex over the lower-cased column/field name that identifies the entity
    enabled     rules that are pure technical identifiers (URL, UUID) default to False
    examples    valid sample values, used by tests and docs
    """

    name: str
    category: str
    severity: str
    patterns: Sequence[Pattern]
    context: Sequence[str] = ()
    region: Optional[str] = None
    validator: Optional[Validator] = None
    invalidator: Optional[Validator] = None
    field_hint: Optional[str] = None
    enabled: bool = True
    context_boost: float = 0.35
    min_score_with_context: float = 0.4
    description: str = ""
    examples: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self):
        if not self.patterns:
            raise ValueError(f"Rule '{self.name}' has no patterns")
        self.context = tuple(w.lower() for w in self.context)
        if self.region:
            self.region = self.region.upper()
        self._field_hint_re = re.compile(self.field_hint) if self.field_hint else None
        self._max_pattern_score = max(p.score for p in self.patterns)
        self._context_single = frozenset(w for w in self.context if " " not in w)
        self._context_phrases = tuple(w for w in self.context if " " in w)

    def can_reach(self, threshold: float, words: frozenset, lowered: str, field_name: Optional[str]) -> bool:
        """
        Cheap upper bound on the score this rule can produce for a text whose
        lower-cased word set is `words`: rules with a validator can always hit
        1.0; the others need their pattern score plus context/field evidence.
        """
        if self.validator is not None:
            return True
        best = self._max_pattern_score
        if field_name and self._field_hint_re is not None and self._field_hint_re.search(str(field_name).lower()):
            best = max(best, FIELD_HINT_SCORE)
        if best > threshold:
            return True
        if self._context_single & words or any(p in lowered for p in self._context_phrases):
            best = min(1.0, max(best + self.context_boost, self.min_score_with_context))
        return best > threshold


def tokenize_field_name(field_name: Optional[str]) -> List[str]:
    """
    'api_event.http.request.headers.authorization' -> ['api', 'event', 'http', ...]
    'customerSSN' -> ['customer', 'ssn']; 'zipCode' -> ['zip', 'code']
    """
    if not field_name:
        return []
    parts = []
    for chunk in _FIELD_SPLIT_RE.split(str(field_name)):
        if not chunk:
            continue
        for token in _CAMEL_RE.split(chunk):
            if token:
                parts.append(token.lower())
    return parts


def _context_words(text: str, start: int, end: int) -> str:
    """Lower-cased window of whole words around a match, joined by single spaces."""
    before = text[max(0, start - CONTEXT_WINDOW_CHARS):start]
    after = text[end:end + CONTEXT_WINDOW_CHARS]
    words_before = _WORD_RE.findall(before)[-CONTEXT_PREFIX_WORDS:]
    words_after = _WORD_RE.findall(after)[:CONTEXT_SUFFIX_WORDS]
    return " ".join(w.lower() for w in words_before + words_after)


def find_context_word(rule: Rule, text: str, start: int, end: int, field_name: Optional[str]) -> Optional[str]:
    """
    Returns the first context word of the rule found as a whole word in the
    surrounding text or in the field name, else None.
    """
    if not rule.context:
        return None
    haystacks = [" " + _context_words(text, start, end) + " "]
    field_tokens = tokenize_field_name(field_name)
    if field_tokens:
        haystacks.append(" " + " ".join(field_tokens) + " ")
        # Compound field names ('socialsecurity', 'ssnumber') are compared as one word too
        haystacks.append(" " + "".join(field_tokens) + " ")
    for kw in rule.context:
        probe = " " + kw + " "
        for hay in haystacks:
            if probe in hay:
                return kw
    return None


def _dedupe(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """upstream remove_duplicates: drop matches contained in a higher/equal-scored match."""
    if len(results) < 2:
        return results
    results.sort(key=lambda r: (-r["score"], -(r["end"] - r["start"]), r["start"]))
    kept: List[Dict[str, Any]] = []
    for r in results:
        if any(k["start"] <= r["start"] and r["end"] <= k["end"] and k["score"] >= r["score"] for k in kept):
            continue
        kept.append(r)
    kept.sort(key=lambda r: r["start"])
    return kept


def run_rule(rule: Rule, text: str, field_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Applies one Rule to text. Returns finding dicts (detector, category, severity,
    value, score, start, end, pattern, context_word) for every match with score > 0.
    """
    if not text:
        return []
    results: List[Dict[str, Any]] = []
    field_hint_hit = bool(field_name and rule._field_hint_re is not None and rule._field_hint_re.search(str(field_name).lower()))

    for pattern in rule.patterns:
        for match in pattern.compiled.finditer(text):
            start, end = match.span()
            value = text[start:end]
            if not value:
                continue
            score = pattern.score

            validation = rule.validator(value) if rule.validator else None
            if validation is True:
                score = 1.0
            elif validation is False:
                continue

            if rule.invalidator and rule.invalidator(value):
                continue

            context_word = find_context_word(rule, text, start, end, field_name)
            if context_word is not None:
                score = min(1.0, max(score + rule.context_boost, rule.min_score_with_context))
            if field_hint_hit:
                score = max(score, FIELD_HINT_SCORE)

            if score <= 0:
                continue
            results.append({
                "detector": rule.name,
                "category": rule.category,
                "severity": rule.severity,
                "value": value,
                "score": round(score, 4),
                "start": start,
                "end": end,
                "pattern": pattern.name,
                "context_word": context_word,
                "field_hint": field_hint_hit,
            })
    return _dedupe(results)


def run_rules(
    rules: Sequence[Rule],
    text: str,
    field_name: Optional[str] = None,
    enabled_regions: Optional[Sequence[str]] = None,
    threshold: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """
    Runs every enabled rule whose region is generic or in enabled_regions.
    With a threshold, rules that cannot score above it for this text (no
    validator, weak pattern, no context word / field hint present) are skipped
    before any regex runs - the result is identical, most of the work is not.
    """
    regions = {r.upper() for r in (enabled_regions or [])}
    out: List[Dict[str, Any]] = []
    words: frozenset = frozenset()
    lowered = ""
    if threshold is not None:
        lowered = text.lower() + " " + " ".join(tokenize_field_name(field_name))
        words = frozenset(_WORD_RE.findall(lowered)) | frozenset("".join(tokenize_field_name(field_name)).split())
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.region and rule.region not in regions:
            continue
        if threshold is not None and not rule.can_reach(threshold, words, lowered, field_name):
            continue
        out.extend(run_rule(rule, text, field_name))
    return out
