"""
Optional named-entity recognition for person names in prose.

Names that sit in a name-labelled column are handled by the field rules
(layers.scan_person_names); names inside free text - a support note, a PDF
page, a comment field - need a model. Macie's NAME, Purview's named-entity
SITs and Cyera's NER all do this with a statistical model, and so does this
module with spaCy: the transformer pipeline en_core_web_trf (RoBERTa, OntoNotes
NER F1 0.90) when it is installed, else en_core_web_sm (F1 0.84, 40x smaller);
NER_MODEL picks the model explicitly. Without any model the layer is silently
absent.

A PERSON entity is accepted when it looks like a written personal name: two
to four title-case alphabetic tokens (initials and particles allowed), no
digits, no all-caps acronym, not followed by a company suffix. The small
model labels many non-Western names as ORG / GPE / FAC; such entities are
accepted when their first token is a known given name (data/given_names.txt),
the lexicon trick Cyera and Presidio-style pipelines rely on. Every hit is a
`possible` candidate - the pipeline decides whether a document holds enough
distinct names, a name field or a context word backs it, or a free-text
column is mostly names (src/pipeline). Context words next to the name (patient,
customer, employee, regards, dear, mr/ms/dr ...) make it `likely` on its own.
"""
import os
import re
from typing import Any, List, Optional, Tuple

from src.engine.data import load_given_names

MAX_CHARS = 50_000
LOOSE_LABELS = frozenset({"ORG", "GPE", "FAC", "WORK_OF_ART", "NORP", "PRODUCT", "LOC", "EVENT"})
MODEL_PREFERENCE = ("en_core_web_trf", "en_core_web_sm")
# pipeline components NER does not need; dropping them halves the cost of the statistical models
_UNUSED_PIPES = ("tagger", "parser", "attribute_ruler", "lemmatizer", "textcat")
_MODEL_NAME: Optional[str] = None
_NLP: Any = None
_LOAD_FAILED = False

NAME_TOKEN_RE = re.compile(r"^(?:[A-Z][a-z\'\-]+|[A-Z]\.?|(?:de|da|di|del|della|van|von|der|den|la|le|du|bin|ibn|al|el|st\.?)|Mc[A-Z][a-z]+|O\'[A-Z][a-z]+)$")
PARTICLES = frozenset({"de", "da", "di", "del", "della", "van", "von", "der", "den", "la", "le", "du", "bin", "ibn", "al", "el", "st", "st."})
COMPANY_SUFFIX_RE = re.compile(r"^\s*(?:inc|inc\.|ltd|ltd\.|llc|corp|corp\.|co\.|gmbh|plc|pvt|limited|holdings|group|technologies|labs)\b", re.IGNORECASE)
HONORIFIC_RE = re.compile(r"\b(?:mr|mrs|ms|miss|dr|prof|sir|madam|shri|smt|mx)\.?\s*$", re.IGNORECASE)
CONTEXT_RE = re.compile(
    r"\b(?:name|names|patient|customer|client|employee|applicant|contact|owner|holder|beneficiary|guardian|"
    r"spouse|father|mother|son|daughter|regards|sincerely|dear|attn|attention|signed|author|reported by|"
    r"submitted by|prepared by|approved by|cardholder|passenger|student|tenant|driver)\b",
    re.IGNORECASE,
)
STOP_NAMES = frozenset({
    "new york", "los angeles", "san francisco", "hong kong", "united states", "amazon web", "web services",
    "google cloud", "microsoft azure", "read more", "click here", "terms of", "privacy policy", "thank you",
    "best regards", "kind regards", "internal server", "not found", "bad request", "error code",
})


def model_name() -> Optional[str]:
    """Name of the loaded model (en_core_web_trf / en_core_web_sm), None when NER is unavailable."""
    return _MODEL_NAME if available() else None


def available() -> bool:
    """
    A spaCy pipeline is loaded (cached). NER_ENABLED=false disables; NER_MODEL
    names the model, otherwise the first installed of MODEL_PREFERENCE is used.
    """
    global _NLP, _LOAD_FAILED, _MODEL_NAME
    if _NLP is not None:
        return True
    if _LOAD_FAILED or os.environ.get("NER_ENABLED", "true").strip().lower() in ("0", "false", "no", "off"):
        return False
    try:
        import spacy
    except Exception:
        _LOAD_FAILED = True
        return False
    wanted = os.environ.get("NER_MODEL", "").strip()
    candidates = (wanted,) if wanted else MODEL_PREFERENCE
    for name in candidates:
        try:
            nlp = spacy.load(name)
        except Exception:
            continue
        for pipe in _UNUSED_PIPES:
            if pipe in nlp.pipe_names:
                nlp.disable_pipe(pipe)
        _NLP, _MODEL_NAME = nlp, name
        return True
    _LOAD_FAILED = True
    return False


def looks_like_prose(text: str) -> bool:
    """At least six words and thirty characters: a sentence, not a value."""
    if not text or len(text) < 30 or len(text) > 2_000_000:
        return False
    words = 0
    for chunk in text.split():
        if any(c.isalpha() for c in chunk):
            words += 1
            if words >= 6:
                return True
    return False


def _acceptable(name: str) -> bool:
    tokens = name.replace("\n", " ").split()
    if not 2 <= len(tokens) <= 4 or len(name) > 60:
        return False
    if name.lower() in STOP_NAMES:
        return False
    real = 0
    for tok in tokens:
        if any(c.isdigit() for c in tok):
            return False
        if tok.isalpha() and tok.isupper() and len(tok) > 1:
            return False  # acronym
        if tok.lower() in PARTICLES:
            continue
        if not NAME_TOKEN_RE.match(tok):
            return False
        if len(tok.rstrip(".")) > 1:
            real += 1
    return real >= 2 or (real >= 1 and len(tokens) >= 2)


def person_names(text: str) -> List[Tuple[int, int, str, Optional[str]]]:
    """
    (start, end, name, context_word) for every accepted PERSON entity;
    context_word is the corroborating word found in the 40 characters before
    or after the name, or None.
    """
    if not available():
        return []
    doc = _NLP(text[:MAX_CHARS])
    out: List[Tuple[int, int, str, Optional[str]]] = []
    seen = set()
    given = load_given_names()
    for ent in doc.ents:
        if ent.label_ != "PERSON" and ent.label_ not in LOOSE_LABELS:
            continue
        name = ent.text.strip(" \t\r\n,.;:\"\'()")
        if not name or not _acceptable(name):
            continue
        if ent.label_ != "PERSON" and name.split()[0].lower().rstrip(".") not in given:
            continue
        start = ent.start_char + ent.text.find(name)
        end = start + len(name)
        if (start, end) in seen:
            continue
        seen.add((start, end))
        after = text[end:end + 24]
        if COMPANY_SUFFIX_RE.match(after):
            continue
        before = text[max(0, start - 40):start]
        context = None
        if HONORIFIC_RE.search(before):
            context = "honorific"
        else:
            m = CONTEXT_RE.search(before + " " + text[end:end + 40])
            if m:
                context = m.group(0).lower()
        out.append((start, end, name, context))
    return out
