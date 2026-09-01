"""Person names in prose via the optional spaCy layer (src/engine/ner.py); skipped when the model is absent."""
from src.engine import ner
from src.engine.detector import DetectionEngine
from src.pipeline import Cell, Record, TextBlob, UnitClassifier


def _skip():
    if not ner.available():
        print("        (skipped: no spaCy model installed)")
        return True
    return False


def test_model_selection_and_switch():
    if _skip():
        return
    assert ner.model_name() in ner.MODEL_PREFERENCE
    # an explicit NER_MODEL wins over the preference order; an unknown name disables the layer cleanly
    import os
    from unittest.mock import patch

    saved = (ner._NLP, ner._MODEL_NAME, ner._LOAD_FAILED)
    try:
        ner._NLP, ner._MODEL_NAME, ner._LOAD_FAILED = None, None, False
        with patch.dict(os.environ, {"NER_MODEL": "en_core_web_sm"}):
            assert ner.available() and ner.model_name() == "en_core_web_sm"
        ner._NLP, ner._MODEL_NAME, ner._LOAD_FAILED = None, None, False
        with patch.dict(os.environ, {"NER_MODEL": "no_such_model"}):
            assert not ner.available() and ner.model_name() is None
    finally:
        ner._NLP, ner._MODEL_NAME, ner._LOAD_FAILED = saved


def test_prose_gate_and_acceptance_rules():
    assert not ner.looks_like_prose("Priya Sharma")
    assert ner.looks_like_prose("Please contact Priya Sharma about the invoice for last month.")
    assert ner._acceptable("Priya Sharma") and ner._acceptable("Daniel J. Whitmore") and ner._acceptable("Ludwig van Beethoven")
    assert not ner._acceptable("ACME Corp") and not ner._acceptable("Priya") and not ner._acceptable("Error 500")
    assert not ner._acceptable("AWS Lambda") and not ner._acceptable("new york")


def test_names_in_prose_are_possible_unless_corroborated():
    if _skip():
        return
    engine = DetectionEngine()
    text = "Please contact Priya Sharma or Daniel Whitmore regarding the invoice raised last week."
    found = engine.scan_text(text, min_confidence="possible")
    names = {f["value"]: f for f in found if f["detector"] == "PII.PersonName"}
    assert {"Priya Sharma", "Daniel Whitmore"} <= set(names)
    assert names["Priya Sharma"]["confidence"] == "likely" and "context:contact" in names["Priya Sharma"]["evidence"]
    # not reported at the default tier without corroboration
    plain = "The parcel for Daniel Whitmore was left at the reception desk this morning."
    assert [f["confidence"] for f in engine.scan_text(plain, min_confidence="possible") if f["detector"] == "PII.PersonName"] == ["possible"]
    assert [f for f in engine.scan_text(plain) if f["detector"] == "PII.PersonName"] == []
    assert [f for f in engine.scan_text("Patient Daniel Whitmore was admitted on Monday for observation.") if f["detector"] == "PII.PersonName"]
    assert DetectionEngine({"ner": False}).scan_text(text, min_confidence="possible") == []


def test_technical_prose_yields_no_names():
    if _skip():
        return
    engine = DetectionEngine()
    for text in (
        "The API returned HTTP 500 from Amazon Web Services after the Lambda timeout was exceeded.",
        "Deploy the Helm chart to the Kubernetes cluster and restart the Nginx Ingress Controller pods.",
        "Terraform plan failed because the S3 bucket policy denies the GetObject action for that role.",
    ):
        assert [f for f in engine.scan_text(text, min_confidence="possible") if f["detector"] == "PII.PersonName"] == [], text


def test_document_with_many_names_is_likely():
    if _skip():
        return
    names = [
        "Priya Sharma", "Daniel Whitmore", "Amara Okafor", "Lucas Moreau", "Mei Lin Chen", "Rohan Mehta",
        "Sofia Alvarez", "Tomasz Nowak", "Hana Kobayashi", "Elena Petrova", "Omar Haddad", "Ingrid Larsen",
    ]
    text = "\n".join(f"The parcel for {n} was left at the reception desk after the courier called twice." for n in names)
    clf = UnitClassifier(DetectionEngine(), "unit://doc")
    clf.feed(TextBlob(text, location="PDF Page 1"))
    out = [f for f in clf.finish() if f["detector"] == "PII.PersonName"]
    assert len(out) >= 10 and all(f["confidence"] == "likely" and any(e.startswith("count:") for e in f["evidence"]) for f in out)
    # a single-name cell in a name column still goes through the field rule, not the model
    clf = UnitClassifier(DetectionEngine(), "unit://t")
    clf.feed(Record([Cell("Priya Sharma", "full_name", "r0")]))
    assert [(f["detector"], f["confidence"]) for f in clf.finish()] == [("PII.PersonName", "likely")]
