"""
Regression corpus built from real scans (anonymised, see tests/fixtures/detection_corpus.json).

Every 'fp' sample was reported by the engine before the accuracy overhaul and
reviewed as noise; every 'tp' sample is real (or a synthetic recall case).
The test fails when a reviewed false positive comes back or a true positive is
lost - fix the detector or, if the review was wrong, relabel the sample.
"""
import json
from collections import Counter
from pathlib import Path

from src.engine.detector import DetectionEngine

CORPUS = Path(__file__).resolve().parent / "fixtures" / "detection_corpus.json"


def _load():
    return json.loads(CORPUS.read_text())["samples"]


def _evaluate(samples):
    engine = DetectionEngine({"enabled_regions": ["US", "IN", "GB"]})
    fp_retained, tp_missed = [], []
    per_detector = Counter()
    for sample in samples:
        findings = engine.scan_text(sample["text"], field_name=sample.get("field"))
        detectors = {f["detector"] for f in findings}
        categories = {f["category"] for f in findings}
        if sample["kind"] == "fp":
            if detectors & set(sample["forbid_detectors"]) or categories & set(sample["forbid_categories"]):
                if not sample.get("tolerated"):
                    fp_retained.append((sample["id"], sample["old_detector"], sorted(detectors)))
                    per_detector[sample["old_detector"]] += 1
        else:
            if not detectors & set(sample["expect_any"]):
                tp_missed.append((sample["id"], sample.get("old_detector"), sample["expect_any"], sorted(detectors)))
    return fp_retained, tp_missed, per_detector


def test_corpus_is_well_formed():
    samples = _load()
    assert len(samples) > 400
    kinds = Counter(s["kind"] for s in samples)
    assert kinds["fp"] > 300 and kinds["tp"] > 100
    for s in samples:
        assert s["text"] and s["kind"] in ("fp", "tp"), s["id"]
        if s["kind"] == "tp":
            assert s["expect_any"], s["id"]
        else:
            assert s["forbid_detectors"] and s["forbid_categories"], s["id"]


def test_reviewed_false_positives_stay_gone():
    fp_retained, _, per_detector = _evaluate(_load())
    assert not fp_retained, f"{len(fp_retained)} reviewed false positives reported again {dict(per_detector)}: {fp_retained[:10]}"


def test_true_positives_are_still_detected():
    _, tp_missed, _ = _evaluate(_load())
    assert not tp_missed, f"{len(tp_missed)} true positives lost: {tp_missed[:10]}"
