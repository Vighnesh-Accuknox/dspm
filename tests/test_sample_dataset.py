"""sample_data/all_detectors.* cover every detector they list (built by tests/sample_dataset_builder.py)."""
from tests import sample_dataset_builder as builder


def test_all_detectors_dataset_is_detected():
    expected = builder.expected_detectors()
    assert len(expected) >= 250
    jsonl, text = builder.scan_files()
    missing_jsonl = sorted(expected - jsonl)
    assert not missing_jsonl, f"detectors listed in all_detectors.jsonl but not found: {missing_jsonl}"
    # the unstructured path (keyword + value per line) covers the self-describing and keyword-backed detectors;
    # column-hint-only recognizers (weak passport / licence shapes) legitimately need a column
    missing_text = sorted(expected - text)
    assert len(missing_text) <= len(expected) * 0.25, missing_text


def test_dataset_is_in_sync_with_the_catalogue():
    rows, missing = builder.build()
    assert not missing, f"mapping entries without a sample: {missing}"
    assert {r["_detector"] for r in rows} == builder.expected_detectors(), "run: python -m tests.sample_dataset_builder"
