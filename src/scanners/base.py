import re
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Tuple

from src.engine.detector import DetectionEngine

# Detectors that are structurally noisy for certain column/field names:
# random ids and hashes light up the entropy detector. Overridable via
# config {"column_suppression": {...}}. (No date rule: birth_date columns
# would match *_date, and the engine's year-range + birth-context checks
# already drop operational timestamps.)
DEFAULT_COLUMN_SUPPRESSION = {
    "High Entropy Secret": r"(^|_)(id|ids|uuid|guid|arn|sha\d*|hash|digest|etag|checksum|fingerprint)($|_)",
}


class BaseScanner(ABC):
    """
    Abstract base class for DSPM scanners.
    """

    def __init__(
        self,
        engine: DetectionEngine,
        config: Dict[str, Any] = None,
        client=None,
    ):
        self.engine = engine
        self.config = config or {}
        self.client = client

    @abstractmethod
    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Executes scanner logic against the specified target resource.
        Returns a list of findings matching the DSPM schema.
        """
        pass

    def format_finding(
        self,
        detector: str,
        category: str,
        severity: str,
        value: str,
        resource_id: str,
        location: str,
        extra: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Standardizes findings for the CSPM/Artifact API.
        """
        finding = {
            "resource_id": resource_id,
            "detector": detector,
            "category": category,
            "severity": severity,
            "value": value,
            "location": location,
        }
        if extra:
            finding.update(extra)
        return finding

    def is_suppressed(self, detector: str, column_name: str) -> bool:
        """
        True when a detector is structurally noisy for this column/field name
        (see DEFAULT_COLUMN_SUPPRESSION). Override or disable via
        config {"column_suppression": {detector: regex}} / {}.
        """
        rules = self.config.get("column_suppression", DEFAULT_COLUMN_SUPPRESSION)
        pattern = rules.get(detector)
        if not pattern or not column_name:
            return False
        try:
            return re.search(pattern, column_name.lower()) is not None
        except re.error:
            return False

    def flush_grouped_findings(
        self, grouped: Dict[Tuple[str, str], List[Dict[str, Any]]],
        location_fn: Callable[[str, int], str],
    ) -> List[Dict[str, Any]]:
        """
        Emits findings buffered per (detector, column). A group with at least
        config aggregation_threshold hits (default 25) collapses into a single
        column-level finding carrying the occurrence count — a column that fires
        on every row is a data classification, not N separate incidents.
        Set the threshold to 0 to disable aggregation.
        """
        threshold = self.config.get("aggregation_threshold", 25)
        out = []
        for (detector, column), items in grouped.items():
            if threshold and len(items) >= threshold:
                first = items[0]
                out.append(
                    self.format_finding(
                        detector, first["category"], first["severity"], first["value"],
                        first["resource_id"], location_fn(column, len(items)),
                        extra={"aggregated": True, "occurrences": len(items), "column": column},
                    ),
                )
            else:
                out.extend(items)
        return out

    def dedup_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Collapses repeated values (the same secret in many rows/documents) to
        one finding per (resource_id, detector, value).
        """
        seen = set()
        deduped = []
        for f in findings:
            sig = (f.get("resource_id"), f.get("detector"), f.get("value"))
            if sig not in seen:
                seen.add(sig)
                deduped.append(f)
        return deduped
