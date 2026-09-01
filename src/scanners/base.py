"""
BaseScanner: the connector contract.

A connector (scanner) knows how to reach a data source, enumerate its units
(tables, collections, objects, sheets) and turn one unit into a stream of
Records or TextBlobs (src/pipeline/records.py). It never calls the detection
engine itself: it hands the stream to `classify()`, which runs the shared
classification pipeline (cell candidates -> context policy -> record
corroboration -> column verdicts -> minimum counts -> aggregation) and returns
findings in the common schema.

Adding a connector therefore means implementing:

    scan(target)            -> List[finding]           required (BaseScanner.scan
                                                        can be `return self.collect(target)`)
    iter_scan(target)       -> (resource_id, unit_name, findings) per unit, when the
                                                        source has many units (databases,
                                                        buckets) so callers can checkpoint
    a record generator per unit that yields Record / TextBlob and updates self.stats

See src/scanners/db/sql.py (columnar rows), src/scanners/db/mongo.py
(documents) and src/scanners/files/parsers.py (files) for the three shapes.
"""
import re
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from src.engine.detector import DetectionEngine
from src.pipeline.classifier import UnitClassifier, dedup
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Scanner-level column suppression, overridable via config {"column_suppression": {...}}.
# The engine already applies its own structural field rules (src/engine/context.py:
# token detectors never fire in id/hash/etag/path columns, digit-run detectors never
# fire in counter/timestamp columns) and the pipeline applies per-detector negative
# field names (src/engine/policy.py). This map is the escape hatch for
# deployment-specific noise; the default mirrors the engine's identifier rule.
DEFAULT_COLUMN_SUPPRESSION = {
    "High Entropy Secret": r"(^|_)(id|ids|uuid|guid|arn|sha\d*|hash|digest|etag|checksum|fingerprint)($|_)",
}

LocationFn = Callable[[str, int], str]


class BaseScanner(ABC):
    """Abstract base class for DSPM scanners (connectors)."""

    def __init__(
        self,
        engine: DetectionEngine,
        config: Dict[str, Any] = None,
        client=None,
    ):
        self.engine = engine
        self.config = config or {}
        self.client = client
        self.stats: Dict[str, Any] = {"errors": 0}

    @abstractmethod
    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Executes scanner logic against the specified target resource.
        Returns a list of findings matching the DSPM schema.
        """

    def iter_scan(self, target: Dict[str, Any]) -> Iterator[Tuple[str, str, List[Dict[str, Any]]]]:
        """
        Yields (resource_id, unit_name, findings) per unit as each finishes.
        Single-unit connectors fall back to one entry wrapping scan().
        """
        yield target.get("resource_id") or "", target.get("name") or "", self.scan(target)

    def collect(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """scan() as the concatenation of iter_scan()."""
        findings: List[Dict[str, Any]] = []
        for _resource_id, _unit, unit_findings in self.iter_scan(target):
            findings.extend(unit_findings)
        return findings

    # ------------------------------------------------------------------ pipeline
    def classify(
        self,
        resource_id: str,
        items: Iterable[Any],
        location_fn: Optional[LocationFn] = None,
        unit_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Runs the classification pipeline over one unit's Record / TextBlob
        stream and returns its findings. unit_name (table, collection, object
        key, sheet) is context for the pipeline. With config adaptive_sampling
        the stream is abandoned once the unit's column verdicts have settled.
        Errors raised by the stream are counted in self.stats and the findings
        gathered so far are still returned.
        """
        classifier = UnitClassifier(
            self.engine, resource_id, location_fn=location_fn, config=self.config, suppressed=self.is_suppressed,
            unit_name=unit_name or resource_id.rsplit("/", 1)[-1],
        )
        adaptive = bool(self.config.get("adaptive_sampling"))
        iterator = iter(items)
        try:
            for item in iterator:
                classifier.feed(item)
                if adaptive and classifier.settled:
                    logger.info(f"Sampling settled for {resource_id} after {classifier.records_seen} records")
                    break
        except Exception as e:
            self.record_error(f"{resource_id}: {str(e)[:200]}")
            logger.error(f"Error while reading {resource_id}: {str(e)}")
        finally:
            close = getattr(iterator, "close", None)
            if callable(close):
                close()
        return classifier.finish()

    def record_error(self, detail: str) -> None:
        self.stats["errors"] = self.stats.get("errors", 0) + 1
        self.stats.setdefault("error_details", []).append(detail)

    # ------------------------------------------------------------------ helpers
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
        """Standardizes findings for the CSPM/Artifact API (used by callers that build findings by hand)."""
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

    def dedup_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Drops exact duplicates: one finding per (resource_id, detector, value,
        location). A value repeated across rows/documents keeps one finding per
        row; columns that fire on every row are collapsed by the pipeline's
        aggregation instead.
        """
        return dedup(findings)
