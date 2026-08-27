from abc import ABC, abstractmethod
from typing import Any, Dict, List

from src.engine.detector import DetectionEngine


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
            "value": value,  # Usually masked or partial to protect raw data
            "location": location,
        }
        if extra:
            finding.update(extra)
        return finding
