from typing import Any, Dict, List

from src.engine.layers import (
    scan_credentials, scan_entropy, scan_financial,
    scan_healthcare, scan_pii, scan_regional,
)


class DetectionEngine:
    """
    Coordinates detection layers and executes scans on text blobs.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        # Regional compliance packs: e.g., ["US", "IN", "CA", "GB"] (disabled by default)
        self.enabled_regions = self.config.get("enabled_regions", [])

    def scan_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Runs all active scanning layers on the provided text string.
        """
        if not text or not isinstance(text, str):
            return []

        findings = []

        # Run standard layers
        findings.extend(scan_pii(text))
        findings.extend(scan_credentials(text))
        findings.extend(scan_financial(text))
        findings.extend(scan_healthcare(text))
        findings.extend(scan_regional(text, self.enabled_regions))
        findings.extend(scan_entropy(text))

        # Filter findings where score is > 0.8
        filtered_findings = [f for f in findings if f.get("score", 0.0) > 0.8]
        return filtered_findings
