"""
Adaptive sampling: stop reading a unit once its classification is stable.

Wiz describes its structured-data scans as "statistical sampling of a
sufficient number of records" that keeps "incrementally expanding the sample
until statistical confidence is reached"; Macie samples representative objects
and never re-reads unchanged ones. SettleTracker is the stop rule for one unit:
after a minimum number of records, when no new (column, detector) pair has
appeared for a full window and no column sits within `margin` of its
classification ratio, the verdicts will not change and reading more rows only
costs time. Off by default (config adaptive_sampling); the fixed sample_limit
still caps the read either way.
"""
from typing import Iterable, Tuple


class SettleTracker:
    def __init__(self, enabled: bool = False, min_records: int = 2000, window: int = 1000, margin: float = 0.05):
        self.enabled = enabled
        self.min_records = int(min_records)
        self.window = int(window)
        self.margin = float(margin)
        self.last_change = 0

    def observe(self, records_seen: int, new_pair: bool) -> None:
        if new_pair:
            self.last_change = records_seen

    def settled(self, records_seen: int, ratios: Iterable[Tuple[float, float]]) -> bool:
        """ratios: (match share, classification threshold) for every column profile."""
        if not self.enabled or records_seen < self.min_records:
            return False
        if records_seen - self.last_change < self.window:
            return False
        return all(abs(ratio - threshold) > self.margin for ratio, threshold in ratios)
