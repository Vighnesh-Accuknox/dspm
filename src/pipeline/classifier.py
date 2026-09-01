"""
UnitClassifier: classifies one unit (a table, a collection, an object, a
sheet) from the records and text blobs a connector streams into it.

Per cell the engine produces `possible`-and-above candidates; the classifier
then applies what every vendor engine layers on top of pattern matching:

  1. Field vetoes        deployment column_suppression, per-detector negative
                         field names, Macie-style allow lists of known values
  2. Context policy      a `context: required` detector whose hit carries neither
                         validation nor context is capped at `possible`
                         (Macie keyword requirements, Nightfall "Possible ignores context")
  3. Record corroboration a `possible` national id / card in a record that also
                         carries two identity signals (name, e-mail, phone, address,
                         birth date) is promoted to `likely` (Purview: SSN next to
                         Name / DateOfBirth; Cyera's identifiability)
  4. Column verdicts     a column whose sampled values match at the policy's ratio
                         is classified as that detector one tier above its cells
                         (Sentra 50% rule, Google column profiles); isolated
                         `possible` hits in an otherwise clean column are dropped
                         (Orca's statistical scan). Sibling columns named for the
                         detector's companions (expiry / CVV next to a card column,
                         date of birth next to a national id) raise it one more tier.
                         A classified column is exclusive: other detectors' hits in it
                         are coincidences unless `very_likely` on their own (Google SDP
                         exclude-if-another-infoType-matched)
  5. Minimum counts      `possible` hits that do not classify a column become `likely`
                         when a unit holds enough distinct ones (Purview "low
                         confidence patterns with counts of 20 or more", Nightfall
                         minimum number of findings, Macie occurrence thresholds)
  6. Reporting tier      findings below min_confidence are dropped
  7. Aggregation         a (column, detector) pair with aggregation_threshold or
                         more hits collapses into one column-level finding carrying
                         occurrences and column statistics

Output dicts keep the schema the scanners always produced (resource_id,
detector, category, severity, value, location) plus confidence, evidence,
value_hash and, for column findings, aggregated / occurrences / column /
column_sampled / column_matches / column_ratio.
"""
import re
from collections import Counter
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

import dataclasses

from src.engine.confidence import at_least, has_context, has_validation, max_tier, normalize, promote, rank
from src.engine.context import field_hints
from src.engine.policy import CONTEXT_NONE, CONTEXT_REQUIRED, DetectorPolicy, policy_for
from src.engine.rules import tokenize_field_name
from src.pipeline.columns import ColumnProfile, column_verdict
from src.pipeline.records import Cell, Record, TextBlob
from src.pipeline.sampling import SettleTracker
from src.utils.logger import get_logger

logger = get_logger(__name__)

CANDIDATE_TIER = "possible"
_PASSTHROUGH_KEYS = ("value_hash",)
STRAGGLER_MIN_VALIDATED_RATIO = 0.2
_EXCLUSIVITY_EXEMPT_CATEGORIES = frozenset({"Credentials and Secrets", "Entropy-Based Secret Detection"})


def _singular(token: str) -> str:
    if len(token) > 4 and token.endswith("ies"):
        return token[:-3] + "y"
    if len(token) > 3 and token.endswith("s") and not token.endswith("ss"):
        return token[:-1]
    return token


def _merge_evidence(items: Iterable[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for item in items:
        for e in item.get("evidence", ()):
            if e not in out:
                out.append(e)
    return out


def dedup(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One finding per (resource_id, detector, value, location)."""
    seen: Set[Tuple[Any, ...]] = set()
    out = []
    for f in findings:
        sig = (f.get("resource_id"), f.get("detector"), f.get("value"), f.get("location"))
        if sig not in seen:
            seen.add(sig)
            out.append(f)
    return out


class UnitClassifier:
    def __init__(
        self,
        engine,
        resource_id: str,
        location_fn: Optional[Callable[[str, int], str]] = None,
        config: Optional[Dict[str, Any]] = None,
        suppressed: Optional[Callable[[str, str], bool]] = None,
        unit_name: Optional[str] = None,
    ):
        cfg = config or {}
        self.engine = engine
        self.resource_id = resource_id
        self.location_fn = location_fn
        self.suppressed = suppressed
        self.unit_name = unit_name or ""
        self.unit_tokens = tokenize_field_name(self.unit_name)
        self._unit_hints: Dict[str, bool] = {}
        self.min_confidence = normalize(cfg.get("min_confidence", engine.min_confidence))
        self.aggregation_threshold = int(cfg.get("aggregation_threshold", 25) or 0)
        self.column_ratio = cfg.get("column_ratio")
        self.column_min_matches = cfg.get("column_min_matches")
        self.min_count = cfg.get("min_count")
        self.allow_values = {str(v) for v in (cfg.get("allow_list") or [])}
        self.allow_regexes = [re.compile(p) for p in (cfg.get("allow_regex") or [])]
        self.settle = SettleTracker(
            enabled=bool(cfg.get("adaptive_sampling")),
            min_records=cfg.get("settle_min_records", 2000),
            window=cfg.get("settle_window", 1000),
            margin=cfg.get("settle_margin", 0.05),
        )
        self.values_seen: Counter = Counter()
        self.profiles: Dict[Tuple[str, str], ColumnProfile] = {}
        self.text_hits: Dict[str, List[Dict[str, Any]]] = {}
        self.records_seen = 0
        self.blobs_seen = 0
        self.candidates = 0

    # ------------------------------------------------------------------ feeding
    def feed(self, item: Any) -> None:
        if isinstance(item, Record):
            self._feed_record(item)
        elif isinstance(item, TextBlob):
            self._feed_blob(item)
        else:
            raise TypeError(f"UnitClassifier.feed expects Record or TextBlob, got {type(item).__name__}")

    def _candidates(self, text: str, field_name: Optional[str]) -> List[Dict[str, Any]]:
        return self.engine.scan_text(text, field_name=field_name, min_confidence=CANDIDATE_TIER)

    def _allowed(self, value: str) -> bool:
        if value in self.allow_values:
            return True
        return any(r.search(value) for r in self.allow_regexes)

    def _vetoed(self, finding: Dict[str, Any], column: str, leaf: str, policy: DetectorPolicy) -> bool:
        detector = finding["detector"]
        if self.suppressed is not None and column and (self.suppressed(detector, column) or self.suppressed(detector, leaf)):
            return True
        if policy.negative_fields and leaf and not finding.get("field_hint"):
            if policy.vetoed_by_field(" ".join(tokenize_field_name(leaf))):
                return True
        if self._allowed(str(finding.get("value", ""))):
            return True
        return False

    def _unit_hinted(self, detector: str) -> bool:
        """
        True when the unit's name names the entity (table `credit_cards`, collection
        `passports`, object `ssn_export.csv`): Macie's keyword-in-the-path rule. Only
        the detector's field-hint patterns count - context words are too generic
        for a table name.
        """
        if not self.unit_tokens:
            return False
        hinted = self._unit_hints.get(detector)
        if hinted is None:
            # plural-tolerant: 'credit_cards' hints like 'credit_card', 'passports' like 'passport'
            names = [" ".join(self.unit_tokens), " ".join(_singular(t) for t in self.unit_tokens)]
            hinted = any(field_hints(detector, name) for name in names)
            if not hinted:
                try:
                    from src.engine.recognizers import get_rule
                    rule = get_rule(detector)
                except Exception:
                    rule = None
                if rule is not None and rule._field_hint_re is not None:
                    hinted = any(rule._field_hint_re.search(name) for name in names)
            self._unit_hints[detector] = bool(hinted)
        return bool(hinted)

    def _apply_unit_hint(self, finding: Dict[str, Any]) -> None:
        if finding["confidence"] == CANDIDATE_TIER and self._unit_hinted(finding["detector"]):
            finding["confidence"] = "likely"
            finding["evidence"].append(f"unit:{self.unit_name}")

    @staticmethod
    def _apply_context_policy(finding: Dict[str, Any], policy: DetectorPolicy) -> None:
        """A required-context detector without validation or context is `possible`, whatever its score."""
        if policy.context != CONTEXT_REQUIRED or finding["confidence"] == CANDIDATE_TIER:
            return
        evidence = finding.get("evidence", [])
        if has_context(evidence) or has_validation(evidence):
            return
        finding["confidence"] = CANDIDATE_TIER
        finding.setdefault("evidence", []).append("uncorroborated")

    def _format(self, finding: Dict[str, Any], location: str) -> Dict[str, Any]:
        out = {
            "resource_id": self.resource_id,
            "detector": finding["detector"],
            "category": finding["category"],
            "severity": finding["severity"],
            "value": finding["value"],
            "location": location,
            "confidence": finding["confidence"],
            "evidence": list(finding.get("evidence", [])),
        }
        for key in _PASSTHROUGH_KEYS:
            if key in finding:
                out[key] = finding[key]
        return out

    def _feed_record(self, record: Record) -> None:
        self.records_seen += 1
        hits: List[Tuple[Cell, Dict[str, Any], DetectorPolicy]] = []
        identity: Set[str] = set()
        for cell in record.cells:
            if not cell.value:
                continue
            column = cell.column
            self.values_seen[column] += 1
            for f in self._candidates(cell.value, cell.field):
                policy = policy_for(f["detector"], f["category"])
                if self._vetoed(f, column, cell.leaf, policy):
                    continue
                self._apply_context_policy(f, policy)
                self._apply_unit_hint(f)
                hits.append((cell, f, policy))
                if policy.identity and at_least(f["confidence"], "likely"):
                    identity.add(f["detector"])
        self.candidates += len(hits)
        if len(identity) >= 2:
            for cell, f, policy in hits:
                if policy.identity_corroboration and f["confidence"] == CANDIDATE_TIER and f["detector"] not in identity:
                    f["confidence"] = "likely"
                    f["evidence"].append("record:identity")
        new_pair = False
        for cell, f, policy in hits:
            key = (cell.column, f["detector"])
            profile = self.profiles.get(key)
            if profile is None:
                profile = ColumnProfile(cell.column, f["detector"], f["category"], f["severity"])
                self.profiles[key] = profile
                new_pair = True
            profile.add(f, self._format(f, cell.location))
        self.settle.observe(self.records_seen, new_pair)

    def _feed_blob(self, blob: TextBlob) -> None:
        self.blobs_seen += 1
        leaf = blob.field or ""
        for f in self._candidates(blob.text, blob.field):
            policy = policy_for(f["detector"], f["category"])
            if self._vetoed(f, leaf, leaf, policy):
                continue
            self._apply_context_policy(f, policy)
            self._apply_unit_hint(f)
            self.candidates += 1
            formatted = self._format(f, blob.location_for(f["start"], f["end"]))
            self.text_hits.setdefault(f["detector"], []).append(formatted)

    # ------------------------------------------------------------------ sampling
    def _ratio_pairs(self) -> List[Tuple[float, float]]:
        pairs = []
        for (column, detector), profile in self.profiles.items():
            sampled = self.values_seen.get(column, 0)
            if not sampled:
                continue
            policy = policy_for(detector, profile.category)
            threshold = policy.column_ratio if self.column_ratio is None else float(self.column_ratio)
            pairs.append((profile.matches / sampled, threshold))
        return pairs

    @property
    def settled(self) -> bool:
        return self.settle.settled(self.records_seen, self._ratio_pairs())

    # ------------------------------------------------------------------ verdicts
    def _promote_by_count(self, items: List[Dict[str, Any]], policy: DetectorPolicy) -> None:
        """
        `possible` hits that did not classify a column are promoted to `likely`
        when the unit holds min_count distinct ones - Orca's "file containing
        many nine-digit numbers", Purview's "low confidence patterns with counts
        of 20 or more". Below that they stay `possible` and the reporting tier
        decides. Self-identifying detectors are never counted.
        """
        possible = [it for it in items if it["confidence"] == CANDIDATE_TIER]
        if not possible or policy.context == CONTEXT_NONE or not policy.count_promotion:
            return
        needed = int(self.min_count) if self.min_count is not None else policy.min_count
        distinct = len({it["value"] for it in possible})
        if distinct >= needed:
            for it in possible:
                it["confidence"] = "likely"
                it["evidence"].append(f"count:{distinct}")

    def _siblings_of(self, column: str, policy: DetectorPolicy, tokens_by_column: Dict[str, str]) -> List[str]:
        """Other columns of the unit whose names corroborate the detector (Sentra: expiry and CVV next to a card column)."""
        if policy.siblings is None:
            return []
        return [other for other, tokens in tokens_by_column.items() if other != column and policy.has_sibling(tokens)]

    def _finish_columns(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        tokens_by_column = {col: " ".join(tokenize_field_name(col)) for col in self.values_seen}
        verdicts: Dict[Tuple[str, str], Any] = {}
        for (column, detector), profile in self.profiles.items():
            policy = policy_for(detector, profile.category)
            verdicts[(column, detector)] = column_verdict(
                profile, self.values_seen.get(column, 0), policy,
                ratio_threshold=None if self.column_ratio is None else float(self.column_ratio),
                min_matches=None if self.column_min_matches is None else int(self.column_min_matches),
            )
        # Column exclusivity (Google SDP "exclude if another infoType matched"): once a column
        # is classified, the detector with the densest - then best validated - verdict owns it.
        # Other detectors' hits in that column are coincidences unless they bring their own
        # statistical proof (validated on at least 20% of the sampled values) or are secrets.
        owner: Dict[str, str] = {}

        def strength(column: str, detector: str) -> tuple:
            # validated on most of the column beats a denser shape-only match (a 13-digit prefix
            # of a French NIR is also a "Pakistani CNIC" by shape, never by checksum)
            profile = self.profiles[(column, detector)]
            sampled = self.values_seen.get(column, 0) or 1
            verdict = verdicts[(column, detector)]
            return (profile.validated / sampled >= 0.5, verdict.ratio, profile.validated)

        for (column, detector), verdict in verdicts.items():
            if verdict is None:
                continue
            current = owner.get(column)
            if current is None or strength(column, detector) > strength(column, current):
                owner[column] = detector
        for (column, detector), profile in self.profiles.items():
            policy = policy_for(detector, profile.category)
            sampled = self.values_seen.get(column, 0)
            verdict = verdicts[(column, detector)]
            items = list(profile.items)
            if owner.get(column) not in (None, detector):
                own_proof = sampled and profile.validated / sampled >= STRAGGLER_MIN_VALIDATED_RATIO
                if profile.category not in _EXCLUSIVITY_EXEMPT_CATEGORIES and not own_proof:
                    continue
                items = [it for it in items if it["confidence"] == "very_likely"]
                if not items:
                    continue
            siblings = self._siblings_of(column, policy, tokens_by_column)
            sibling_tag = f"siblings:{','.join(sorted(siblings)[:3])}" if siblings else None
            if verdict is not None:
                if siblings:
                    verdict = dataclasses.replace(verdict, tier=promote(verdict.tier))
                tag = f"column:{verdict.ratio:.2f}"
                for it in items:
                    if rank(it["confidence"]) < rank(verdict.tier):
                        it["confidence"] = verdict.tier
                    it["evidence"].append(tag)
                    if sibling_tag:
                        it["evidence"].append(sibling_tag)
            else:
                if siblings:
                    for it in items:
                        if it["confidence"] == CANDIDATE_TIER:
                            it["confidence"] = "likely"
                        it["evidence"].append(sibling_tag)
                self._promote_by_count(items, policy)
            items = [it for it in items if at_least(it["confidence"], self.min_confidence)]
            if not items:
                continue
            if self.aggregation_threshold and len(items) >= self.aggregation_threshold:
                first = items[0]
                location = self.location_fn(column, len(items)) if self.location_fn else f"Column '{column}' ({len(items)} matches)"
                aggregated = dict(first)
                aggregated.update({
                    "location": location,
                    "confidence": max_tier(it["confidence"] for it in items),
                    "evidence": _merge_evidence(items),
                    "aggregated": True,
                    "occurrences": len(items),
                    "column": column,
                    "column_sampled": sampled,
                    "column_matches": profile.matches,
                    "column_ratio": round(profile.matches / sampled, 3) if sampled else None,
                })
                out.append(aggregated)
            else:
                out.extend(items)
        return out

    def _finish_text(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for detector, items in self.text_hits.items():
            policy = policy_for(detector, items[0]["category"])
            self._promote_by_count(items, policy)
            out.extend(it for it in items if at_least(it["confidence"], self.min_confidence))
        return out

    def finish(self) -> List[Dict[str, Any]]:
        return dedup(self._finish_columns() + self._finish_text())
