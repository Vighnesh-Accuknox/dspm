"""
Country-specific and generic pattern recognizers, expressed as
src.engine.rules.Rule objects and grouped by region pack in sibling modules.
Patterns, context words and validators derive from the MIT-licensed
Microsoft Presidio analyzer (https://github.com/microsoft/presidio and the
data-privacy-stack fork); this attribution line is required by that license.
Loading is lazy so one broken module never takes the others down at import
time; load_all() raises loudly.
"""
import importlib
from typing import Dict, List, Optional

from src.engine.rules import Rule

MODULES = (
    "us_ca",
    "gb_es_it_tr",
    "de_se_fi_pl",
    "in_sg_au_kr_th",
    "za_ng_ph_generic",
    "europe_extra",
    "americas",
    "asia_pacific",
    "middle_east_africa",
    "identifiers",
)

_ALL: Optional[List[Rule]] = None
_BY_NAME: Dict[str, Rule] = {}


def load_all() -> List[Rule]:
    """Imports every rule module once and returns the combined rule list."""
    global _ALL
    if _ALL is None:
        rules: List[Rule] = []
        for mod_name in MODULES:
            module = importlib.import_module(f"src.engine.recognizers.{mod_name}")
            rules.extend(module.RULES)
        by_name: Dict[str, Rule] = {}
        for rule in rules:
            if rule.name in by_name:
                raise ValueError(f"Duplicate upstream rule name: {rule.name}")
            by_name[rule.name] = rule
        _BY_NAME.update(by_name)
        _ALL = rules
    return _ALL


def get_rule(name: str) -> Optional[Rule]:
    load_all()
    return _BY_NAME.get(name)


def rule_names() -> List[str]:
    return [r.name for r in load_all()]


def regions() -> List[str]:
    return sorted({r.region for r in load_all() if r.region})
