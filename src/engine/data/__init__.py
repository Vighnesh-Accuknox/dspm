"""Static data shipped with the engine (IANA TLD list, given-name lexicon)."""
from functools import lru_cache
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=1)
def load_tlds() -> frozenset:
    """Upper-case IANA top-level domains (tlds.txt); empty set if the file is missing."""
    path = _DATA_DIR / "tlds.txt"
    if not path.exists():
        return frozenset()
    tlds = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            tlds.add(line.upper())
    return frozenset(tlds)


@lru_cache(maxsize=1)
def load_given_names() -> frozenset:
    """Lower-case given names (given_names.txt) used to accept names the NER model mislabels; empty set if missing."""
    path = _DATA_DIR / "given_names.txt"
    if not path.exists():
        return frozenset()
    return frozenset(line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#"))
