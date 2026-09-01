"""Static data shipped with the engine (IANA TLD list)."""
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
