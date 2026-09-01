"""
What a connector emits.

Amazon Macie's keyword rules distinguish exactly three data shapes and so do we:

  columnar      rows under a header (CSV, TSV, Excel, Parquet, SQL rows): a value's
                context is its cell plus the column name
  record        documents with field paths (JSON, JSON Lines, Avro, MongoDB
                documents, DynamoDB items): context is the value plus every
                element of the path to it
  unstructured  free text (PDF pages, Word paragraphs, OCR output, plain text):
                context is the surrounding characters only

Structured shapes are emitted as Records made of Cells; unstructured text as
TextBlobs. The pipeline never sees a connection, a cursor or a file - only these.
"""
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, List, Optional, Tuple, Union

_INDEX_RE = re.compile(r"\[\d+\]")
_PATH_SPLIT_RE = re.compile(r"[.\[\]]+")

COLUMNAR = "columnar"
RECORD = "record"


@dataclass
class Cell:
    """
    One value with its structural context.

    value     the text to classify
    field     the name the engine sees as context: column name, dotted document
              path, JSON path, XML tag
    location  rendered, connector-specific location of this value ("Row 3, Column 'email'")
    key       aggregation / column-verdict key; defaults to field. Connectors with
              array paths pass the path with indices collapsed ("tags[].email")
    """

    value: str
    field: Optional[str] = None
    location: str = ""
    key: Optional[str] = None

    @property
    def column(self) -> str:
        return self.key if self.key is not None else (self.field or "")

    @property
    def leaf(self) -> str:
        """Last path element of the column key: 'profile.work_email' -> 'work_email'."""
        parts = [p for p in _PATH_SPLIT_RE.split(self.column) if p]
        return parts[-1] if parts else ""


@dataclass
class Record:
    """One row / document / item: its cells are each other's context."""

    cells: List[Cell]
    shape: str = COLUMNAR
    location: str = ""


@dataclass
class TextBlob:
    """
    Unstructured text. `locate(start, end)` renders the location of a span
    inside the text (line / column for text files); without it every finding
    in the blob shares `location`.
    """

    text: str
    location: str = ""
    field: Optional[str] = None
    locate: Optional[Callable[[int, int], str]] = None

    def location_for(self, start: int, end: int) -> str:
        if self.locate is not None:
            return self.locate(start, end)
        return self.location


Item = Union[Record, TextBlob]


def collapse_indices(path: str) -> str:
    """'orders[3].items[0].sku' -> 'orders[].items[].sku'."""
    return _INDEX_RE.sub("[]", path or "")


def flatten(node: Any, path: str = "", key: str = "") -> Iterator[Tuple[str, str, str]]:
    """
    Walks a document recursively, yielding (dotted_path, leaf_key, string_value)
    for every scalar leaf. Lists keep the field name of their parent key and
    add an index to the path; bytes are decoded; None is skipped.
    """
    if isinstance(node, dict):
        for k, v in node.items():
            child_path = f"{path}.{k}" if path else str(k)
            yield from flatten(v, child_path, str(k))
    elif isinstance(node, (list, tuple, set, frozenset)):
        for idx, item in enumerate(node):
            yield from flatten(item, f"{path}[{idx}]", key)
    elif node is None or isinstance(node, bool):
        return
    else:
        if isinstance(node, bytes):
            value = node.decode("utf-8", errors="ignore")
        else:
            value = str(node)
        if value:
            yield path, key, value


def document_record(
    doc: Any, location_fn: Callable[[str], str], shape: str = RECORD, field_prefix: str = "",
) -> Record:
    """
    Builds a Record from a document (dict / list / scalar). location_fn maps a
    dotted path to the rendered location of that leaf.
    """
    cells: List[Cell] = []
    for path, key, value in flatten(doc):
        full_path = f"{field_prefix}{path}" if field_prefix else path
        cells.append(
            Cell(
                value=value,
                field=full_path or key,
                location=location_fn(full_path),
                key=collapse_indices(full_path or key),
            ),
        )
    return Record(cells, shape=shape)
