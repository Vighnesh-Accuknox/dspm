"""
File parsers: turn a local file into units of Records / TextBlobs.

    iter_units(path, resource_id, config) -> (unit_resource_id, item stream) ...

One file is usually one unit; workbooks yield one unit per sheet and archives
one per member (recursively, with nesting and decompression-size guards).
Columnar formats (CSV/TSV, Excel, Parquet) yield one Record per row so the
pipeline can use the column name as context and judge whole columns;
record formats (JSON, JSON Lines, XML) yield one Record per document with
dotted field paths; documents (PDF, Word, images via OCR) and everything else
yield TextBlobs. A connector for any object store only has to download the
object and call iter_units().

Streams are lazy: consume each unit's stream before advancing to the next
unit (a plain `for unit_id, stream in iter_units(...)` loop does). Archive
members live in a temporary directory that is removed once the archive
generator is exhausted.
"""
import bz2
import gzip
import json
import os
import shutil
import tarfile
import tempfile
import zipfile
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

# Conditional imports for soft failures
try:
    import pandas as pd
except ImportError:
    pd = None

try:
    import fastparquet as pq
except ImportError:
    pq = None

try:
    import ijson
except ImportError:
    ijson = None

try:
    from lxml import etree
except ImportError:
    etree = None

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

try:
    import docx
except ImportError:
    docx = None

try:
    import pytesseract
    from PIL import Image
except ImportError:
    pytesseract = None
    Image = None

from src.pipeline.records import COLUMNAR, RECORD, Cell, Record, TextBlob, collapse_indices, document_record
from src.utils.logger import get_logger

logger = get_logger(__name__)

ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".bz2"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff"}
CHUNK_ROWS = 5000
TEXT_BLOCK_LINES = 1000

ItemStream = Iterator[Any]
Unit = Tuple[str, ItemStream]


def iter_units(file_path: str, resource_id: str, config: Optional[Dict[str, Any]] = None, depth: int = 0) -> Iterator[Unit]:
    """Yields (unit_resource_id, item_stream) for a local file; see module docstring."""
    config = config or {}
    ext = os.path.splitext(file_path)[1].lower()
    if ext in ARCHIVE_EXTENSIONS:
        yield from _iter_archive_units(file_path, ext, resource_id, config, depth)
    elif ext in (".csv", ".tsv"):
        yield resource_id, iter_csv(file_path, ext)
    elif ext == ".parquet":
        yield resource_id, iter_parquet(file_path)
    elif ext in (".xls", ".xlsx"):
        yield from iter_excel_sheets(file_path, resource_id)
    elif ext == ".json":
        yield resource_id, iter_json(file_path)
    elif ext in (".jsonl", ".ndjson"):
        yield resource_id, iter_jsonl(file_path)
    elif ext == ".xml":
        yield resource_id, iter_xml(file_path)
    elif ext == ".pdf":
        yield resource_id, iter_pdf(file_path)
    elif ext in (".doc", ".docx"):
        yield resource_id, iter_docx(file_path)
    elif ext in IMAGE_EXTENSIONS:
        yield resource_id, iter_image_ocr(file_path)
    else:
        yield resource_id, iter_text(file_path)


# --------------------------------------------------------------------------- columnar

def _frame_records(frame: Any, location_fn: Callable[[int, str], str]) -> Iterator[Record]:
    """One Record per row of a DataFrame-like object (columns + per-column iteration)."""
    columns = [str(c) for c in frame.columns]
    series = [list(frame[c]) for c in frame.columns]
    for row_idx, row in enumerate(zip(*series)):
        cells = []
        for col, val in zip(columns, row):
            if val is None or (pd is not None and pd.isna(val)) or not isinstance(val, str) or not val:
                continue
            cells.append(Cell(value=val, field=col, location=location_fn(row_idx, col)))
        if cells:
            yield Record(cells, shape=COLUMNAR)


def iter_csv(file_path: str, ext: str) -> Iterator[Record]:
    if not pd:
        logger.warning("Pandas is not installed. Skipping CSV/TSV scan.")
        return
    sep = "\t" if ext == ".tsv" else ","
    for chunk_idx, chunk in enumerate(pd.read_csv(file_path, sep=sep, chunksize=CHUNK_ROWS, on_bad_lines="skip", dtype=str)):
        base = chunk_idx * CHUNK_ROWS
        yield from _frame_records(chunk, lambda r, c, b=base, k=chunk_idx: f"Chunk {k}, Row {b + r}, Column '{c}'")


def iter_parquet(file_path: str) -> Iterator[Record]:
    if not pq or not pd:
        logger.warning("fastparquet/Pandas is not installed. Skipping Parquet scan.")
        return
    parquet_file = pq.ParquetFile(file_path)
    if hasattr(parquet_file, "iter_row_groups"):          # fastparquet: DataFrames per row group
        batches = parquet_file.iter_row_groups()
    else:                                                  # pyarrow-style API
        batches = (b.to_pandas() for b in parquet_file.iter_batches(batch_size=CHUNK_ROWS))
    offset = 0
    for batch_idx, frame in enumerate(batches):
        yield from _frame_records(frame, lambda r, c, b=offset, k=batch_idx: f"Batch {k}, Row {b + r}, Column '{c}'")
        offset += len(frame)


def iter_excel_sheets(file_path: str, resource_id: str) -> Iterator[Unit]:
    if not pd:
        logger.warning("Pandas is not installed. Skipping Excel scan.")
        return
    excel_file = pd.ExcelFile(file_path)
    for sheet_name in excel_file.sheet_names:
        frame = excel_file.parse(sheet_name, dtype=str)
        yield (
            f"{resource_id} [{sheet_name}]",
            _frame_records(frame, lambda r, c, s=sheet_name: f"Sheet '{s}', Row {r}, Column '{c}'"),
        )


# --------------------------------------------------------------------------- record

def iter_json(file_path: str) -> Iterator[Record]:
    """
    A top-level array is streamed item by item (one Record per element so the
    pipeline sees whole documents); any other root is streamed value by value.
    Falls back to plain text when the file is not valid JSON.
    """
    if not ijson:
        yield from iter_text(file_path)
        return
    with open(file_path, "rb") as f:
        head = f.read(64).lstrip()
    try:
        if head.startswith(b"["):
            with open(file_path, "rb") as f:
                for idx, item in enumerate(ijson.items(f, "item")):
                    yield document_record(item, lambda path, i=idx: f"JSON Path 'item[{i}].{path}'" if path else f"JSON Path 'item[{i}]'")
        else:
            with open(file_path, "rb") as f:
                for prefix, event, value in ijson.parse(f):
                    if event == "string" and value:
                        field = prefix.replace(".item", "[]") or "$"
                        yield Record(
                            [Cell(value=value, field=prefix or "$", location=f"JSON Path '{prefix}'", key=collapse_indices(field))],
                            shape=RECORD,
                        )
    except Exception as e:
        logger.warning(f"ijson parsing failed for {file_path}, falling back to text scan: {str(e)}")
        yield from iter_text(file_path)


def iter_jsonl(file_path: str) -> Iterator[Record]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except ValueError:
                yield TextBlob(line, location=f"Line {line_no}")
                continue
            yield document_record(doc, lambda path, n=line_no: f"Line {n}, Path '{path}'")


def iter_xml(file_path: str) -> Iterator[Record]:
    if not etree:
        yield from iter_text(file_path)
        return
    try:
        # Streaming XML; entity resolution disabled against XXE/entity-expansion input
        context = etree.iterparse(file_path, events=("end",), resolve_entities=False)
        for _event, elem in context:
            if elem.text and elem.text.strip():
                tag = str(elem.tag)
                yield Record([Cell(value=elem.text.strip(), field=tag, location=f"XML Element '{tag}'")], shape=RECORD)
            elem.clear()
    except Exception as e:
        logger.warning(f"etree parsing failed for {file_path}, falling back to text scan: {str(e)}")
        yield from iter_text(file_path)


# --------------------------------------------------------------------------- unstructured

def iter_pdf(file_path: str) -> Iterator[TextBlob]:
    if not PdfReader:
        logger.warning("pypdf is not installed. Skipping PDF scan.")
        return
    reader = PdfReader(file_path)
    for idx, page in enumerate(reader.pages):
        text = page.extract_text()
        if text:
            yield TextBlob(text, location=f"PDF Page {idx + 1}")


def iter_docx(file_path: str) -> Iterator[TextBlob]:
    if not docx:
        logger.warning("python-docx is not installed. Skipping Word document scan.")
        return
    document = docx.Document(file_path)
    for idx, paragraph in enumerate(document.paragraphs):
        if paragraph.text:
            yield TextBlob(paragraph.text, location=f"Paragraph {idx + 1}")


def iter_image_ocr(file_path: str) -> Iterator[TextBlob]:
    if not pytesseract or not Image:
        logger.warning("pytesseract/Pillow is not installed. Skipping Image OCR scan.")
        return
    with Image.open(file_path) as img:
        text = pytesseract.image_to_string(img)
    if text:
        yield TextBlob(text, location="Image OCR Text")


def _text_locator(block_text: str, line_offset: int) -> Callable[[int, int], str]:
    def locate(start: int, end: int) -> str:
        text_before = block_text[:start]
        line_num = line_offset + text_before.count("\n")
        last_nl = text_before.rfind("\n")
        col_num = start + 1 if last_nl == -1 else start - last_nl
        return f"Line {line_num}, Column {col_num}-{col_num + (end - start)}"
    return locate


def iter_text(file_path: str) -> Iterator[TextBlob]:
    """Plain text in blocks of TEXT_BLOCK_LINES lines with line/column locations."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        block_lines: List[str] = []
        line_offset = 1
        for line in f:
            block_lines.append(line)
            if len(block_lines) >= TEXT_BLOCK_LINES:
                block_text = "".join(block_lines)
                yield TextBlob(block_text, location=f"Line {line_offset}", locate=_text_locator(block_text, line_offset))
                line_offset += len(block_lines)
                block_lines = []
        if block_lines:
            block_text = "".join(block_lines)
            yield TextBlob(block_text, location=f"Line {line_offset}", locate=_text_locator(block_text, line_offset))


# --------------------------------------------------------------------------- archives

def _capped_copy(f_in, out_path: str, max_bytes: int) -> bool:
    """Streams f_in to out_path, aborting if the decompressed size exceeds max_bytes."""
    copied = 0
    with open(out_path, "wb") as f_out:
        while True:
            chunk = f_in.read(1024 * 1024)
            if not chunk:
                return True
            copied += len(chunk)
            if copied > max_bytes:
                return False
            f_out.write(chunk)


def _iter_archive_units(file_path: str, ext: str, resource_id: str, config: Dict[str, Any], depth: int) -> Iterator[Unit]:
    # Guard against archive nesting bombs (zip-in-zip-in-zip...)
    max_depth = config.get("max_archive_depth", 3)
    if depth >= max_depth:
        logger.warning(f"Skipping archive {resource_id}: nesting depth exceeds {max_depth}")
        return
    # Guard against decompression bombs
    max_bytes = config.get("max_archive_extract_bytes", 1024 ** 3)
    extract_dir = tempfile.mkdtemp()
    try:
        if ext == ".zip":
            with zipfile.ZipFile(file_path, "r") as z:
                total_size = sum(i.file_size for i in z.infolist())
                if total_size > max_bytes:
                    logger.warning(f"Skipping archive {resource_id}: uncompressed size {total_size} exceeds {max_bytes}")
                    return
                z.extractall(extract_dir)
        elif ext in (".tar", ".tgz"):
            with tarfile.open(file_path, "r:*") as t:
                total_size = sum(m.size for m in t.getmembers())
                if total_size > max_bytes:
                    logger.warning(f"Skipping archive {resource_id}: uncompressed size {total_size} exceeds {max_bytes}")
                    return
                # 'data' filter blocks path traversal, symlinks and special files
                t.extractall(extract_dir, filter="data")
        elif ext == ".gz":
            out_path = os.path.join(extract_dir, os.path.basename(file_path)[:-3])
            with gzip.open(file_path, "rb") as f_in:
                if not _capped_copy(f_in, out_path, max_bytes):
                    logger.warning(f"Skipping archive {resource_id}: uncompressed size exceeds {max_bytes}")
                    return
        elif ext == ".bz2":
            out_path = os.path.join(extract_dir, os.path.basename(file_path)[:-4])
            with bz2.open(file_path, "rb") as f_in:
                if not _capped_copy(f_in, out_path, max_bytes):
                    logger.warning(f"Skipping archive {resource_id}: uncompressed size exceeds {max_bytes}")
                    return

        for root, _, files in os.walk(extract_dir):
            for name in files:
                full_path = os.path.join(root, name)
                rel_path = os.path.relpath(full_path, extract_dir)
                yield from iter_units(full_path, f"{resource_id}#{rel_path}", config, depth + 1)
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)
