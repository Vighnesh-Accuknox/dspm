import bz2
import gzip
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List

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

import boto3

from src.scanners.base import BaseScanner
from src.utils.logger import get_logger

logger = get_logger(__name__)


class S3Scanner(BaseScanner):
    """
    Scans S3 objects for sensitive data. Downloads objects to temporary disk
    to prevent memory overflow, then dispatches to type-specific chunked parsers.
    """

    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Target structure:
        {
            "bucket": "my-bucket",
            "key": "path/to/object.csv",
            "version_id": "optional-version",
            "last_modified": "optional-timestamp"
        }
        """
        bucket = target["bucket"]
        key = target["key"]
        version_id = target.get("version_id")

        resource_id = f"arn:aws:s3:::{bucket}/{key}"
        logger.info(f"Starting S3 scan for {resource_id}")

        s3_client = self.client or boto3.client("s3")

        # Incremental check if configuration specifies last scan time
        if "last_scan_time" in self.config and target.get("last_modified"):
            last_scan = self.config["last_scan_time"]
            if target["last_modified"] <= last_scan:
                logger.info(
                    f"Skipping S3 scan for {resource_id} (not modified since {last_scan})",
                )
                return []

        # Download to a temporary file
        temp_dir = tempfile.mkdtemp()
        temp_file_path = os.path.join(temp_dir, os.path.basename(key) or "object.tmp")

        try:
            download_kwargs = {"Bucket": bucket, "Key": key}
            if version_id:
                download_kwargs["VersionId"] = version_id

            s3_client.download_file(bucket, key, temp_file_path)

            # Scan local file path
            findings = self._scan_local_file(temp_file_path, resource_id)
            return findings

        except Exception as e:
            logger.error(f"Error scanning S3 object {resource_id}: {str(e)}")
            return []
        finally:
            # Clean up temp files and directories
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass

    def _scan_local_file(self, file_path: str, resource_id: str):
        findings = []
        ext = os.path.splitext(file_path)[1].lower()

        # Handle archives first
        if ext in [".zip", ".tar", ".gz", ".tgz", ".bz2"]:
            findings.extend(self._parse_archive(file_path, ext, resource_id))
            return findings

        # Dispatch based on extension
        if ext in [".csv", ".tsv"]:
            findings.extend(self._parse_csv_tsv(file_path, ext, resource_id))
        elif ext == ".parquet":
            findings.extend(self._parse_parquet(file_path, resource_id))
        elif ext in [".xls", ".xlsx"]:
            findings.extend(self._parse_excel(file_path, resource_id))
        elif ext == ".json":
            findings.extend(self._parse_json(file_path, resource_id))
        elif ext == ".xml":
            findings.extend(self._parse_xml(file_path, resource_id))
        elif ext in [".pdf"]:
            findings.extend(self._parse_pdf(file_path, resource_id))
        elif ext in [".doc", ".docx"]:
            findings.extend(self._parse_docx(file_path, resource_id))
        elif ext in [".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff"]:
            findings.extend(self._parse_image_ocr(file_path, resource_id))
        else:
            # Fallback for structured text-based / credentials files
            findings.extend(self._parse_text_fallback(file_path, resource_id))

        # Deduplicate findings
        seen = set()
        deduped = []
        for f in findings:
            sig = (
                f.get("resource_id"),
                f.get("detector"),
                f.get("value"),
                f.get("location"),
            )
            if sig not in seen:
                seen.add(sig)
                deduped.append(f)

        return deduped

    # Parser Implementations

    def _parse_csv_tsv(
        self,
        file_path: str,
        ext: str,
        resource_id: str,
    ) -> List[Dict[str, Any]]:
        findings = []
        if not pd:
            logger.warning("Pandas is not installed. Skipping CSV/TSV scan.")
            return findings

        sep = "\t" if ext == ".tsv" else ","
        try:
            # Streaming chunks of CSV
            for chunk_idx, chunk in enumerate(
                pd.read_csv(
                    file_path,
                    sep=sep,
                    chunksize=5000,
                    on_bad_lines="skip",
                    dtype=str,
                ),
            ):
                # Convert the chunk into rows and scan each column
                for col in chunk.columns:
                    for row_idx, val in enumerate(chunk[col]):
                        if pd.isna(val) or not isinstance(val, str):
                            continue
                        cell_findings = self.engine.scan_text(val)
                        for f in cell_findings:
                            location = f"Chunk {chunk_idx}, Row {chunk_idx * 5000 + row_idx}, Column '{col}'"
                            findings.append(
                                self.format_finding(
                                    f["detector"],
                                    f["category"],
                                    f["severity"],
                                    f["value"],
                                    resource_id,
                                    location,
                                ),
                            )
        except Exception as e:
            logger.error(f"Error parsing CSV/TSV {resource_id}: {str(e)}")
        return findings

    def _parse_parquet(self, file_path: str, resource_id: str) -> List[Dict[str, Any]]:
        findings = []
        if not pq or not pd:
            logger.warning("PyArrow/Pandas is not installed. Skipping Parquet scan.")
            return findings

        try:
            parquet_file = pq.ParquetFile(file_path)
            for batch_idx, batch in enumerate(
                parquet_file.iter_batches(batch_size=5000),
            ):
                df = batch.to_pandas()
                for col in df.columns:
                    for row_idx, val in enumerate(df[col]):
                        if pd.isna(val) or not isinstance(val, str):
                            continue
                        cell_findings = self.engine.scan_text(val)
                        for f in cell_findings:
                            location = f"Batch {batch_idx}, Row {batch_idx * 5000 + row_idx}, Column '{col}'"
                            findings.append(
                                self.format_finding(
                                    f["detector"],
                                    f["category"],
                                    f["severity"],
                                    f["value"],
                                    resource_id,
                                    location,
                                ),
                            )
        except Exception as e:
            logger.error(f"Error parsing Parquet {resource_id}: {str(e)}")
        return findings

    def _parse_excel(self, file_path: str, resource_id: str) -> List[Dict[str, Any]]:
        findings = []
        if not pd:
            logger.warning("Pandas is not installed. Skipping Excel scan.")
            return findings

        try:
            excel_file = pd.ExcelFile(file_path)
            for sheet_name in excel_file.sheet_names:
                df = excel_file.parse(sheet_name, dtype=str)
                for col in df.columns:
                    for row_idx, val in enumerate(df[col]):
                        if pd.isna(val) or not isinstance(val, str):
                            continue
                        cell_findings = self.engine.scan_text(val)
                        for f in cell_findings:
                            location = (
                                f"Sheet '{sheet_name}', Row {row_idx}, Column '{col}'"
                            )
                            findings.append(
                                self.format_finding(
                                    f["detector"],
                                    f["category"],
                                    f["severity"],
                                    f["value"],
                                    resource_id,
                                    location,
                                ),
                            )
        except Exception as e:
            logger.error(f"Error parsing Excel {resource_id}: {str(e)}")
        return findings

    def _parse_json(self, file_path: str, resource_id: str) -> List[Dict[str, Any]]:
        findings = []
        # Support streaming JSON via ijson if available
        if ijson:
            try:
                with open(file_path, "rb") as f:
                    # Scan elements streamingly
                    parser = ijson.parse(f)
                    for prefix, event, value in parser:
                        if event == "string" and value:
                            cell_findings = self.engine.scan_text(value)
                            for f_item in cell_findings:
                                location = f"JSON Path '{prefix}'"
                                findings.append(
                                    self.format_finding(
                                        f_item["detector"],
                                        f_item["category"],
                                        f_item["severity"],
                                        f_item["value"],
                                        resource_id,
                                        location,
                                    ),
                                )
                return findings
            except Exception as e:
                logger.warning(
                    f"ijson parsing failed for {resource_id}, falling back to text scan: {str(e)}",
                )

        # Fallback to line by line or full file reading
        return self._parse_text_fallback(file_path, resource_id)

    def _parse_xml(self, file_path: str, resource_id: str) -> List[Dict[str, Any]]:
        findings = []
        if etree:
            try:
                # Streaming XML
                context = etree.iterparse(file_path, events=("end",))
                for event, elem in context:
                    if elem.text and elem.text.strip():
                        cell_findings = self.engine.scan_text(elem.text.strip())
                        for f in cell_findings:
                            location = f"XML Element '{elem.tag}'"
                            findings.append(
                                self.format_finding(
                                    f["detector"],
                                    f["category"],
                                    f["severity"],
                                    f["value"],
                                    resource_id,
                                    location,
                                ),
                            )
                    elem.clear()
                return findings
            except Exception as e:
                logger.warning(
                    f"etree parsing failed for {resource_id}, falling back to text scan: {str(e)}",
                )

        return self._parse_text_fallback(file_path, resource_id)

    def _parse_pdf(self, file_path: str, resource_id: str) -> List[Dict[str, Any]]:
        findings = []
        if not PdfReader:
            logger.warning("pypdf is not installed. Skipping PDF scan.")
            return findings

        try:
            reader = PdfReader(file_path)
            for idx, page in enumerate(reader.pages):
                text = page.extract_text()
                if text:
                    page_findings = self.engine.scan_text(text)
                    for f in page_findings:
                        location = f"PDF Page {idx + 1}"
                        findings.append(
                            self.format_finding(
                                f["detector"],
                                f["category"],
                                f["severity"],
                                f["value"],
                                resource_id,
                                location,
                            ),
                        )
        except Exception as e:
            logger.error(f"Error parsing PDF {resource_id}: {str(e)}")
        return findings

    def _parse_docx(self, file_path: str, resource_id: str) -> List[Dict[str, Any]]:
        findings = []
        if not docx:
            logger.warning("python-docx is not installed. Skipping Word document scan.")
            return findings

        try:
            doc = docx.Document(file_path)
            for idx, paragraph in enumerate(doc.paragraphs):
                if paragraph.text:
                    p_findings = self.engine.scan_text(paragraph.text)
                    for f in p_findings:
                        location = f"Paragraph {idx + 1}"
                        findings.append(
                            self.format_finding(
                                f["detector"],
                                f["category"],
                                f["severity"],
                                f["value"],
                                resource_id,
                                location,
                            ),
                        )
        except Exception as e:
            logger.error(f"Error parsing DOCX {resource_id}: {str(e)}")
        return findings

    def _parse_image_ocr(
        self,
        file_path: str,
        resource_id: str,
    ) -> List[Dict[str, Any]]:
        findings = []
        if not pytesseract or not Image:
            logger.warning(
                "pytesseract/Pillow is not installed. Skipping Image OCR scan.",
            )
            return findings

        try:
            with Image.open(file_path) as img:
                text = pytesseract.image_to_string(img)
                if text:
                    img_findings = self.engine.scan_text(text)
                    for f in img_findings:
                        location = "Image OCR Text"
                        findings.append(
                            self.format_finding(
                                f["detector"],
                                f["category"],
                                f["severity"],
                                f["value"],
                                resource_id,
                                location,
                            ),
                        )
        except Exception as e:
            logger.error(f"Error parsing image OCR {resource_id}: {str(e)}")
        return findings

    def _parse_text_fallback(
        self,
        file_path: str,
        resource_id: str,
    ) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                block_lines = []
                line_offset = 1
                for idx, line in enumerate(f):
                    block_lines.append(line)
                    if len(block_lines) >= 1000:
                        block_text = "".join(block_lines)
                        block_findings = self.engine.scan_text(block_text)
                        for f_item in block_findings:
                            start = f_item.get("start", 0)
                            end = f_item.get("end", 0)
                            text_before = block_text[:start]
                            line_num = line_offset + text_before.count("\n")
                            last_nl = text_before.rfind("\n")
                            col_num = start + 1 if last_nl == -1 else start - last_nl
                            location = f"Line {line_num}, Column {col_num}-{col_num + (end - start)}"
                            findings.append(
                                self.format_finding(
                                    f_item["detector"],
                                    f_item["category"],
                                    f_item["severity"],
                                    f_item["value"],
                                    resource_id,
                                    location,
                                ),
                            )
                        line_offset += len(block_lines)
                        block_lines = []

                # Scan remaining lines
                if block_lines:
                    block_text = "".join(block_lines)
                    block_findings = self.engine.scan_text(block_text)
                    for f_item in block_findings:
                        start = f_item.get("start", 0)
                        end = f_item.get("end", 0)
                        text_before = block_text[:start]
                        line_num = line_offset + text_before.count("\n")
                        last_nl = text_before.rfind("\n")
                        col_num = start + 1 if last_nl == -1 else start - last_nl
                        location = f"Line {line_num}, Column {col_num}-{col_num + (end - start)}"
                        findings.append(
                            self.format_finding(
                                f_item["detector"],
                                f_item["category"],
                                f_item["severity"],
                                f_item["value"],
                                resource_id,
                                location,
                            ),
                        )
        except Exception as e:
            logger.error(f"Error scanning fallback text file {resource_id}: {str(e)}")
        return findings

    def _parse_archive(
        self,
        file_path: str,
        ext: str,
        resource_id: str,
    ) -> List[Dict[str, Any]]:
        findings = []
        extract_dir = tempfile.mkdtemp()

        try:
            if ext == ".zip":
                with zipfile.ZipFile(file_path, "r") as z:
                    z.extractall(extract_dir)
            elif ext in [".tar", ".tgz"]:
                with tarfile.open(file_path, "r:*") as t:
                    t.extractall(extract_dir)
            elif ext == ".gz":
                out_path = os.path.join(extract_dir, os.path.basename(file_path)[:-3])
                with gzip.open(file_path, "rb") as f_in:
                    with open(out_path, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
            elif ext == ".bz2":
                out_path = os.path.join(extract_dir, os.path.basename(file_path)[:-4])
                with bz2.open(file_path, "rb") as f_in:
                    with open(out_path, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)

            # Traverse extract_dir recursively
            for root, _, files in os.walk(extract_dir):
                for f in files:
                    full_p = os.path.join(root, f)
                    rel_p = os.path.relpath(full_p, extract_dir)
                    sub_resource_id = f"{resource_id}#{rel_p}"
                    findings.extend(self._scan_local_file(full_p, sub_resource_id))

        except Exception as e:
            logger.error(f"Error handling archive {resource_id}: {str(e)}")
        finally:
            try:
                shutil.rmtree(extract_dir)
            except Exception:
                pass

        return findings

    def list_all_files(self, bucket: str):
        paginator = self.client.get_paginator("list_objects_v2")

        files = []

        for page in paginator.paginate(Bucket=bucket):
            files.extend(page.get("Contents", []))

        return files
