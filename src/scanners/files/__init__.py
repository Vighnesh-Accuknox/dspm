"""File-format parsers shared by every file-based connector (S3 today; any object store or file share tomorrow)."""
from src.scanners.files.parsers import ARCHIVE_EXTENSIONS, iter_units

__all__ = ["ARCHIVE_EXTENSIONS", "iter_units"]
