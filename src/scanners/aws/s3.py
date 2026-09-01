import os
import shutil
import tempfile
from typing import Any, Dict, List

import boto3

from src.scanners.base import BaseScanner
from src.scanners.files import iter_units
from src.utils.logger import get_logger

logger = get_logger(__name__)


class S3Scanner(BaseScanner):
    """
    Scans S3 objects for sensitive data: downloads the object to temporary
    disk (never into memory), hands it to the shared file parsers
    (src/scanners/files) and classifies every unit they yield. An object store
    connector for another provider only needs a different download step.
    """

    def __init__(self, engine, config: Dict[str, Any] = None, client=None):
        super().__init__(engine, config, client)
        # Same shape as the DB scanners' stats so callers can surface failures uniformly
        self.stats = {"objects_scanned": 0, "errors": 0}

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
            if version_id:
                s3_client.download_file(
                    bucket,
                    key,
                    temp_file_path,
                    ExtraArgs={"VersionId": version_id},
                )
            else:
                s3_client.download_file(bucket, key, temp_file_path)

            findings = self.scan_local_file(temp_file_path, resource_id)
            self.stats["objects_scanned"] += 1
            return findings

        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Error scanning S3 object {resource_id}: {str(e)}")
            return []
        finally:
            # Clean up temp files and directories
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass

    def scan_local_file(self, file_path: str, resource_id: str) -> List[Dict[str, Any]]:
        """Classifies every unit (file, sheet, archive member) of a local file."""
        findings: List[Dict[str, Any]] = []
        for unit_resource_id, stream in iter_units(file_path, resource_id, self.config):
            findings.extend(
                self.classify(
                    unit_resource_id, stream,
                    location_fn=lambda column, n: f"Column '{column}' ({n} matches)",
                ),
            )
        return self.dedup_findings(findings)

    def list_all_files(self, bucket: str):
        paginator = self.client.get_paginator("list_objects_v2")

        files = []

        for page in paginator.paginate(Bucket=bucket):
            files.extend(page.get("Contents", []))

        return files
