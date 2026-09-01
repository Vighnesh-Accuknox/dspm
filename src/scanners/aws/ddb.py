from typing import Any, Dict, Iterator, List

import boto3
from boto3.dynamodb.types import TypeDeserializer

from src.pipeline.records import Record, document_record
from src.scanners.base import BaseScanner
from src.utils.logger import get_logger

logger = get_logger(__name__)


class DynamoDBScanner(BaseScanner):
    """
    Scans DynamoDB tables for sensitive data. Items are streamed as Records
    (attribute paths as context) into the classification pipeline. Supports
    full baseline scanning and event-driven incremental CDC scanning via
    DynamoDB Streams.
    """

    def __init__(self, engine, config: Dict[str, Any] = None):
        super().__init__(engine, config)
        self.deserializer = TypeDeserializer()
        self.stats = {"tables_scanned": 0, "items_scanned": 0, "errors": 0}

    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Target structure:
        {
            "table_name": "my-dynamodb-table",
            "region": "us-east-1",
            "sample_limit": 10000  # limit number of items to scan
        }
        """
        table_name = target["table_name"]
        region = target.get("region")

        resource_id = f"arn:aws:dynamodb:{region or 'us-east-1'}:table/{table_name}"
        logger.info(f"Starting DynamoDB scan for {resource_id}")

        limit = target.get("sample_limit", 10000)
        try:
            ddb_client = (
                boto3.client("dynamodb", region_name=region)
                if region
                else boto3.client("dynamodb")
            )
            paginator = ddb_client.get_paginator("scan")
        except Exception as e:
            self.record_error(f"{resource_id}: {str(e)[:200]}")
            logger.error(f"Error scanning DynamoDB table {resource_id}: {str(e)}")
            return []

        if self.config.get("log_queries"):
            logger.info(f"Executing DynamoDB Scan on table '{table_name}' (sample_limit {limit})")

        def items() -> Iterator[Record]:
            items_scanned = 0
            try:
                for page in paginator.paginate(TableName=table_name):
                    if items_scanned >= limit:
                        break
                    page_items = page.get("Items", [])
                    for item_idx, raw_item in enumerate(page_items):
                        item = self._deserialize_item(raw_item)
                        # Track location using primary keys if possible, or index
                        base = f"Item index {items_scanned + item_idx} (Keys: {self._get_primary_key_info(item)})"
                        yield document_record(item, lambda path, b=base: f"{b}, Field '{path}'")
                    items_scanned += len(page_items)
            finally:
                self.stats["items_scanned"] += items_scanned

        errors_before = self.stats["errors"]
        findings = self.classify(
            resource_id, items(), location_fn=lambda field, n: f"Attribute '{field}' ({n} matches)", unit_name=table_name,
        )
        if self.stats["errors"] == errors_before:
            self.stats["tables_scanned"] += 1
        return findings

    def scan_stream_records(
        self,
        records: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Scans change data capture (CDC) stream records, one classification
        unit per source table.
        """
        per_table: Dict[str, List[Record]] = {}
        for record in records:
            event_name = record.get("eventName")  # INSERT, MODIFY, REMOVE
            if event_name == "REMOVE":
                continue  # skip deletions

            dynamodb_data = record.get("dynamodb", {})
            raw_image = dynamodb_data.get("NewImage")
            if not raw_image:
                continue

            table_arn = record.get("eventSourceARN", "unknown-table")
            # Remove stream suffix if present
            table_resource_id = (
                table_arn.split("/stream/")[0] if "/stream/" in table_arn else table_arn
            )

            item = self._deserialize_item(raw_image)
            pk_info = self._get_primary_key_info(
                self._deserialize_item(dynamodb_data.get("Keys", {})),
            )
            base = f"CDC Event {event_name} (Keys: {pk_info})"
            per_table.setdefault(table_resource_id, []).append(
                document_record(item, lambda path, b=base: f"{b}, Field '{path}'"),
            )

        findings: List[Dict[str, Any]] = []
        for table_resource_id, table_records in per_table.items():
            findings.extend(
                self.classify(
                    table_resource_id, table_records,
                    location_fn=lambda field, n: f"Attribute '{field}' ({n} matches)",
                    unit_name=table_resource_id.rsplit("/", 1)[-1],
                ),
            )
        return findings

    def _deserialize_item(self, raw_item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Converts DynamoDB types (e.g. {'S': 'val'}) into standard Python types.
        """
        deserialized = {}
        for key, val in raw_item.items():
            try:
                deserialized[key] = self.deserializer.deserialize(val)
            except Exception:
                deserialized[key] = val  # fallback if deserialization fails
        return deserialized

    def _get_primary_key_info(self, item: Dict[str, Any]) -> str:
        # A simple helper to summarize first few keys for tracking
        keys_str = []
        for k, v in list(item.items())[:3]:
            keys_str.append(f"{k}={v}")
        return ", ".join(keys_str)
