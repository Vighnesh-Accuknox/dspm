from typing import Any, Dict, List

import boto3
from boto3.dynamodb.types import TypeDeserializer

from src.scanners.base import BaseScanner
from src.utils.logger import get_logger

logger = get_logger(__name__)


class DynamoDBScanner(BaseScanner):
    """
    Scans DynamoDB tables for sensitive data.
    Supports full baseline scanning and event-driven incremental CDC scanning via DynamoDB Streams.
    """

    def __init__(self, engine, config: Dict[str, Any] = None):
        super().__init__(engine, config)
        self.deserializer = TypeDeserializer()

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

        ddb_client = (
            boto3.client("dynamodb", region_name=region)
            if region
            else boto3.client("dynamodb")
        )
        findings = []

        try:
            paginator = ddb_client.get_paginator("scan")
            items_scanned = 0
            limit = target.get("sample_limit", 10000)

            # Paginate through table scan
            for page in paginator.paginate(TableName=table_name):
                if items_scanned >= limit:
                    break

                items = page.get("Items", [])
                for item_idx, raw_item in enumerate(items):
                    item = self._deserialize_item(raw_item)
                    item_findings = self._scan_deserialized_item(item)

                    # Track location using primary keys if possible, or index
                    pk_info = self._get_primary_key_info(item)
                    location = (
                        f"Item index {items_scanned + item_idx} (Keys: {pk_info})"
                    )

                    for f in item_findings:
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

                items_scanned += len(items)

        except Exception as e:
            logger.error(f"Error scanning DynamoDB table {resource_id}: {str(e)}")

        return findings

    def scan_stream_records(
        self,
        records: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Scans change data capture (CDC) stream records.
        """
        findings = []
        for idx, record in enumerate(records):
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
            item_findings = self._scan_deserialized_item(item)

            pk_info = self._get_primary_key_info(
                self._deserialize_item(dynamodb_data.get("Keys", {})),
            )
            location = f"CDC Event {event_name} (Keys: {pk_info})"

            for f in item_findings:
                findings.append(
                    self.format_finding(
                        f["detector"],
                        f["category"],
                        f["severity"],
                        f["value"],
                        table_resource_id,
                        location,
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

    def _scan_deserialized_item(self, item: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        for attr_name, value in item.items():
            # Scan attribute key name for potential secrets (e.g., password field name)
            findings.extend(self.engine.scan_text(attr_name))

            # Scan value
            if isinstance(value, str):
                findings.extend(self.engine.scan_text(value))
            elif isinstance(value, (dict, list)):
                findings.extend(self.engine.scan_text(str(value)))
        return findings

    def _get_primary_key_info(self, item: Dict[str, Any]) -> str:
        # A simple helper to summarize first few keys for tracking
        keys_str = []
        for k, v in list(item.items())[:3]:
            keys_str.append(f"{k}={v}")
        return ", ".join(keys_str)
