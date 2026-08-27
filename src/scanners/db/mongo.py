import re
from datetime import datetime
from typing import Any, Dict, Iterator, List, Tuple
from urllib.parse import quote_plus

# Conditional import for soft failures
try:
    from pymongo import MongoClient
except ImportError:
    MongoClient = None

from src.scanners.base import BaseScanner
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Databases that hold engine internals rather than user data
SYSTEM_DATABASES = {"admin", "local", "config"}


class MongoScanner(BaseScanner):
    """
    Scans MongoDB (and API-compatible stores like DocumentDB) for sensitive data.
    Discovers databases and collections dynamically, then walks documents
    recursively. Field values are scanned with their field name as context so
    keyword-based scoring (e.g. a bare email in an 'email' field) works.
    """

    def __init__(self, engine, config: Dict[str, Any] = None, client=None):
        super().__init__(engine, config, client)
        self.stats = {"collections_scanned": 0, "documents_scanned": 0, "errors": 0}

    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Target structure:
        {
            "uri": "mongodb://user:pass@host:27017/?authSource=admin", # optional, overrides the fields below # pragma: allowlist secret
            "host": "mongo.internal.example.com",
            "port": 27017,
            "username": "scanner",
            "password": "dbpassword", # pragma: allowlist secret
            "database": "appdb",           # optional, all non-system databases if omitted
            "collection": "users",         # optional, all collections if omitted
            "incremental_field": "updated_at",        # optional field for incremental scans
            "last_scan_time": "2026-08-01T00:00:00",  # optional, used with incremental_field
            "sample_limit": 10000          # optional, max documents per collection
        }
        """
        host = target.get("host") or "localhost"
        client = self.client
        owns_client = client is None

        if owns_client:
            if not MongoClient:
                self.stats["errors"] += 1
                logger.warning("pymongo is not installed. Skipping MongoDB scan.")
                return []
            uri = target.get("uri") or self._build_uri(target)
            try:
                client = MongoClient(uri, serverSelectionTimeoutMS=self.config.get("connect_timeout", 10) * 1000)
            except Exception as e:
                self.stats["errors"] += 1
                logger.error(f"Failed to connect to MongoDB at {host}: {str(e)}")
                return []

        logger.info(f"Starting MongoDB scan for mongodb://{host}")
        findings = []
        try:
            if target.get("database"):
                db_names = [target["database"]]
            else:
                db_names = [d for d in client.list_database_names() if d not in SYSTEM_DATABASES]

            for db_name in db_names:
                db = client[db_name]
                try:
                    if target.get("collection"):
                        coll_names = [target["collection"]]
                    else:
                        coll_names = [c for c in db.list_collection_names() if not c.startswith("system.")]
                except Exception as e:
                    self.stats["errors"] += 1
                    logger.error(f"Failed to list collections for database '{db_name}': {str(e)}")
                    continue

                for coll_name in coll_names:
                    findings.extend(self._scan_collection(db, db_name, coll_name, target, host))

        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Error scanning MongoDB at {host}: {str(e)}")
        finally:
            if owns_client:
                try:
                    client.close()
                except Exception:
                    pass

        return self.dedup_findings(findings)

    def _build_uri(self, target: Dict[str, Any]) -> str:
        host = target.get("host") or "localhost"
        port = target.get("port") or 27017
        username = target.get("username")
        password = target.get("password")
        auth = ""
        if username:
            auth = quote_plus(str(username))
            if password:
                auth += f":{quote_plus(str(password))}"
            auth += "@"
        return f"mongodb://{auth}{host}:{port}/"

    def _scan_collection(
        self, db: Any, db_name: str, coll_name: str,
        target: Dict[str, Any], host: str,
    ) -> List[Dict[str, Any]]:
        findings = []
        resource_id = f"mongodb://{host}/{db_name}/{coll_name}"
        logger.info(f"Scanning collection {db_name}.{coll_name}")

        # Incremental scanning: only documents changed since the last scan
        query = {}
        inc_field = target.get("incremental_field")
        last_scan_time = target.get("last_scan_time")
        if inc_field and last_scan_time:
            # BSON comparisons are type-bracketed: an ISO string never matches a
            # Date field, so parse strings into datetimes (raw value kept if unparseable)
            if isinstance(last_scan_time, str):
                try:
                    last_scan_time = datetime.fromisoformat(last_scan_time.replace("Z", "+00:00"))
                except ValueError:
                    pass
            query = {inc_field: {"$gt": last_scan_time}}

        sample_limit = target.get("sample_limit", 10000)
        batch_size = self.config.get("chunk_size", 1000)

        if self.config.get("log_queries"):
            logger.info(
                f"Executing query on {db_name}.{coll_name}: "
                f"find({query}, batch_size={batch_size}).limit({sample_limit})",
            )

        grouped = {}
        try:
            cursor = db[coll_name].find(query, batch_size=batch_size).limit(sample_limit)
            doc_count = 0
            for doc_idx, doc in enumerate(cursor):
                doc_id = doc.get("_id", f"index {doc_idx}") if isinstance(doc, dict) else f"index {doc_idx}"
                for path, key, value in self._iter_leaves(doc):
                    # Field name gives the detection engine keyword context
                    text_blob = f"{key}: {value}" if key else value
                    for f in self.engine.scan_text(text_blob):
                        if self.is_suppressed(f["detector"], key):
                            continue
                        location = (
                            f"Database '{db_name}', Collection '{coll_name}', "
                            f"Document _id={doc_id}, Field '{path}'"
                        )
                        # Aggregate per field path with array indices collapsed
                        norm_path = re.sub(r"\[\d+\]", "[]", path)
                        grouped.setdefault((f["detector"], norm_path), []).append(
                            self.format_finding(
                                f["detector"], f["category"], f["severity"], f["value"],
                                resource_id, location,
                            ),
                        )
                doc_count += 1
            self.stats["documents_scanned"] += doc_count
            self.stats["collections_scanned"] += 1
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Error scanning collection {db_name}.{coll_name}: {str(e)}")

        findings.extend(
            self.flush_grouped_findings(
                grouped,
                lambda field, n: (
                    f"Database '{db_name}', Collection '{coll_name}', "
                    f"Field '{field}' ({n} matches)"
                ),
            ),
        )
        return findings

    def _iter_leaves(self, node: Any, path: str = "", key: str = "") -> Iterator[Tuple[str, str, str]]:
        """
        Recursively walks a document, yielding (dotted_path, leaf_field_name, string_value)
        for every scalar leaf. Lists keep the field name of their parent key.
        """
        if isinstance(node, dict):
            for k, v in node.items():
                child_path = f"{path}.{k}" if path else str(k)
                yield from self._iter_leaves(v, child_path, str(k))
        elif isinstance(node, (list, tuple)):
            for idx, item in enumerate(node):
                yield from self._iter_leaves(item, f"{path}[{idx}]", key)
        elif node is None:
            return
        else:
            if isinstance(node, bytes):
                value = node.decode("utf-8", errors="ignore")
            else:
                value = str(node)
            if value:
                yield path, key, value
