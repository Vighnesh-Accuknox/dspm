from typing import Any, Dict, List

from src.scanners.db.sql import SQLScanner
from src.utils.logger import get_logger

logger = get_logger(__name__)


class RDSScanner(SQLScanner):
    """
    Scans RDS and Aurora databases for sensitive data.
    Thin wrapper over the generic SQLScanner (postgres/mysql/mariadb/mssql):
    routes to the Aurora reader endpoint when requested and formats resource
    ids as RDS ARNs.
    """

    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Target structure (in addition to SQLScanner target fields):
        {
            "reader_endpoint": "mydb-ro.xyz.us-east-1.rds.amazonaws.com",
            "use_reader": true
        }
        """
        if target.get("use_reader") and target.get("reader_endpoint"):
            target = {**target, "host": target["reader_endpoint"]}
            logger.info(f"Routing connection to Aurora Reader Endpoint: {target['host']}")
        return super().scan(target)

    def _base_resource_id(self, target: Dict[str, Any]) -> str:
        return f"arn:aws:rds:db:{target.get('host')}/{target.get('database')}"
