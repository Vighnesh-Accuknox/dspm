from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import quote_plus

# Conditional imports for soft failures
try:
    from sqlalchemy import create_engine, inspect, select
    from sqlalchemy import table as sql_table, column as sql_column
except ImportError:
    create_engine = None

from src.scanners.base import BaseScanner
from src.utils.logger import get_logger

logger = get_logger(__name__)

# SQLAlchemy dialect+driver per supported engine
DIALECT_DRIVERS = {
    "postgres": "postgresql+psycopg2",
    "postgresql": "postgresql+psycopg2",
    "mysql": "mysql+pymysql",
    "mariadb": "mysql+pymysql",
    "mssql": "mssql+pymssql",
    "sqlserver": "mssql+pymssql",
}

# Schemas that hold engine internals rather than user data
SYSTEM_SCHEMAS = {
    "information_schema",
    "pg_catalog", "pg_toast",              # PostgreSQL
    "mysql", "performance_schema", "sys",  # MySQL / MariaDB (sys also on MSSQL)
    "guest",                               # MSSQL
}
SYSTEM_SCHEMA_PREFIXES = ("pg_", "db_")


class SQLScanner(BaseScanner):
    """
    Scans relational databases (PostgreSQL, MySQL, MariaDB, MSSQL) for sensitive data.
    Discovers schemas, tables and columns dynamically, then streams rows in chunks.
    Cell values are scanned with their column name as context so keyword-based
    scoring (e.g. a bare email in an 'email' column) works on structured data.
    """

    def __init__(self, engine, config: Dict[str, Any] = None, client=None):
        super().__init__(engine, config, client)
        self.stats = {"tables_scanned": 0, "rows_scanned": 0, "errors": 0}

    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scans every relation of the database and returns all findings.
        See iter_scan for the target structure and per-relation results.
        """
        findings = []
        for _resource_id, _relation_name, relation_findings in self.iter_scan(target):
            findings.extend(relation_findings)
        return findings

    def iter_scan(self, target: Dict[str, Any]) -> Iterator[Tuple[str, str, List[Dict[str, Any]]]]:
        """
        Scans the database one relation at a time, yielding
        (resource_id, relation_name, findings) as each table/view finishes —
        the database counterpart of scanning an S3 bucket object by object.
        relation_name is schema-qualified ('public.users') when the engine has
        schemas; every visited relation is yielded, with an empty list when it
        is clean, and findings are deduplicated per relation.

        Target structure:
        {
            "engine": "postgres" | "mysql" | "mariadb" | "mssql",
            "host": "db.internal.example.com",
            "port": 5432,
            "username": "scanner",
            "password": "dbpassword",               # pragma: allowlist secret
            "database": "production",               # pragma: allowlist secret
            "connection_string": "postgresql+psycopg2://...",  # optional, overrides the fields above
            "connect_args": {"sslmode": "require"},  # optional, extra DBAPI args (TLS etc.)
            "schema": "public",              # optional, restrict to a single schema
            "tables": ["users", "sales.orders"],  # optional, restrict to specific tables
            "include_views": false,          # optional, also scan views
            "incremental_column": "updated_at",       # optional column for incremental scans
            "last_scan_time": "2026-08-01T00:00:00",  # optional, used with incremental_column
            "sample_limit": 10000            # optional, max rows per table
        }
        """
        if not create_engine:
            self.stats["errors"] += 1
            logger.warning("SQLAlchemy is not installed. Skipping SQL database scan.")
            return

        db_engine = (target.get("engine") or "postgres").lower()
        database = target.get("database")
        resource_id = self._base_resource_id(target)
        logger.info(f"Starting SQL scan for {resource_id}")

        conn_str = target.get("connection_string")
        if conn_str:
            conn_str = self._normalize_driver(conn_str, db_engine)
        else:
            conn_str = self._build_connection_string(
                db_engine, target.get("host"), target.get("port"),
                target.get("username"), target.get("password"), database,
            )
        if not conn_str:
            self.stats["errors"] += 1
            logger.error(f"Unsupported database engine '{db_engine}' or missing connection details.")
            return

        sa_engine = self.client
        owns_engine = sa_engine is None
        try:
            if owns_engine:
                connect_args = {**self._connect_args(conn_str), **(target.get("connect_args") or {})}
                sa_engine = create_engine(conn_str, connect_args=connect_args)
            inspector = inspect(sa_engine)

            for schema in self._discover_schemas(sa_engine, inspector, target, database):
                for name, rel_type in self._list_relations(inspector, schema, target):
                    full_relation_name = f"{schema}.{name}" if schema else name
                    relation_findings = self._scan_relation(
                        sa_engine, inspector, schema, name, rel_type, target, resource_id,
                    )
                    yield (
                        f"{resource_id}/{full_relation_name}",
                        full_relation_name,
                        self.dedup_findings(relation_findings),
                    )

        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Error connecting/scanning SQL database {resource_id}: {str(e)}")
        finally:
            if owns_engine and sa_engine is not None:
                try:
                    sa_engine.dispose()
                except Exception:
                    pass

    def _base_resource_id(self, target: Dict[str, Any]) -> str:
        db_engine = (target.get("engine") or "postgres").lower()
        host = target.get("host") or "localhost"
        port = target.get("port")
        database = target.get("database") or ""
        netloc = f"{host}:{port}" if port else host
        return f"{db_engine}://{netloc}/{database}"

    def _build_connection_string(
        self, db_engine: str, host: str, port: Any,
        username: str, password: str, database: str,
    ) -> Optional[str]:
        driver = DIALECT_DRIVERS.get(db_engine)
        if not driver or not host:
            return None
        auth = ""
        if username:
            auth = quote_plus(str(username))
            if password:
                auth += f":{quote_plus(str(password))}"
            auth += "@"
        netloc = f"{host}:{port}" if port else host
        return f"{driver}://{auth}{netloc}/{database or ''}"

    def _normalize_driver(self, conn_str: str, db_engine: str) -> str:
        """
        Upgrades a bare 'mysql://', 'postgres://', 'mssql://' scheme (no explicit
        DBAPI driver) to our supported driver, e.g. 'mysql+pymysql://'. SQLAlchemy's
        default drivers (MySQLdb, pyodbc, ...) aren't in requirements.txt, so a raw
        DB_URI would otherwise fail with 'No module named MySQLdb'/similar.
        """
        driver = DIALECT_DRIVERS.get(db_engine)
        scheme, sep, rest = conn_str.partition("://")
        if not driver or not sep or "+" in scheme:
            return conn_str
        return f"{driver}://{rest}"

    def _connect_args(self, conn_str: str) -> Dict[str, Any]:
        timeout = self.config.get("connect_timeout", 10)
        if conn_str.startswith(("postgresql", "mysql", "mariadb")):
            return {"connect_timeout": timeout}
        if conn_str.startswith("mssql+pymssql"):
            return {"login_timeout": timeout}
        return {}

    def _is_system_schema(self, schema: str) -> bool:
        if not schema:
            return False
        lowered = schema.lower()
        return lowered in SYSTEM_SCHEMAS or lowered.startswith(SYSTEM_SCHEMA_PREFIXES)

    def _discover_schemas(
        self, sa_engine: Any, inspector: Any, target: Dict[str, Any],
        database: str,
    ) -> List[Optional[str]]:
        if target.get("schema"):
            return [target["schema"]]
        try:
            schemas = [s for s in inspector.get_schema_names() if not self._is_system_schema(s)]
        except Exception:
            schemas = [None]
        # On MySQL/MariaDB schemas are databases; stay scoped to the connected one
        if sa_engine.dialect.name in ("mysql", "mariadb") and database:
            schemas = [s for s in schemas if s == database] or [database]
        return schemas or [None]

    def _list_relations(
        self, inspector: Any, schema: Optional[str], target: Dict[str, Any],
    ) -> List[Tuple[str, str]]:
        """
        (name, "table"|"view") pairs to scan in a schema, honouring target
        'tables' (plain or schema-qualified names) and 'include_views'.
        """
        try:
            tables = inspector.get_table_names(schema=schema)
            views = inspector.get_view_names(schema=schema) if target.get("include_views") else []
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Failed to list tables for schema '{schema}': {str(e)}")
            return []

        requested = {t.lower() for t in target.get("tables") or []}
        relations = []
        for name, rel_type in [(t, "table") for t in tables] + [(v, "view") for v in views]:
            qualified = f"{schema}.{name}".lower() if schema else name.lower()
            if requested and name.lower() not in requested and qualified not in requested:
                continue
            relations.append((name, rel_type))
        return relations

    def _scan_relation(
        self, sa_engine: Any, inspector: Any, schema: Optional[str], name: str,
        rel_type: str, target: Dict[str, Any], resource_id: str,
    ) -> List[Dict[str, Any]]:
        findings = []
        full_relation_name = f"{schema}.{name}" if schema else name
        logger.info(f"Scanning {rel_type} {full_relation_name}")

        try:
            columns_info = inspector.get_columns(name, schema=schema)
            column_names = [col["name"] for col in columns_info]
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Failed to get columns for {full_relation_name}: {str(e)}")
            return []

        if not column_names:
            return []

        relation = sql_table(name, *[sql_column(c) for c in column_names], schema=schema)
        stmt = select(relation)

        # Incremental scanning: only rows changed since the last scan
        inc_col = target.get("incremental_column")
        last_scan_time = target.get("last_scan_time")
        if inc_col and last_scan_time and inc_col in column_names:
            stmt = stmt.where(relation.c[inc_col] > last_scan_time)

        # Dialect-aware row cap (LIMIT / TOP), avoids full scans of huge tables
        sample_limit = target.get("sample_limit", 10000)
        if sample_limit:
            stmt = stmt.limit(sample_limit)

        chunk_size = self.config.get("chunk_size", 5000)
        table_resource_id = f"{resource_id}/{full_relation_name}"
        schema_part = f"Schema '{schema}', " if schema else ""

        if self.config.get("log_queries"):
            # Log the exact statement as compiled for this dialect, with bound values inlined
            try:
                query_str = str(stmt.compile(sa_engine, compile_kwargs={"literal_binds": True}))
            except Exception:
                try:
                    query_str = str(stmt.compile(sa_engine))
                except Exception:
                    query_str = str(stmt)
            logger.info(f"Executing query on {full_relation_name}: {' '.join(query_str.split())}")

        grouped = {}
        try:
            with sa_engine.connect() as conn:
                result = conn.execution_options(stream_results=True).execute(stmt)
                row_idx = 0
                while True:
                    rows = result.fetchmany(chunk_size)
                    if not rows:
                        break
                    for row in rows:
                        mapping = row._mapping
                        for col_name in column_names:
                            val = mapping.get(col_name)
                            if val is None:
                                continue
                            if isinstance(val, bytes):
                                val = val.decode("utf-8", errors="ignore")
                            val_str = str(val)
                            if not val_str:
                                continue
                            # Column name gives the detection engine keyword context
                            cell_findings = self.engine.scan_text(f"{col_name}: {val_str}")
                            for f in cell_findings:
                                if self.is_suppressed(f["detector"], col_name):
                                    continue
                                location = (
                                    f"{schema_part}Relation '{name}' ({rel_type}), "
                                    f"Row {row_idx}, Column '{col_name}'"
                                )
                                grouped.setdefault((f["detector"], col_name), []).append(
                                    self.format_finding(
                                        f["detector"], f["category"], f["severity"], f["value"],
                                        table_resource_id, location,
                                    ),
                                )
                        row_idx += 1
                self.stats["rows_scanned"] += row_idx
                self.stats["tables_scanned"] += 1
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Error querying rows from {full_relation_name}: {str(e)}")

        findings.extend(
            self.flush_grouped_findings(
                grouped,
                lambda column, n: (
                    f"{schema_part}Relation '{name}' ({rel_type}), "
                    f"Column '{column}' ({n} matches)"
                ),
            ),
        )
        return findings
