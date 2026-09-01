from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple
from urllib.parse import quote_plus

# Conditional imports for soft failures
try:
    from sqlalchemy import create_engine, inspect, select, tablesample, text as sql_text
    from sqlalchemy import table as sql_table, column as sql_column
except ImportError:
    create_engine = None

from src.pipeline.records import COLUMNAR, Cell, Record
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
    Discovers schemas, tables and columns dynamically, then streams rows in chunks
    as columnar Records (one Cell per non-empty column) into the classification
    pipeline, which uses the column name as context and judges whole columns.
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
            "sample_limit": 10000,           # optional, max rows per table
            "sample_strategy": "head"        # optional: "head" (first rows) or "random" (TABLESAMPLE on
                                             # PostgreSQL / MSSQL for large tables, head elsewhere)
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
            self.stats.setdefault("error_details", []).append(f"connect: {str(e)[:200]}")
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
            self.stats.setdefault("error_details", []).append(f"schema {schema}: {str(e)[:200]}")
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
            self.stats.setdefault("error_details", []).append(f"{full_relation_name}: {str(e)[:200]}")
            logger.error(f"Failed to get columns for {full_relation_name}: {str(e)}")
            return []

        if not column_names:
            return []

        relation = sql_table(name, *[sql_column(c) for c in column_names], schema=schema)
        sample_limit = target.get("sample_limit", 10000)

        # Random sampling (Wiz: "statistical sampling of a sufficient number of records"):
        # TABLESAMPLE on engines that support it, when the table is large enough for it to matter
        strategy = str(target.get("sample_strategy") or self.config.get("sample_strategy") or "head").lower()
        source = relation
        if strategy == "random" and sample_limit:
            sampled = self._random_sample_source(sa_engine, relation, schema, name, sample_limit)
            if sampled is not None:
                source = sampled
        stmt = select(source)

        # Incremental scanning: only rows changed since the last scan
        inc_col = target.get("incremental_column")
        last_scan_time = target.get("last_scan_time")
        if inc_col and last_scan_time and inc_col in column_names:
            stmt = stmt.where(source.c[inc_col] > last_scan_time)

        # Dialect-aware row cap (LIMIT / TOP), avoids full scans of huge tables
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

        def location_of(row_idx: int, col_name: str) -> str:
            return f"{schema_part}Relation '{name}' ({rel_type}), Row {row_idx}, Column '{col_name}'"

        errors_before = self.stats["errors"]
        findings = self.classify(
            table_resource_id,
            self._iter_rows(sa_engine, stmt, column_names, chunk_size, location_of),
            location_fn=lambda column, n: f"{schema_part}Relation '{name}' ({rel_type}), Column '{column}' ({n} matches)",
            unit_name=name,
        )
        if self.stats["errors"] == errors_before:
            self.stats["tables_scanned"] += 1
        return findings

    def _estimate_rows(self, sa_engine: Any, schema: Optional[str], name: str) -> Optional[int]:
        """Cheap planner estimate of a table's row count (PostgreSQL, MSSQL); None when unknown."""
        dialect = sa_engine.dialect.name
        try:
            with sa_engine.connect() as conn:
                if dialect == "postgresql":
                    qualified = f'"{schema}"."{name}"' if schema else f'"{name}"'
                    value = conn.execute(sql_text("SELECT reltuples::bigint FROM pg_class WHERE oid = to_regclass(:q)"), {"q": qualified}).scalar()
                elif dialect == "mssql":
                    value = conn.execute(
                        sql_text(
                            "SELECT SUM(p.rows) FROM sys.partitions p JOIN sys.tables t ON p.object_id = t.object_id "
                            "JOIN sys.schemas s ON t.schema_id = s.schema_id "
                            "WHERE t.name = :t AND s.name = :s AND p.index_id IN (0, 1)",
                        ),
                        {"t": name, "s": schema or "dbo"},
                    ).scalar()
                else:
                    return None
        except Exception as e:
            logger.info(f"Row estimate unavailable for {name}: {str(e)[:120]}")
            return None
        try:
            return int(value) if value is not None and int(value) >= 0 else None
        except (TypeError, ValueError):
            return None

    def _random_sample_source(self, sa_engine: Any, relation: Any, schema: Optional[str], name: str, sample_limit: int) -> Any:
        """
        TABLESAMPLE SYSTEM (p) wrapping the relation when the engine supports it and
        the table holds well over sample_limit rows; p is chosen so that about three
        times sample_limit rows are sampled before LIMIT cuts them (page sampling is
        clumpy). None means: read the head as usual.
        """
        if sa_engine.dialect.name not in ("postgresql", "mssql"):
            return None
        estimate = self._estimate_rows(sa_engine, schema, name)
        if not estimate or estimate <= sample_limit * 2:
            return None
        percent = min(100.0, max(0.01, round(100.0 * sample_limit * 3 / estimate, 4)))
        logger.info(f"Random sampling {name}: TABLESAMPLE {percent}% of ~{estimate} rows")
        return tablesample(relation, percent, name="sampled")

    def _iter_rows(
        self, sa_engine: Any, stmt: Any, column_names: List[str], chunk_size: int,
        location_of: Callable[[int, str], str],
    ) -> Iterator[Record]:
        """
        Streams the statement's rows as columnar Records. Rows are counted in
        stats even when the pipeline stops reading early (adaptive sampling).
        """
        row_idx = 0
        try:
            with sa_engine.connect() as conn:
                result = conn.execution_options(stream_results=True).execute(stmt)
                while True:
                    rows = result.fetchmany(chunk_size)
                    if not rows:
                        break
                    for row in rows:
                        mapping = row._mapping
                        cells = []
                        for col_name in column_names:
                            val = mapping.get(col_name)
                            if val is None:
                                continue
                            if isinstance(val, bytes):
                                val = val.decode("utf-8", errors="ignore")
                            val_str = str(val)
                            if not val_str:
                                continue
                            # The column name is context for the engine (credential/identifier
                            # columns, entity hints), never part of the scanned text
                            cells.append(Cell(value=val_str, field=col_name, location=location_of(row_idx, col_name)))
                        row_idx += 1
                        if cells:
                            yield Record(cells, shape=COLUMNAR)
        finally:
            self.stats["rows_scanned"] += row_idx
