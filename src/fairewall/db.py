"""One storage layer for every fAIrewall store: SQLite locally, Postgres in the cloud.

A store is opened with a *target*:

  * a file path (or ":memory:") -> SQLite, as before; no extra dependency;
  * a ``postgresql://`` URL     -> Postgres (Cloud SQL in production). Needs
    ``pip install 'fairewall[postgres]'``.

Every store keeps the same guarantee on both: **one write transaction at a
time per store**. On SQLite that is ``BEGIN IMMEDIATE``. On Postgres it is a
transaction-scoped advisory lock taken first thing in every transaction, so
several Cloud Run instances sharing one database still behave as one serial
writer: an idempotency key is bound once, an approval is decided once, a run is
claimed once. Each store lives in its own Postgres schema (by default the
store's name, or ``?schema=`` on the URL), the way each has its own file on
SQLite, and stores do not block each other.

Store code writes SQL once, in the subset both engines accept: ``?``
placeholders, ``INSERT ... ON CONFLICT``, no ``INSERT OR REPLACE``. DDL is
written for SQLite and adapted (``REAL`` -> ``DOUBLE PRECISION``, ``INTEGER``
-> ``BIGINT``, ``AUTOINCREMENT`` -> ``BIGSERIAL``); anything that differs more
(triggers) is passed per dialect.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SCHEMA_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def is_postgres(target: Any) -> bool:
    return isinstance(target, str) and target.startswith(("postgres://", "postgresql://"))


def redact_url(target: Any) -> str:
    """A store target safe to print: the password in a database URL is masked."""
    text = str(target)
    if not is_postgres(text):
        return text
    parts = urlsplit(text)
    if parts.password:
        netloc = parts.netloc.replace(":" + parts.password + "@", ":***@", 1)
        parts = parts._replace(netloc=netloc)
    return urlunsplit(parts)


def with_schema(url: str, schema: str) -> str:
    """The same Postgres URL with ``?schema=`` set (replacing any existing one)."""
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query) if k != "schema"] + [("schema", schema)]
    return urlunsplit(parts._replace(query=urlencode(query)))


def _split_schema(url: str, default: str) -> Tuple[str, str]:
    parts = urlsplit(url)
    query = parse_qsl(parts.query)
    schema = next((v for k, v in query if k == "schema"), default)
    rest = urlencode([(k, v) for k, v in query if k != "schema"])
    return urlunsplit(parts._replace(query=rest)), schema


def resolve(target: Any, schema: str) -> Tuple[str, Any, str]:
    """(dialect, location, schema) for a store target. Tests may patch this."""
    if is_postgres(target):
        url, schema = _split_schema(target, schema)
        return "postgres", url, schema
    return "sqlite", str(target), schema


class Row(dict):
    """A result row readable by name (``row["id"]``) and by position (``row[0]``)."""

    __slots__ = ()

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return list(self.values())[key]
        return dict.__getitem__(self, key)


def _sqlite_row(cursor: sqlite3.Cursor, values: Sequence[Any]) -> Row:
    return Row(zip([c[0] for c in cursor.description], values))


def _pg_row_factory(cursor: Any):
    names = [c.name for c in cursor.description] if cursor.description else []
    return lambda values: Row(zip(names, values))


def pg_ddl(sql: str) -> str:
    """Adapt SQLite DDL to Postgres types."""
    sql = re.sub(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", "BIGSERIAL PRIMARY KEY", sql, flags=re.I)
    sql = re.sub(r"\bREAL\b", "DOUBLE PRECISION", sql)
    return re.sub(r"\bINTEGER\b", "BIGINT", sql)


def _pg_sql(sql: str) -> str:
    return sql.replace("%", "%%").replace("?", "%s")


class _PgCursor:
    """Runs store SQL (``?`` placeholders) on a psycopg connection."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Any:
        if params:
            return self._conn.execute(_pg_sql(sql), tuple(params))
        return self._conn.execute(sql)


_POOLS: Dict[str, Any] = {}
_POOLS_LOCK = threading.Lock()


def _behind_pooler(url: str) -> bool:
    """True when connections go through a transaction pooler (PgBouncer, Neon's ``-pooler`` host).

    Such poolers hand each transaction to any server connection, so server-side prepared
    statements are switched off. Advisory locks here are transaction-scoped, so they still hold.
    Override with FAIREWALL_DB_POOLER=1/0.
    """
    flag = os.environ.get("FAIREWALL_DB_POOLER", "").strip().lower()
    if flag in ("1", "true", "yes"):
        return True
    if flag in ("0", "false", "no"):
        return False
    host = urlsplit(url).hostname or ""
    return "-pooler." in host or "pgbouncer" in host


def _pool(url: str) -> Any:
    """One small connection pool per database URL, shared by every store on it.

    The smallest Cloud SQL tier allows 25 connections in total, so the pool is
    capped (FAIREWALL_DB_POOL_SIZE, default 5) rather than one per thread.
    """
    with _POOLS_LOCK:
        pool = _POOLS.get(url)
        if pool is None:
            try:
                from psycopg_pool import ConnectionPool  # type: ignore
            except ImportError as exc:  # pragma: no cover - env dependent
                raise ImportError("Postgres storage needs `pip install 'fairewall[postgres]'`") from exc
            size = int(os.environ.get("FAIREWALL_DB_POOL_SIZE", "5"))
            kwargs: Dict[str, Any] = {"autocommit": True, "row_factory": _pg_row_factory}
            if _behind_pooler(url):
                kwargs["prepare_threshold"] = None
            pool = ConnectionPool(
                url, min_size=1, max_size=max(1, size), open=True, name="fairewall",
                kwargs=kwargs,
                check=ConnectionPool.check_connection,
                timeout=float(os.environ.get("FAIREWALL_DB_POOL_TIMEOUT_S", "30")))
            _POOLS[url] = pool
        return pool


def close_pools() -> None:
    """Close every Postgres pool (tests, and clean shutdown)."""
    with _POOLS_LOCK:
        for pool in _POOLS.values():
            try:
                pool.close()
            except Exception:
                pass
        _POOLS.clear()


class Database:
    """A store's database. ``transaction()`` is the only way in."""

    def __init__(self, target: Any, *, schema: str) -> None:
        self.dialect, self.location, self.schema = resolve(target, schema)
        if self.dialect == "postgres":
            if not _SCHEMA_NAME.match(self.schema):
                raise ValueError("Postgres schema names use lowercase letters, digits and '_' "
                                 "(got %r)" % self.schema)
            digest = hashlib.sha256(("fairewall:" + self.schema).encode()).digest()
            self._lock_key = int.from_bytes(digest[:8], "big", signed=True)
            with _pool(self.location).connection() as conn:
                conn.execute("BEGIN")
                try:
                    conn.execute("SELECT pg_advisory_xact_lock(%s)", (self._lock_key,))
                    conn.execute('CREATE SCHEMA IF NOT EXISTS "%s"' % self.schema)
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
        else:
            self._memory = self.location == ":memory:"
            self._local = threading.local()
            self._connections: list = []
            self._connections_lock = threading.Lock()
            self._shared_lock = threading.RLock()

    # The column that orders rows by insertion.
    @property
    def rowid(self) -> str:
        return "seq" if self.dialect == "postgres" else "rowid"

    def json_text(self, column: str, key: str) -> str:
        """SQL for the text value of top-level *key* in a JSON text column."""
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", column + key):
            raise ValueError("bad JSON path")
        if self.dialect == "postgres":
            return "(%s::jsonb ->> '%s')" % (column, key)
        return "json_extract(%s, '$.%s')" % (column, key)

    def _sqlite_connection(self) -> sqlite3.Connection:
        db = None if self._memory else getattr(self._local, "db", None)
        if self._memory:
            db = self._connections[0] if self._connections else None
        if db is None:
            db = sqlite3.connect(self.location, timeout=15, isolation_level=None,
                                 check_same_thread=not self._memory)
            db.row_factory = _sqlite_row
            if not self._memory:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA synchronous=FULL")
                self._local.db = db
            with self._connections_lock:
                self._connections.append(db)
        return db

    def _key_for(self, lock: Optional[str]) -> int:
        if lock is None:
            return self._lock_key
        digest = hashlib.sha256(("fairewall:%s:%s" % (self.schema, lock)).encode()).digest()
        return int.from_bytes(digest[:8], "big", signed=True)

    @contextmanager
    def transaction(self, lock: Optional[str] = None) -> Iterator[Any]:
        """One serialized write transaction. Commits on success, rolls back on error.

        By default the whole store is one critical section. ``lock`` narrows it
        to one key (a session id, an audit log id) on Postgres, so unrelated
        keys proceed in parallel across instances. Code using a key lock must
        only touch rows belonging to that key. SQLite always takes its single
        write lock, which is at least as strict.
        """
        if self.dialect == "postgres":
            with _pool(self.location).connection() as conn:
                conn.execute('BEGIN; SET LOCAL search_path TO "%s"; SELECT pg_advisory_xact_lock(%d)'
                             % (self.schema, self._key_for(lock)))
                try:
                    yield _PgCursor(conn)
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                else:
                    conn.execute("COMMIT")
            return
        with self._shared_lock if self._memory else _nullcontext():
            db = self._sqlite_connection()
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            else:
                db.execute("COMMIT")

    def create(self, sqlite_ddl: str, postgres_extra: Optional[str] = None,
               sqlite_extra: Optional[str] = None) -> None:
        """Create tables (idempotent). *sqlite_ddl* is adapted for Postgres.

        Extras hold what can't be adapted mechanically, such as triggers.
        """
        statements = [s for s in sqlite_ddl.split(";") if s.strip()]
        with self.transaction() as db:
            if self.dialect == "postgres":
                for s in statements:
                    db.execute(pg_ddl(s))
                if postgres_extra:
                    db.execute(postgres_extra)
            else:
                for s in statements:
                    db.execute(s)
                for s in (sqlite_extra or "").split(";;"):
                    if s.strip():
                        db.execute(s)

    def close(self) -> None:
        """Close this store's SQLite connections. Postgres pools are shared; see close_pools()."""
        if self.dialect != "sqlite":
            return
        with self._connections_lock:
            for db in self._connections:
                try:
                    db.close()
                except Exception:
                    pass
            self._connections.clear()
        self._local = threading.local()


@contextmanager
def _nullcontext() -> Iterator[None]:
    yield
