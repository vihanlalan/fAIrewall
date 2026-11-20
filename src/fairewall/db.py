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
import time
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


def _pg_timeouts() -> str:
    """Per-transaction safety limits, so one stuck caller can never wedge every other request.

    - lock_timeout: waiting for a store's lock fails after FAIREWALL_DB_LOCK_TIMEOUT_MS (15 s)
      instead of hanging.
    - idle_in_transaction_session_timeout: a transaction left open by a caller that froze or died
      (a serverless instance suspended mid-request) is ended by Postgres after
      FAIREWALL_DB_IDLE_TX_TIMEOUT_MS (60 s), releasing its locks.
    """
    lock_ms = int(os.environ.get("FAIREWALL_DB_LOCK_TIMEOUT_MS", "15000"))
    idle_ms = int(os.environ.get("FAIREWALL_DB_IDLE_TX_TIMEOUT_MS", "60000"))
    stmt_ms = int(os.environ.get("FAIREWALL_DB_STATEMENT_TIMEOUT_MS", "30000"))
    return ("SET LOCAL lock_timeout = %d; SET LOCAL idle_in_transaction_session_timeout = %d; "
            "SET LOCAL statement_timeout = %d;" % (lock_ms, idle_ms, stmt_ms))


class InlinePool:
    """A connection pool with no background threads, for serverless hosts (Vercel).

    psycopg_pool opens connections from worker threads. A serverless runtime may start the app,
    then fork or snapshot the process to serve requests; the workers do not come along, so every
    request would wait for a connection that never arrives (PoolTimeout). Here the requesting
    thread opens connections itself, and the pool is rebuilt whenever the process id changes.

    A serverless instance is suspended between requests, and a connection idle across a
    suspension can be dead without either side being told: a query on it would wait forever.
    So connections idle longer than FAIREWALL_DB_IDLE_REUSE_S (10 s) are discarded rather than
    reused, sockets carry TCP keepalives and a send timeout (a dead peer errors in ~15 s instead
    of hanging), and a reused connection that fails on BEGIN is replaced once, transparently:
    nothing has run yet at that point, so the retry is safe.

    It never makes a caller wait for a slot. One request can hold a transaction on one store while
    it opens another, so a capped pool deadlocks as soon as a few requests do that at once (each
    holds a slot the others need). ``size`` caps only the idle connections kept for reuse; a
    transaction pooler in front of Postgres (Neon's ``-pooler`` host) absorbs the client count.
    """

    def __init__(self, url: str, size: int, kwargs: Dict[str, Any]) -> None:
        self.url, self.size, self.kwargs = url, max(1, size), kwargs
        self.pid = os.getpid()
        self._idle: list = []
        self._lock = threading.Lock()

    def _connect(self) -> Any:
        import psycopg  # type: ignore
        return psycopg.connect(self.url, connect_timeout=10, keepalives=1, keepalives_idle=5,
                               keepalives_interval=3, keepalives_count=3, tcp_user_timeout=15000,
                               **self.kwargs)

    @staticmethod
    def _discard(conn: Any) -> None:
        try:
            conn.close()
        except Exception:
            pass

    def _checkout(self) -> Any:
        """A connection used within the last few seconds, or a new one."""
        max_idle = float(os.environ.get("FAIREWALL_DB_IDLE_REUSE_S", "10"))
        while True:
            with self._lock:
                candidate, since = self._idle.pop() if self._idle else (None, 0.0)
            if candidate is None:
                return self._connect(), False
            if not (candidate.closed or candidate.broken) and time.monotonic() - since <= max_idle:
                return candidate, True
            self._discard(candidate)

    @contextmanager
    def connection(self, begin: Optional[str] = None) -> Iterator[Any]:
        conn = None
        try:
            conn, reused = self._checkout()
            if begin is not None:
                try:
                    conn.execute(begin)
                except Exception:
                    if not (reused and (conn.closed or conn.broken)):
                        raise
                    # The reused connection was dead. Nothing ran yet: start over on a new one.
                    self._discard(conn)
                    conn = None
                    conn = self._connect()
                    conn.execute(begin)
            yield conn
        except BaseException:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
            raise
        finally:
            if conn is not None:
                if conn.closed or conn.broken or conn.info.transaction_status != 0:  # 0: idle
                    try:
                        conn.close()
                    except Exception:
                        pass
                else:
                    with self._lock:
                        keep = len(self._idle) < self.size
                        if keep:
                            self._idle.append((conn, time.monotonic()))
                    if not keep:
                        try:
                            conn.close()
                        except Exception:
                            pass

    def close(self) -> None:
        with self._lock:
            idle, self._idle = self._idle, []
        for conn, _ in idle:
            try:
                conn.close()
            except Exception:
                pass


@contextmanager
def _begin(pool: Any, sql: str) -> Iterator[Any]:
    """A pooled connection with ``sql`` (BEGIN ...) already run on it."""
    if isinstance(pool, InlinePool):
        with pool.connection(begin=sql) as conn:
            yield conn
        return
    with pool.connection() as conn:
        conn.execute(sql)
        yield conn


def _inline_pool_wanted() -> bool:
    mode = os.environ.get("FAIREWALL_DB_POOL_MODE", "").strip().lower()
    if mode in ("inline", "threads"):
        return mode == "inline"
    return bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


def _pool(url: str) -> Any:
    """One small connection pool per database URL, shared by every store on it.

    The smallest Cloud SQL tier allows 25 connections in total, so the pool is
    capped (FAIREWALL_DB_POOL_SIZE, default 5) rather than one per thread.
    """
    with _POOLS_LOCK:
        pool = _POOLS.get(url)
        if isinstance(pool, InlinePool) and pool.pid != os.getpid():
            pool = None  # forked or restored into a new process: old sockets are not ours
        if pool is None and _inline_pool_wanted():
            kwargs = {"autocommit": True, "row_factory": _pg_row_factory}
            if _behind_pooler(url):
                kwargs["prepare_threshold"] = None
            pool = InlinePool(url, int(os.environ.get("FAIREWALL_DB_POOL_SIZE", "5")), kwargs)
            _POOLS[url] = pool
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
            with _begin(_pool(self.location), "BEGIN; " + _pg_timeouts()) as conn:
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
            with _begin(_pool(self.location), 'BEGIN; %s SET LOCAL search_path TO "%s"; '
                        'SELECT pg_advisory_xact_lock(%d)'
                        % (_pg_timeouts(), self.schema, self._key_for(lock))) as conn:
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
