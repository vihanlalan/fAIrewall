"""The storage layer: same behaviour on SQLite and (with FAIREWALL_TEST_POSTGRES_URL) Postgres."""
import os
import threading
import time

import pytest

from fairewall.db import Database, Row, is_postgres, pg_ddl, redact_url, with_schema

PG = bool(os.environ.get("FAIREWALL_TEST_POSTGRES_URL"))


def make(tmp_path, name="t.sqlite"):
    db = Database(str(tmp_path / name), schema="fairewall_test")
    db.create("""CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v INTEGER NOT NULL, at REAL);
                 CREATE TABLE IF NOT EXISTS log (id INTEGER PRIMARY KEY AUTOINCREMENT, msg TEXT)""")
    return db


def test_dialect_matches_the_test_mode(tmp_path):
    # Guards the Postgres run: a silent fallback to SQLite would prove nothing.
    assert make(tmp_path).dialect == ("postgres" if PG else "sqlite")


def test_rows_read_by_name_and_position(tmp_path):
    db = make(tmp_path)
    with db.transaction() as tx:
        tx.execute("INSERT INTO kv VALUES (?,?,?)", ("a", 1, 1.5))
        row = tx.execute("SELECT k, v FROM kv").fetchone()
    assert row["k"] == "a" and row[1] == 1 and dict(row) == {"k": "a", "v": 1}


def test_upsert_and_ignore_are_portable(tmp_path):
    db = make(tmp_path)
    with db.transaction() as tx:
        tx.execute("INSERT INTO kv VALUES (?,?,?) ON CONFLICT(k) DO UPDATE SET v=kv.v+excluded.v", ("a", 1, 0))
        tx.execute("INSERT INTO kv VALUES (?,?,?) ON CONFLICT(k) DO UPDATE SET v=kv.v+excluded.v", ("a", 2, 0))
        ignored = tx.execute("INSERT INTO kv VALUES (?,?,?) ON CONFLICT DO NOTHING", ("a", 9, 0))
        assert ignored.rowcount == 0
        assert tx.execute("SELECT v FROM kv WHERE k=?", ("a",)).fetchone()[0] == 3


def test_timestamps_keep_full_precision(tmp_path):
    # REAL is 4-byte on Postgres; the layer maps it to DOUBLE PRECISION.
    db = make(tmp_path)
    now = time.time()
    with db.transaction() as tx:
        tx.execute("INSERT INTO kv VALUES (?,?,?)", ("t", 0, now))
        assert tx.execute("SELECT at FROM kv").fetchone()[0] == now


def test_error_rolls_back(tmp_path):
    db = make(tmp_path)
    with pytest.raises(RuntimeError):
        with db.transaction() as tx:
            tx.execute("INSERT INTO kv VALUES (?,?,?)", ("x", 1, 0))
            raise RuntimeError("boom")
    with db.transaction() as tx:
        assert tx.execute("SELECT COUNT(*) FROM kv").fetchone()[0] == 0


def test_transactions_are_serialized(tmp_path):
    """Read-modify-write from many threads loses no update: one writer at a time."""
    db = make(tmp_path)
    with db.transaction() as tx:
        tx.execute("INSERT INTO kv VALUES (?,?,?)", ("n", 0, 0))

    def bump():
        for _ in range(10):
            with db.transaction() as tx:
                n = tx.execute("SELECT v FROM kv WHERE k='n'").fetchone()[0]
                time.sleep(0.001)
                tx.execute("UPDATE kv SET v=? WHERE k='n'", (n + 1,))

    threads = [threading.Thread(target=bump) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with db.transaction() as tx:
        assert tx.execute("SELECT v FROM kv WHERE k='n'").fetchone()[0] == 40


def test_json_text_and_insertion_order(tmp_path):
    db = make(tmp_path)
    with db.transaction() as tx:
        tx.execute("CREATE TABLE IF NOT EXISTS docs (body TEXT)")
        tx.execute("INSERT INTO docs VALUES (?)", ('{"id": "p1", "n": 2}',))
        assert tx.execute("SELECT %s FROM docs" % db.json_text("body", "id")).fetchone()[0] == "p1"
        for m in ("first", "second", "third"):
            tx.execute("INSERT INTO log (msg) VALUES (?)", (m,))
        assert [r["msg"] for r in tx.execute("SELECT msg FROM log ORDER BY id")] == ["first", "second", "third"]
    with pytest.raises(ValueError):
        db.json_text("body); DROP TABLE kv; --", "id")


def test_percent_signs_survive(tmp_path):
    db = make(tmp_path)
    with db.transaction() as tx:
        tx.execute("INSERT INTO kv VALUES (?,?,?)", ("100% sure", 1, 0))
        assert tx.execute("SELECT k FROM kv WHERE k LIKE '100%' AND v=?", (1,)).fetchone()[0] == "100% sure"


def test_url_helpers():
    url = "postgresql://app:s3cret@/fairewall?host=/cloudsql/p:asia-south1:fw"
    assert is_postgres(url) and not is_postgres("data/actions.sqlite")
    assert "s3cret" not in redact_url(url) and "***" in redact_url(url)
    assert redact_url("data/x.sqlite") == "data/x.sqlite"
    scoped = with_schema(url, "refund_ledger")
    assert scoped.endswith("schema=refund_ledger") and "host=%2Fcloudsql" in scoped
    assert with_schema(scoped, "other").count("schema=") == 1


def test_bad_schema_name_is_refused():
    with pytest.raises(ValueError):
        Database("postgresql://u:p@127.0.0.1:1/db?schema=Bad-Name", schema="x")


def test_pg_ddl_types():
    ddl = pg_ddl("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, n INTEGER, at REAL)")
    assert ddl == "CREATE TABLE t (id BIGSERIAL PRIMARY KEY, n BIGINT, at DOUBLE PRECISION)"


def test_row_is_a_plain_dict_for_json():
    import json
    assert json.dumps(Row(a=1)) == '{"a": 1}'
