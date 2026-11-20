"""Shared test setup.

Postgres mode: set FAIREWALL_TEST_POSTGRES_URL to a database the tests may
create and drop schemas in, e.g.

    FAIREWALL_TEST_POSTGRES_URL=postgresql://fairewall_test:fairewall-test@127.0.0.1:5432/fairewall_test \
        python -m pytest tests/test_durable_actions.py tests/test_refund_desk.py tests/test_control_plane.py

Every store a test opens with a SQLite file path (or ":memory:") then runs on
Postgres instead, in a fresh schema of its own, so the same tests prove both
engines. The schemas are dropped after each test.
"""
import hashlib
import os
import uuid

import pytest

PG_URL = os.environ.get("FAIREWALL_TEST_POSTGRES_URL")


@pytest.fixture(autouse=True)
def _stores_on_postgres(monkeypatch):
    if not PG_URL:
        yield
        return
    from fairewall import db as fdb

    original = fdb.resolve
    created = set()
    run = uuid.uuid4().hex[:8]

    def resolve(target, schema):
        if fdb.is_postgres(target):
            return original(target, schema)
        key = uuid.uuid4().hex if str(target) == ":memory:" else str(target)
        name = "t%s_%s_%s" % (run, hashlib.sha1(key.encode()).hexdigest()[:10], schema)
        created.add(name[:63])
        return "postgres", PG_URL, name[:63]

    monkeypatch.setattr(fdb, "resolve", resolve)
    yield
    with fdb._pool(PG_URL).connection() as conn:
        for name in created:
            conn.execute('DROP SCHEMA IF EXISTS "%s" CASCADE' % name)


def pytest_sessionfinish(session, exitstatus):
    if PG_URL:
        from fairewall.db import close_pools
        close_pools()
