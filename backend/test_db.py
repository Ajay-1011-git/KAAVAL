# backend/test_db.py
#
# FIX-6b's VERIFY: "a test that sets DB_PATH to a temp file *after* importing
# db.py successfully uses the temp file, not whatever was resolved at import
# time."
#
# This is the regression guard for the import-time-resolution bug. Before the
# fix, backend/db.py computed DB_PATH once at module import, so the first
# module in a process to import it fixed the database for everything after —
# and a later DATABASE_URL change was silently ignored.

import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

from backend.db import get_connection, get_db_path, init_db


def test_database_url_set_after_import_is_honoured():
    """The whole point of FIX-6b: a later override actually takes effect."""
    temp_dir = tempfile.mkdtemp(prefix="kaaval_test_db_late_")
    late_path = os.path.join(temp_dir, "late.db").replace("\\", "/")

    before = get_db_path()

    with patch.dict(os.environ, {"DATABASE_URL": f"sqlite:///{late_path}"}, clear=False):
        assert get_db_path() == late_path, "the override was ignored"
        init_db()
        conn = get_connection()
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        finally:
            conn.close()

    # The schema really landed in the temp file, not in the session database.
    assert {"events", "sessions"} <= tables
    assert Path(late_path).exists()

    # And the override is scoped: the path reverts once it is removed.
    assert get_db_path() == before


def test_a_plain_path_without_the_sqlite_prefix_is_accepted():
    temp_dir = tempfile.mkdtemp(prefix="kaaval_test_db_plain_")
    plain_path = os.path.join(temp_dir, "plain.db").replace("\\", "/")

    with patch.dict(os.environ, {"DATABASE_URL": plain_path}, clear=False):
        assert get_db_path() == plain_path
        init_db()

    assert Path(plain_path).exists()


def test_an_unset_database_url_falls_back_to_the_documented_default():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("DATABASE_URL", None)
        assert get_db_path() == "./kaaval.db"


def test_writes_land_in_the_database_the_override_names():
    """Guards the specific failure mode: writing to the wrong database."""
    temp_dir = tempfile.mkdtemp(prefix="kaaval_test_db_write_")
    target = os.path.join(temp_dir, "target.db").replace("\\", "/")

    with patch.dict(os.environ, {"DATABASE_URL": f"sqlite:///{target}"}, clear=False):
        init_db()
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO sessions (session_id, user_id, public_key_jwk,"
                " credential_id, is_active, last_sequence, created_at)"
                " VALUES ('late-1', 'u', '{}', 'c', 1, 0, 'now')"
            )
            conn.commit()
        finally:
            conn.close()

    # Read the file directly, outside the app's own helpers.
    raw = sqlite3.connect(target)
    try:
        rows = raw.execute(
            "SELECT session_id FROM sessions WHERE session_id = 'late-1'"
        ).fetchall()
    finally:
        raw.close()
    assert rows == [("late-1",)]
