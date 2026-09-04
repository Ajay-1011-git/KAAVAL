# backend/conftest.py
#
# One temp database for the whole test session, chosen before any test module
# is imported (pytest loads conftest first).
#
# Why this exists: backend/db.py used to resolve DB_PATH at import time, so
# whichever test module imported it first silently fixed the path for every
# other module in the process. That accident is what made the suite pass.
# get_db_path() is now lazy (FIX-6b), which means a module setting
# DATABASE_URL at import time would instead have the LAST import win, and
# modules would read a database whose schema was created somewhere else.
#
# So the sharing is now explicit rather than accidental: this file picks the
# path once, and each test module uses os.environ.setdefault so it defers to
# it. Test modules keep using unique session/event ids to stay isolated
# inside that shared database — the same isolation strategy they always had.
#
# A test that deliberately wants its own database can still set DATABASE_URL
# at any point and call init_db(); lazy resolution is precisely what makes
# that work now (see test_db.py).

import os
import tempfile

_SESSION_DB_DIR = tempfile.mkdtemp(prefix="kaaval_test_session_")
os.environ.setdefault(
    "DATABASE_URL", f"sqlite:///{_SESSION_DB_DIR}/test_kaaval.db".replace("\\", "/")
)
