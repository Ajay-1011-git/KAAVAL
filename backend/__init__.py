# backend/__init__.py
#
# Load the root .env before any backend module reads os.environ.
#
# Several modules resolve configuration at IMPORT time, not call time —
# backend/db.py freezes DB_PATH, backend/gateway/verify.py reads the
# freshness window, backend/gateway/nonce.py the nonce TTL. Importing any
# of them runs this package initializer first, so this is the one place
# that is guaranteed to execute before any of those reads.
#
# .env is gitignored and never committed; .env.example is the tracked
# template. Real environment variables always win over the file
# (override=False), so container/CI configuration is not silently
# overwritten by a developer's local file.

from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dotenv is in backend/requirements.txt
    pass
else:
    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
