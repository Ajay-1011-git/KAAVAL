# backend/gateway/test_events_stream.py
#
# T-RO.7 VERIFY: a newly written event appears on the stream within a
# bounded delay, and a since_event_id cursor resumes without replaying
# history (TRD §7).
#
# WHY THESE TESTS DRIVE THE GENERATOR DIRECTLY: /events/stream is an
# infinite response by design, so consuming it through TestClient hangs
# the suite at teardown — the ASGI task never finishes, so closing the
# response never returns. (Confirmed the hard way.) The stream's real
# logic — cursor resolution, frame shape, live delivery — is exercised
# here against the real database, and the genuine end-to-end HTTP check
# is a live curl against uvicorn, which is what the build document's
# VERIFY explicitly allows ("test or curl session").
#
# DATABASE_URL is set before backend.db is first imported in this process
# — see the note in test_webauthn_routes.py.

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone

_TEST_DB_DIR = tempfile.mkdtemp(prefix="kaaval_test_stream_")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TEST_DB_DIR}/test_kaaval.db")

import anyio  # noqa: E402
import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.contracts import SecurityEvent  # noqa: E402
from backend.db import init_db  # noqa: E402
from backend.events import write_event  # noqa: E402
from backend.gateway.events_stream import (  # noqa: E402
    EVENT_PAGE_SIZE,
    UnknownCursor,
    event_stream,
    event_to_frame,
    resolve_cursor,
    router,
)

init_db()

app = FastAPI()
app.include_router(router)
client = TestClient(app)

DEADLINE_S = 5.0


def _write(reason: str) -> SecurityEvent:
    return write_event(
        SecurityEvent(
            event_id=uuid.uuid4().hex,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            event_type="request_blocked",
            session_id="sess-" + reason,
            user_id="user-1",
            application_id=None,
            reason=reason,
            detail={"k": "v"},
            severity="blocked",
        )
    )


def _collect(
    cursor: int,
    count: int,
    deadline_s: float = DEADLINE_S,
    stop_on_event: str | None = None,
) -> list[dict]:
    """Pull frames off the live generator, bounded by a deadline.

    Stops after `count` frames, or — when `stop_on_event` is given — as soon
    as a frame of that kind arrives, whichever comes first. The generator is
    infinite by design, so every caller needs one of the two bounds.
    """

    async def run() -> list[dict]:
        frames: list[dict] = []
        with anyio.fail_after(deadline_s):
            async for frame in event_stream(cursor, poll_interval=0.05):
                frames.append(frame)
                if stop_on_event is not None:
                    if frame["event"] == stop_on_event:
                        break
                elif len(frames) >= count:
                    break
        return frames

    return anyio.run(run)


# --- the literal T-RO.7 VERIFY ----------------------------------------

def test_an_event_written_after_the_cursor_appears_on_the_stream():
    baseline_cursor = _current_max_rowid()
    written = _write("appears_live")

    frames = _collect(baseline_cursor, count=1)

    assert len(frames) == 1, "no event arrived on the stream"
    payload = json.loads(frames[0]["data"])
    assert payload["event_id"] == written.event_id
    assert payload["reason"] == "appears_live"
    print("LIVE FRAME:", frames[0]["event"], payload["event_type"], "/", payload["reason"])


def test_an_event_written_while_the_stream_is_idle_is_delivered_within_the_poll_interval():
    """The stream must pick up rows written after it started polling, not
    only rows that already existed when it connected.

    The stream opens on an empty backlog here, so the first frame is the
    stream_synced boundary marker; this test is about the security_event
    that follows it.
    """
    cursor = _current_max_rowid()
    written: dict = {}

    async def run():
        frames = []
        with anyio.fail_after(DEADLINE_S):
            async with anyio.create_task_group() as tg:

                async def write_later():
                    await anyio.sleep(0.2)  # stream is already polling by now
                    written["event"] = _write("written_while_idle")

                tg.start_soon(write_later)
                async for frame in event_stream(cursor, poll_interval=0.05):
                    frames.append(frame)
                    if frame["event"] == "security_event":
                        break
        return frames

    frames = anyio.run(run)

    delivered = [f for f in frames if f["event"] == "security_event"]
    assert len(delivered) == 1
    assert json.loads(delivered[0]["data"])["event_id"] == written["event"].event_id


# --- cursor semantics --------------------------------------------------

def test_since_event_id_resumes_after_that_event_without_replaying_history():
    first = _write("cursor_first")
    second = _write("cursor_second")
    third = _write("cursor_third")

    frames = _collect(resolve_cursor(second.event_id), count=1)

    reasons = [json.loads(f["data"])["reason"] for f in frames]
    assert reasons == ["cursor_third"], f"expected only events after the cursor, got {reasons}"
    assert first.event_id not in [f["id"] for f in frames]
    assert third.event_id == frames[0]["id"]
    print("CURSOR RESUME: after", second.reason, "->", reasons)


def test_no_cursor_starts_from_the_beginning():
    assert resolve_cursor(None) == 0
    assert resolve_cursor(None, None) == 0


def test_last_event_id_header_is_honoured_the_way_a_browser_sends_it():
    marker = _write("header_marker")

    assert resolve_cursor(None, marker.event_id) == resolve_cursor(marker.event_id)


def test_an_explicit_query_cursor_wins_over_the_header():
    older = _write("precedence_older")
    newer = _write("precedence_newer")

    # Browser replays a stale Last-Event-ID; the caller explicitly asked
    # for a newer position. The explicit request must win.
    assert resolve_cursor(newer.event_id, older.event_id) == resolve_cursor(newer.event_id)
    assert resolve_cursor(newer.event_id, older.event_id) > resolve_cursor(older.event_id)


def test_an_unknown_cursor_is_rejected_rather_than_guessed():
    with pytest.raises(UnknownCursor):
        resolve_cursor("not-a-real-event-id")


def test_the_endpoint_reports_an_unknown_cursor_as_a_400():
    """Checked over real HTTP: this response is finite, so unlike the
    stream itself it is safe to read through TestClient."""
    response = client.get("/events/stream?since_event_id=not-a-real-event-id")

    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "unknown_since_event_id"
    print("UNKNOWN CURSOR:", response.status_code, response.json())


# --- frame shape -------------------------------------------------------

def test_each_frame_carries_its_event_id_so_a_browser_can_resume():
    event = _write("carries_id")

    frame = event_to_frame(event)

    assert frame["event"] == "security_event"
    assert frame["id"] == event.event_id, "SSE id: must be the event_id, for Last-Event-ID resume"


def test_the_frame_carries_the_full_frozen_security_event_shape():
    event = _write("full_shape")

    payload = json.loads(event_to_frame(event)["data"])

    # Every field of the frozen contract (TRD §6.2) must survive the wire,
    # since Sai's dashboard and Chronicle both read this shape.
    assert set(payload) == {
        "event_id", "timestamp", "event_type", "session_id", "user_id",
        "application_id", "reason", "detail", "severity",
    }
    assert payload["event_id"] == event.event_id
    assert payload["detail"] == {"k": "v"}
    print("STREAMED PAYLOAD:", payload)


def _current_max_rowid() -> int:
    from backend.db import get_connection

    conn = get_connection()
    try:
        row = conn.execute("SELECT COALESCE(MAX(rowid), 0) AS m FROM events").fetchone()
    finally:
        conn.close()
    return row["m"]


# --- backlog / live boundary ------------------------------------------
#
# A browser's first EventSource connection carries no Last-Event-ID, so the
# cursor is 0 and the stream correctly replays the recorded history. The
# dashboard needs that history for its feed, but it must not mistake a
# replayed event for one happening now: without a boundary marker the
# counters climb from zero on every reload and the attack banner fires for
# events that are hours old.

def test_the_stream_marks_where_the_replayed_backlog_ends():
    _write("backlog_one")
    _write("backlog_two")

    frames = _collect(0, count=1, stop_on_event="stream_synced")

    kinds = [f["event"] for f in frames]
    assert "stream_synced" in kinds, (
        "the stream never told the client where replayed history ends"
    )

    synced_index = kinds.index("stream_synced")
    assert set(kinds[:synced_index]) == {"security_event"}, (
        "the sync marker must come after the backlog, not interleaved with it"
    )
    assert kinds.count("stream_synced") == 1, "the boundary is announced exactly once"

    payload = json.loads(frames[synced_index]["data"])
    assert payload["replayed"] == synced_index, (
        f"replayed count {payload['replayed']} disagrees with the "
        f"{synced_index} events actually sent before it"
    )
    print("BACKLOG BOUNDARY:", kinds[:synced_index + 1][-3:], "replayed =", payload["replayed"])


def test_the_sync_marker_carries_no_id_so_a_browser_cannot_resume_from_it():
    """EventSource echoes the last `id:` it saw as Last-Event-ID. If the
    sync marker carried one, the next reconnect would send an event_id that
    is not in the events table and resolve_cursor would reject it with a
    400, breaking reconnection entirely."""
    _write("sync_marker_id")

    frames = _collect(0, count=1, stop_on_event="stream_synced")
    marker = next(f for f in frames if f["event"] == "stream_synced")

    assert "id" not in marker, "the sync marker must not set an SSE id:"


def test_a_backlog_larger_than_one_page_is_fully_drained_before_syncing():
    """get_events_since pages at EVENT_PAGE_SIZE. A history longer than one
    page must still be replayed in full before the boundary is announced,
    and without waiting a poll interval between pages."""
    for i in range(EVENT_PAGE_SIZE + 5):
        _write(f"page_{i}")

    frames = _collect(0, count=1, stop_on_event="stream_synced", deadline_s=10.0)

    kinds = [f["event"] for f in frames]
    synced_index = kinds.index("stream_synced")
    assert synced_index > EVENT_PAGE_SIZE, (
        f"only {synced_index} events replayed before the boundary; a backlog "
        f"of more than one {EVENT_PAGE_SIZE}-row page was cut short"
    )


def test_events_written_after_the_sync_marker_still_arrive_live():
    """The boundary must not end the stream."""
    cursor = _current_max_rowid()
    written: dict = {}

    async def run():
        frames = []
        with anyio.fail_after(DEADLINE_S):
            async with anyio.create_task_group() as tg:

                async def write_later():
                    await anyio.sleep(0.3)
                    written["event"] = _write("after_sync")

                tg.start_soon(write_later)
                async for frame in event_stream(cursor, poll_interval=0.05):
                    frames.append(frame)
                    if frame["event"] == "security_event":
                        break
        return frames

    frames = anyio.run(run)

    assert frames[0]["event"] == "stream_synced", "an empty backlog syncs immediately"
    assert json.loads(frames[-1]["data"])["event_id"] == written["event"].event_id
    print("LIVE AFTER SYNC:", [f["event"] for f in frames])
