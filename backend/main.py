# backend/main.py — Stage 0
#
# App wiring only. Routers are mounted here; their actual logic lives in
# each module's own package (backend/gateway/, backend/radar/,
# backend/guardian/, backend/chronicle/). Owned by Rohith (gateway core) —
# see KAAVAL_Team_Integration_Plan.md §1.

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.db import init_db
from backend.gateway.events_stream import router as events_stream_router
from backend.gateway.webauthn_routes import router as webauthn_router
from backend.gateway.nonce import router as nonce_router
from backend.gateway.demo_app_routes import router as demo_app_router
from backend.radar.routes import router as radar_router
from backend.guardian.routes import router as guardian_router
from backend.chronicle.routes import router as chronicle_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="KAAVAL backend", lifespan=lifespan)

# The dashboard (Next.js, :3000) reads /radar/report, /events/stream and
# /chronicle/explain from this app (:8000) — a different origin, so without
# CORS every dashboard fetch fails and the panels sit empty. Origins are
# configurable; the default is the dashboard's local dev origin only, never
# a wildcard. Chronicle's X-KAAVAL-Chronicle-Mode header is exposed so the
# dashboard can show whether an explanation was live or the fallback.
DASHBOARD_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "DASHBOARD_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=DASHBOARD_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-KAAVAL-Chronicle-Mode"],
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


app.include_router(events_stream_router)
app.include_router(webauthn_router, tags=["gateway"])
app.include_router(nonce_router, tags=["gateway"])
app.include_router(demo_app_router, tags=["demo-app"])
# The Radar, Guardian and Chronicle routers each declare their own prefix
# ("/radar", "/guardian", "/chronicle") in their own module, so they are
# mounted bare here — adding a prefix again would yield /radar/radar/report.
app.include_router(radar_router, tags=["radar"])
app.include_router(guardian_router, tags=["guardian"])
app.include_router(chronicle_router, tags=["chronicle"])
