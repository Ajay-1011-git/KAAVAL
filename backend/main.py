# backend/main.py — Stage 0
#
# App wiring only. Routers are mounted here; their actual logic lives in
# each module's own package (backend/gateway/, backend/radar/,
# backend/guardian/, backend/chronicle/). Owned by Rohith (gateway core) —
# see KAAVAL_Team_Integration_Plan.md §1.

from contextlib import asynccontextmanager

from fastapi import FastAPI

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


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


app.include_router(events_stream_router)
app.include_router(webauthn_router, tags=["gateway"])
app.include_router(nonce_router, tags=["gateway"])
app.include_router(demo_app_router, tags=["demo-app"])
# Radar and Guardian routers declare their own "/radar" and "/guardian"
# prefixes (backend/radar/routes.py, backend/guardian/routes.py), so they are
# mounted bare here — adding a prefix again would yield /radar/radar/report.
app.include_router(radar_router, tags=["radar"])
app.include_router(guardian_router, tags=["guardian"])
app.include_router(chronicle_router, prefix="/chronicle", tags=["chronicle"])
