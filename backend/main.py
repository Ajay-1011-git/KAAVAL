# MINIMAL STAND-IN for Rohith's Stage 0 scaffold (Team Integration Plan §3).
# App wiring. Radar and Guardian routers are real; gateway/chronicle are
# empty stubs owned by Rohith/Sai respectively.

from fastapi import FastAPI

from backend.db import init_db

app = FastAPI(title="KAAVAL Backend")


@app.on_event("startup")
def on_startup() -> None:
    init_db()


from backend.radar.routes import router as radar_router  # noqa: E402
from backend.guardian.routes import router as guardian_router  # noqa: E402

app.include_router(radar_router)
app.include_router(guardian_router)

# gateway/chronicle routers are Rohith's/Sai's to wire in on their branches.
