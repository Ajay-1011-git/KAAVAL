# MINIMAL STAND-IN for Rohith's Stage 0 scaffold (Team Integration Plan §3).
# App wiring. Radar and Guardian routers are real; gateway/chronicle are
# empty stubs owned by Rohith/Sai respectively.

from fastapi import FastAPI

from backend.db import init_db

app = FastAPI(title="KAAVAL Backend")


@app.on_event("startup")
def on_startup() -> None:
    init_db()


# Routers are included as each task lands (radar: T-AD.4, guardian: T-AD.8).
# gateway/chronicle routers are Rohith's/Sai's to wire in on their branches.
