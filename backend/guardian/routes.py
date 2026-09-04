# backend/guardian/routes.py — Stage 0 stub
#
# Owned by Adhi (feature/radar-guardian). Empty placeholder router so
# backend/main.py has something real to mount from Stage 0 onward; Adhi's
# branch replaces its contents (POST /guardian/oauth/evaluate,
# /guardian/device-code/evaluate, per TRD §5 and T-AD.8). Do not build out
# Guardian's actual logic here.

from fastapi import APIRouter

router = APIRouter()
