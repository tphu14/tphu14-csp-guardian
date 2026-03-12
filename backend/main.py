# CSP Guardian v3 – main.py
# Full monitoring: Prometheus middleware, Sentry init, structured logging

import os, time, logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv

load_dotenv()

from db import init_db
from routers import analyze_router, violations_router, history_router, monitoring_router
from services import notifier, get_active_provider, init_sentry
from services.metrics import http_requests_total, http_request_duration_seconds
from security import get_allowed_origins, verify_api_key

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("csp-guardian")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing database…")
    init_db()

    # Init Sentry (no-op if SENTRY_DSN not set)
    init_sentry()

    provider = get_active_provider()
    auth_on  = bool(os.environ.get("CSP_GUARDIAN_API_KEY", ""))
    logger.info(f"LLM={provider or 'NONE'} | Auth={'on' if auth_on else 'off (dev)'}")
    logger.info("CSP Guardian v3 ready 🛡️")
    yield
    logger.info("Shutting down")


limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="CSP Guardian API v3",
    description="AI-powered CSP builder – Multi-LLM · Database · Real-time · Monitoring",
    version="3.0.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-API-Key"],
)

# ── Prometheus HTTP instrumentation middleware ─────────────────────────────────
@app.middleware("http")
async def prometheus_and_timing(request: Request, call_next):
    start    = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start

    # Normalize path (strip dynamic IDs to avoid cardinality explosion)
    path = request.url.path
    for segment in path.split("/"):
        if segment.isdigit():
            path = path.replace(segment, "{id}", 1)

    http_requests_total.labels(
        method=request.method,
        endpoint=path,
        status_code=response.status_code,
    ).inc()
    http_request_duration_seconds.labels(
        method=request.method,
        endpoint=path,
    ).observe(duration)

    response.headers["X-Response-Time"] = f"{duration*1000:.1f}ms"
    return response


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(analyze_router,    tags=["Analysis"],   dependencies=[Depends(verify_api_key)])
app.include_router(violations_router, tags=["Violations"])
app.include_router(history_router,    tags=["History"],    dependencies=[Depends(verify_api_key)])
app.include_router(monitoring_router, tags=["Monitoring"])  # /metrics, /metrics/summary

# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws/violations")
async def ws_violations(websocket: WebSocket, domain: str = Query(None)):
    await notifier.connect(websocket, domain)
    try:
        while True:
            if await websocket.receive_text() == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        notifier.disconnect(websocket, domain)

# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health():
    from services.sentry_service import is_enabled as sentry_on
    return {
        "status":       "ok",
        "version":      "3.0.0",
        "llm_provider": get_active_provider() or "not configured",
        "ws_clients":   notifier.connection_count(),
        "auth_enabled": bool(os.environ.get("CSP_GUARDIAN_API_KEY", "")),
        "sentry":       sentry_on(),
        "timestamp":    time.time(),
    }