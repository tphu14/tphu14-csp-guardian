# CSP Guardian v3 – routers/monitoring.py
# GET /metrics  – Prometheus scrape endpoint
# GET /metrics/summary – Human-readable dashboard data

import time
import logging
from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from sqlalchemy.orm import Session
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from db import get_db
from services.metrics import (
    update_db_gauges, active_ws_connections,
    analyze_requests_total, violation_reports_total,
    http_requests_total, llm_errors_total,
)
from services.sentry_service import is_enabled as sentry_enabled
from services import notifier, get_active_provider

logger = logging.getLogger("csp-guardian.monitoring")
router = APIRouter()


# ── GET /metrics  (Prometheus format) ────────────────────────────────────────
@router.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
async def prometheus_metrics(db: Session = Depends(get_db)):
    """
    Prometheus scrape endpoint.
    Add to prometheus.yml:
      - job_name: 'csp-guardian'
        static_configs:
          - targets: ['localhost:8000']
        metrics_path: /metrics
    """
    # Update live gauges before scraping
    active_ws_connections.set(notifier.connection_count())
    update_db_gauges(db)

    return PlainTextResponse(
        content=generate_latest().decode("utf-8"),
        media_type=CONTENT_TYPE_LATEST,
    )


# ── GET /metrics/summary  (human-readable dashboard) ─────────────────────────
@router.get("/metrics/summary", tags=["Monitoring"])
async def metrics_summary(db: Session = Depends(get_db)):
    """
    Human-readable metrics summary.
    Used by the popup's monitoring dashboard.
    """
    from db.models import AnalysisRecord, ViolationReport
    from sqlalchemy import func, desc

    # DB stats
    total_analyses   = db.query(func.count(AnalysisRecord.id)).scalar() or 0
    total_violations = db.query(func.count(ViolationReport.id)).scalar() or 0
    avg_score        = db.query(func.avg(AnalysisRecord.risk_score)).scalar() or 0.0

    # Risk level breakdown
    risk_breakdown = dict(
        db.query(AnalysisRecord.risk_level, func.count(AnalysisRecord.id))
          .group_by(AnalysisRecord.risk_level).all()
    )

    # Top violated directives
    top_directives = [
        {"directive": d, "count": c}
        for d, c in db.query(
            ViolationReport.violated_directive,
            func.count(ViolationReport.id).label("c"),
        ).group_by(ViolationReport.violated_directive)
         .order_by(desc("c")).limit(5).all()
    ]

    # Recent analyses (last 5)
    recent = [
        r.to_dict() for r in
        db.query(AnalysisRecord)
          .order_by(desc(AnalysisRecord.created_at))
          .limit(5).all()
    ]

    # Top risky domains
    risky_domains = [
        {"domain": d, "avg_score": round(float(s), 1), "count": c}
        for d, s, c in db.query(
            AnalysisRecord.domain,
            func.avg(AnalysisRecord.risk_score).label("avg_score"),
            func.count(AnalysisRecord.id).label("count"),
        ).group_by(AnalysisRecord.domain)
         .order_by(desc("avg_score")).limit(5).all()
    ]

    return {
        "summary": {
            "total_analyses":   total_analyses,
            "total_violations": total_violations,
            "avg_risk_score":   round(float(avg_score), 1),
            "ws_connections":   notifier.connection_count(),
            "llm_provider":     get_active_provider() or "none",
            "sentry_enabled":   sentry_enabled(),
        },
        "risk_breakdown":   risk_breakdown,
        "top_directives":   top_directives,
        "risky_domains":    risky_domains,
        "recent_analyses":  recent,
    }


# ── GET /metrics/health/detailed  ─────────────────────────────────────────────
@router.get("/metrics/health/detailed", tags=["Monitoring"])
async def health_detailed(db: Session = Depends(get_db)):
    """Extended health check with component status."""
    components = {}

    # Database
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        components["database"] = {"status": "ok", "type": "sqlite"}
    except Exception as e:
        components["database"] = {"status": "error", "error": str(e)}

    # LLM provider
    provider = get_active_provider()
    components["llm"] = {
        "status":   "ok" if provider else "unconfigured",
        "provider": provider or "none",
    }

    # WebSocket
    components["websocket"] = {
        "status":      "ok",
        "connections": notifier.connection_count(),
    }

    # Sentry
    components["sentry"] = {
        "status": "ok" if sentry_enabled() else "disabled",
    }

    overall = "ok" if all(
        c["status"] == "ok" for c in components.values()
        if c["status"] != "disabled"
    ) else "degraded"

    return {
        "status":     overall,
        "version":    "3.0.0",
        "components": components,
        "timestamp":  time.time(),
    }