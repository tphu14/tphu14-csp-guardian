# CSP Guardian v2 – routers/violations.py
# CSP Report-URI endpoint + violation history API

import logging
from urllib.parse import urlparse
from fastapi import APIRouter, Request, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc

from db import get_db, ViolationReport, AnalysisRecord
from services import notifier

logger = logging.getLogger("csp-guardian.violations")
router = APIRouter()


def extract_domain(uri: str) -> str:
    """Extract hostname from a URI."""
    try:
        return urlparse(uri).hostname or ""
    except Exception:
        return ""


# ── POST /csp-report  (browser sends violations here) ────────────────────────
@router.post("/csp-report")
async def csp_report(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Browser-native CSP report endpoint.
    Configure in CSP header:  report-uri https://your-backend/csp-report
    Or with Report-To API:    report-to csp-endpoint
    """
    try:
        body = await request.json()
    except Exception:
        # Browsers sometimes send with different content-type
        raw = await request.body()
        try:
            import json
            body = json.loads(raw)
        except Exception:
            return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)

    # Browser wraps report in "csp-report" key
    report = body.get("csp-report", body)

    document_uri  = report.get("document-uri", "")
    blocked_uri   = report.get("blocked-uri", "")
    domain        = extract_domain(document_uri) or extract_domain(blocked_uri)

    violation = ViolationReport(
        domain               = domain,
        document_uri         = document_uri[:512],
        violated_directive   = report.get("violated-directive", "")[:255],
        effective_directive  = report.get("effective-directive", "")[:255],
        blocked_uri          = blocked_uri[:512],
        original_policy      = report.get("original-policy", "")[:2000],
        disposition          = report.get("disposition", "enforce")[:20],
        status_code          = report.get("status-code"),
        source_file          = report.get("source-file", "")[:512],
        line_number          = report.get("line-number"),
        column_number        = report.get("column-number"),
    )

    db.add(violation)
    db.commit()
    db.refresh(violation)

    logger.warning(
        f"CSP VIOLATION [{domain}] "
        f"directive={violation.violated_directive!r} "
        f"blocked={blocked_uri!r}"
    )

    # Real-time WebSocket broadcast
    await notifier.broadcast_violation(violation.to_dict())

    return JSONResponse({"ok": True, "id": violation.id}, status_code=204)


# ── GET /violations  (list recent violations) ─────────────────────────────────
@router.get("/violations")
async def list_violations(
    domain:   str = Query(None, description="Filter by domain"),
    limit:    int = Query(50, ge=1, le=200),
    offset:   int = Query(0, ge=0),
    db:       Session = Depends(get_db),
):
    q = db.query(ViolationReport).order_by(desc(ViolationReport.received_at))
    if domain:
        q = q.filter(ViolationReport.domain == domain)
    total = q.count()
    items = q.offset(offset).limit(limit).all()
    return {
        "total":  total,
        "offset": offset,
        "limit":  limit,
        "items":  [v.to_dict() for v in items],
    }


# ── GET /violations/stats  (violation summary) ────────────────────────────────
@router.get("/violations/stats")
async def violation_stats(db: Session = Depends(get_db)):
    from sqlalchemy import func
    stats = (
        db.query(
            ViolationReport.violated_directive,
            func.count(ViolationReport.id).label("count"),
        )
        .group_by(ViolationReport.violated_directive)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )
    total = db.query(func.count(ViolationReport.id)).scalar()
    return {
        "total_violations": total,
        "by_directive": [{"directive": s[0], "count": s[1]} for s in stats],
    }