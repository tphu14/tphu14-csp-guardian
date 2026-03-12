# CSP Guardian v3 – routers/analyze.py
# POST /analyze – instrumented with Prometheus metrics + Sentry

import time
import logging
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from pydantic import BaseModel

from db import get_db, AnalysisRecord
from services import (
    analyze_csp_with_llm, notifier,
    analyze_requests_total, analyze_duration_seconds,
    llm_response_duration_seconds, llm_errors_total,
    capture_exception,
)
from security import sanitize_domain, validate_llm_response

logger = logging.getLogger("csp-guardian.analyze")
router  = APIRouter()
limiter = Limiter(key_func=get_remote_address)


class ResourceSummary(BaseModel):
    script_domains:   list[str] = []
    style_domains:    list[str] = []
    connect_domains:  list[str] = []
    inline_script:    bool = False
    eval_detected:    bool = False
    wildcard_used:    bool = False
    wildcard_domains: list[str] = []


class AnalyzeRequest(BaseModel):
    domain:           str
    resource_summary: ResourceSummary
    generated_csp:    str
    risk_score:       int
    risk_level:       str
    issues:           list[str] = []
    resource_stats:   dict = {}


@router.post("/analyze")
@limiter.limit("20/minute")
async def analyze(
    request: Request,
    body:    AnalyzeRequest,
    db:      Session = Depends(get_db),
):
    start = time.perf_counter()
    logger.info(f"Analyze: domain={body.domain!r} risk={body.risk_score} ({body.risk_level})")

    body.domain = sanitize_domain(body.domain)

    provider = "unknown"
    try:
        llm_start = time.perf_counter()
        result, provider = await analyze_csp_with_llm(body)
        llm_dur = time.perf_counter() - llm_start
        llm_response_duration_seconds.labels(provider=provider).observe(llm_dur)
        logger.info(f"LLM ({provider}) responded in {llm_dur:.2f}s")

    except ValueError as e:
        analyze_requests_total.labels(status="error", risk_level=body.risk_level, llm_provider="none").inc()
        raise HTTPException(503, str(e))
    except Exception as e:
        logger.error(f"LLM failed: {e}", exc_info=True)
        llm_errors_total.labels(provider=provider, error_type=type(e).__name__).inc()
        capture_exception(e, context={"domain": body.domain, "provider": provider})
        raise HTTPException(502, f"LLM analysis failed: {e}")

    result = validate_llm_response(result)

    record = AnalysisRecord(
        domain          = body.domain,
        risk_score      = body.risk_score,
        risk_level      = body.risk_level,
        generated_csp   = body.generated_csp,
        hardened_csp    = result.get("hardened_csp"),
        issues          = body.issues,
        recommendations = result.get("recommendations", []),
        resource_stats  = body.resource_stats,
        llm_provider    = provider,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    logger.info(f"Saved analysis #{record.id} for {body.domain!r} via {provider}")

    total_dur = time.perf_counter() - start
    analyze_duration_seconds.labels(llm_provider=provider).observe(total_dur)
    analyze_requests_total.labels(
        status="success", risk_level=body.risk_level, llm_provider=provider
    ).inc()

    await notifier.broadcast_analysis(record.to_dict())

    return JSONResponse({
        **result,
        "analysis_id": record.id,
        "provider":    provider,
        "duration_ms": round(total_dur * 1000, 1),
    })