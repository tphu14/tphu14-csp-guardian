# CSP Guardian v2 – routers/history.py
# Analysis history CRUD endpoints

import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from db import get_db, AnalysisRecord

logger = logging.getLogger("csp-guardian.history")
router = APIRouter()


# ── GET /history ──────────────────────────────────────────────────────────────
@router.get("/history")
async def list_history(
    domain: str  = Query(None, description="Filter by domain"),
    limit:  int  = Query(20, ge=1, le=100),
    offset: int  = Query(0, ge=0),
    db: Session  = Depends(get_db),
):
    """List analysis history, newest first."""
    q = db.query(AnalysisRecord).order_by(desc(AnalysisRecord.created_at))
    if domain:
        q = q.filter(AnalysisRecord.domain == domain)
    total = q.count()
    items = q.offset(offset).limit(limit).all()
    return {
        "total":  total,
        "offset": offset,
        "limit":  limit,
        "items":  [r.to_dict() for r in items],
    }


# ── GET /history/{id} ─────────────────────────────────────────────────────────
@router.get("/history/{record_id}")
async def get_history(record_id: int, db: Session = Depends(get_db)):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == record_id).first()
    if not record:
        raise HTTPException(404, f"Analysis #{record_id} not found")
    data = record.to_dict()
    data["violations"] = [v.to_dict() for v in record.violations]
    return data


# ── DELETE /history/{id} ──────────────────────────────────────────────────────
@router.delete("/history/{record_id}")
async def delete_history(record_id: int, db: Session = Depends(get_db)):
    record = db.query(AnalysisRecord).filter(AnalysisRecord.id == record_id).first()
    if not record:
        raise HTTPException(404, f"Analysis #{record_id} not found")
    db.delete(record)
    db.commit()
    return {"ok": True, "deleted_id": record_id}


# ── GET /history/stats/summary ────────────────────────────────────────────────
@router.get("/history/stats/summary")
async def history_stats(db: Session = Depends(get_db)):
    """Overall stats across all analyses."""
    total = db.query(func.count(AnalysisRecord.id)).scalar()
    avg_score = db.query(func.avg(AnalysisRecord.risk_score)).scalar()
    by_level = (
        db.query(AnalysisRecord.risk_level, func.count(AnalysisRecord.id))
        .group_by(AnalysisRecord.risk_level)
        .all()
    )
    top_domains = (
        db.query(AnalysisRecord.domain, func.count(AnalysisRecord.id).label("n"))
        .group_by(AnalysisRecord.domain)
        .order_by(desc("n"))
        .limit(5)
        .all()
    )
    return {
        "total_analyses":    total,
        "avg_risk_score":    round(float(avg_score or 0), 1),
        "by_risk_level":     {r[0]: r[1] for r in by_level},
        "top_domains":       [{"domain": d[0], "count": d[1]} for d in top_domains],
    }