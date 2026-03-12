# CSP Guardian v2 – db/models.py
# SQLAlchemy ORM models

from sqlalchemy import (
    Column, Integer, String, Float, Boolean,
    DateTime, Text, JSON, ForeignKey, Index
)
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime, timezone

Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


# ── Analysis History ──────────────────────────────────────────────────────────
class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    domain        = Column(String(255), nullable=False, index=True)
    created_at    = Column(DateTime(timezone=True), default=utcnow, index=True)

    # Risk
    risk_score    = Column(Integer, nullable=False)
    risk_level    = Column(String(20), nullable=False)

    # CSP
    generated_csp = Column(Text, nullable=False)
    hardened_csp  = Column(Text, nullable=True)

    # Summary
    issues        = Column(JSON, default=list)
    recommendations = Column(JSON, default=list)
    resource_stats  = Column(JSON, default=dict)

    # LLM provider used
    llm_provider  = Column(String(50), nullable=True)

    # Relationships
    violations    = relationship("ViolationReport", back_populates="analysis",
                                 cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_domain_created", "domain", "created_at"),
    )

    def to_dict(self):
        return {
            "id":             self.id,
            "domain":         self.domain,
            "created_at":     self.created_at.isoformat() if self.created_at else None,
            "risk_score":     self.risk_score,
            "risk_level":     self.risk_level,
            "generated_csp":  self.generated_csp,
            "hardened_csp":   self.hardened_csp,
            "issues":         self.issues or [],
            "recommendations": self.recommendations or [],
            "resource_stats": self.resource_stats or {},
            "llm_provider":   self.llm_provider,
            "violation_count": len(self.violations) if self.violations else 0,
        }


# ── CSP Violation Reports ─────────────────────────────────────────────────────
class ViolationReport(Base):
    __tablename__ = "violation_reports"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id     = Column(Integer, ForeignKey("analysis_records.id",
                                                  ondelete="CASCADE"), nullable=True)
    received_at     = Column(DateTime(timezone=True), default=utcnow, index=True)

    # From browser CSP report
    document_uri    = Column(String(512), nullable=True)
    violated_directive = Column(String(255), nullable=True, index=True)
    effective_directive = Column(String(255), nullable=True)
    blocked_uri     = Column(String(512), nullable=True)
    original_policy = Column(Text, nullable=True)
    disposition     = Column(String(20), nullable=True)   # enforce / report
    status_code     = Column(Integer, nullable=True)
    source_file     = Column(String(512), nullable=True)
    line_number     = Column(Integer, nullable=True)
    column_number   = Column(Integer, nullable=True)

    # Domain extracted
    domain          = Column(String(255), nullable=True, index=True)

    # Relationship
    analysis        = relationship("AnalysisRecord", back_populates="violations")

    def to_dict(self):
        return {
            "id":                   self.id,
            "analysis_id":          self.analysis_id,
            "received_at":          self.received_at.isoformat() if self.received_at else None,
            "document_uri":         self.document_uri,
            "violated_directive":   self.violated_directive,
            "effective_directive":  self.effective_directive,
            "blocked_uri":          self.blocked_uri,
            "disposition":          self.disposition,
            "source_file":          self.source_file,
            "line_number":          self.line_number,
            "domain":               self.domain,
        }