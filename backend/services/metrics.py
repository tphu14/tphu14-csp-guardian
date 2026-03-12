# CSP Guardian v3 – services/metrics.py
# Prometheus metrics for API performance monitoring

from prometheus_client import (
    Counter, Histogram, Gauge, Info,
    generate_latest, CONTENT_TYPE_LATEST,
    CollectorRegistry, REGISTRY,
)
import time
import logging

logger = logging.getLogger("csp-guardian.metrics")

# ── Counters ──────────────────────────────────────────────────────────────────
analyze_requests_total = Counter(
    "csp_guardian_analyze_requests_total",
    "Total number of /analyze requests",
    ["status", "risk_level", "llm_provider"],
)

violation_reports_total = Counter(
    "csp_guardian_violation_reports_total",
    "Total CSP violation reports received",
    ["domain", "violated_directive"],
)

llm_errors_total = Counter(
    "csp_guardian_llm_errors_total",
    "Total LLM provider errors",
    ["provider", "error_type"],
)

http_requests_total = Counter(
    "csp_guardian_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"],
)

# ── Histograms ────────────────────────────────────────────────────────────────
analyze_duration_seconds = Histogram(
    "csp_guardian_analyze_duration_seconds",
    "Time spent processing /analyze requests",
    ["llm_provider"],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
)

llm_response_duration_seconds = Histogram(
    "csp_guardian_llm_response_duration_seconds",
    "Time spent waiting for LLM response",
    ["provider"],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
)

http_request_duration_seconds = Histogram(
    "csp_guardian_http_request_duration_seconds",
    "HTTP request duration",
    ["method", "endpoint"],
    buckets=[0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
)

# ── Gauges ────────────────────────────────────────────────────────────────────
active_ws_connections = Gauge(
    "csp_guardian_active_ws_connections",
    "Number of active WebSocket connections",
)

analyses_stored_total = Gauge(
    "csp_guardian_analyses_stored_total",
    "Total analysis records in database",
)

violations_stored_total = Gauge(
    "csp_guardian_violations_stored_total",
    "Total violation records in database",
)

avg_risk_score = Gauge(
    "csp_guardian_avg_risk_score",
    "Average risk score across all analyses",
)

# ── Info ──────────────────────────────────────────────────────────────────────
app_info = Info(
    "csp_guardian",
    "CSP Guardian application info",
)

app_info.info({
    "version":     "3.0.0",
    "environment": "development",
})


# ── Context manager for timing ────────────────────────────────────────────────
class Timer:
    """Context manager to time a block and record to a Histogram."""
    def __init__(self, histogram, labels: dict):
        self.histogram = histogram
        self.labels    = labels
        self._start    = None

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args):
        elapsed = time.perf_counter() - self._start
        self.histogram.labels(**self.labels).observe(elapsed)


def update_db_gauges(db):
    """Update database-backed gauges. Call periodically."""
    try:
        from db.models import AnalysisRecord, ViolationReport
        from sqlalchemy import func

        count_analyses  = db.query(func.count(AnalysisRecord.id)).scalar() or 0
        count_violations = db.query(func.count(ViolationReport.id)).scalar() or 0
        avg_score       = db.query(func.avg(AnalysisRecord.risk_score)).scalar() or 0.0

        analyses_stored_total.set(count_analyses)
        violations_stored_total.set(count_violations)
        avg_risk_score.set(float(avg_score))
    except Exception as e:
        logger.debug(f"Gauge update skipped: {e}")