# CSP Guardian v3 – tests/test_monitoring.py

import pytest
import pytest_asyncio
import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.setdefault("GROQ_API_KEY", "test-key")

from httpx import AsyncClient, ASGITransport
from main import app
from db import Base, engine

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_prometheus_format(client):
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    # Prometheus format always contains TYPE lines
    assert "# HELP" in resp.text or "# TYPE" in resp.text


@pytest.mark.asyncio
async def test_metrics_summary(client):
    resp = await client.get("/metrics/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert "total_analyses"   in data["summary"]
    assert "total_violations" in data["summary"]
    assert "avg_risk_score"   in data["summary"]
    assert "ws_connections"   in data["summary"]
    assert "risk_breakdown"   in data
    assert "risky_domains"    in data
    assert "recent_analyses"  in data


@pytest.mark.asyncio
async def test_health_detailed(client):
    resp = await client.get("/metrics/health/detailed")
    assert resp.status_code == 200
    data = resp.json()
    assert "status"     in data
    assert "components" in data
    assert "database"   in data["components"]
    assert "llm"        in data["components"]
    assert "websocket"  in data["components"]
    assert "sentry"     in data["components"]


@pytest.mark.asyncio
async def test_health_includes_sentry_field(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "sentry" in data


@pytest.mark.asyncio
async def test_metrics_increments_on_violation(client):
    """Sending a CSP report should increment violation counter."""
    report = {
        "csp-report": {
            "document-uri":       "https://example.com/",
            "violated-directive": "script-src",
            "blocked-uri":        "https://evil.com/x.js",
            "original-policy":    "default-src 'self'",
            "disposition":        "enforce",
            "status-code":        200,
        }
    }
    resp = await client.post("/csp-report", json=report)
    assert resp.status_code in (200, 204)

    # Metrics should now include the violation counter
    metrics_resp = await client.get("/metrics")
    assert "csp_guardian_violation_reports_total" in metrics_resp.text