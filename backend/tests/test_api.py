# CSP Guardian v3 – backend/tests/test_api.py
# pytest + pytest-asyncio tests for all API endpoints

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch

# We need to set env before importing app
import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["GROQ_API_KEY"] = "test-key-groq"

from main import app
from db import init_db, engine, Base

# ── Fixtures ──────────────────────────────────────────────────────────────────
@pytest.fixture(scope="session", autouse=True)
def setup_db():
    """Create all tables in in-memory SQLite for tests."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


# ── Mocked LLM response ───────────────────────────────────────────────────────
MOCK_LLM_RESULT = {
    "hardened_csp": "default-src 'self'; script-src 'self' 'strict-dynamic'",
    "explanation":  {"default-src": "Fallback for all resource types."},
    "recommendations": ["Use nonces for inline scripts"],
}


# ── Health endpoint ───────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["version"] == "3.0.0"


# ── Analyze endpoint ──────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_analyze_success(client):
    payload = {
        "domain": "example.com",
        "resource_summary": {
            "script_domains": ["cdn.example.com"],
            "style_domains":  [],
            "connect_domains": [],
            "inline_script":  False,
            "eval_detected":  False,
            "wildcard_used":  False,
            "wildcard_domains": [],
        },
        "generated_csp":  "default-src 'self'; script-src 'self'",
        "risk_score":     10,
        "risk_level":     "Low",
        "issues":         [],
        "resource_stats": {},
    }

    with patch("routers.analyze.analyze_csp_with_llm", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = (MOCK_LLM_RESULT, "groq/llama-3.3-70b")
        resp = await client.post("/analyze", json=payload)

    assert resp.status_code == 200
    data = resp.json()
    assert "hardened_csp" in data
    assert "analysis_id" in data
    assert data["analysis_id"] is not None


@pytest.mark.asyncio
async def test_analyze_rejects_full_url(client):
    payload = {
        "domain": "https://example.com",  # should be rejected
        "resource_summary": {"script_domains":[],"style_domains":[],"connect_domains":[],
                             "inline_script":False,"eval_detected":False,
                             "wildcard_used":False,"wildcard_domains":[]},
        "generated_csp": "default-src 'self'",
        "risk_score": 0, "risk_level": "Low", "issues": [], "resource_stats": {},
    }
    resp = await client.post("/analyze", json=payload)
    assert resp.status_code == 400


# ── History endpoints ─────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_history_list(client):
    resp = await client.get("/history")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data


@pytest.mark.asyncio
async def test_history_stats(client):
    resp = await client.get("/history/stats/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_analyses" in data
    assert "avg_risk_score" in data


@pytest.mark.asyncio
async def test_history_not_found(client):
    resp = await client.get("/history/99999")
    assert resp.status_code == 404


# ── Violations endpoints ──────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_csp_report_receive(client):
    report = {
        "csp-report": {
            "document-uri":        "https://example.com/page",
            "violated-directive":  "script-src",
            "effective-directive": "script-src",
            "blocked-uri":         "https://evil.com/script.js",
            "original-policy":     "default-src 'self'",
            "disposition":         "enforce",
            "status-code":         200,
        }
    }
    resp = await client.post(
        "/csp-report",
        json=report,
        headers={"Content-Type": "application/json"},
    )
    # 204 No Content is the standard response for CSP reports
    assert resp.status_code in (200, 204)


@pytest.mark.asyncio
async def test_violations_list(client):
    resp = await client.get("/violations")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data


@pytest.mark.asyncio
async def test_violations_stats(client):
    resp = await client.get("/violations/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_violations" in data
    assert "by_directive" in data


# ── Security tests ────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_domain_sanitization(client):
    """Test that malicious domain inputs are rejected."""
    bad_domains = [
        "example.com/../../etc/passwd",
        "http://evil.com",
        "a" * 300,  # too long
    ]
    for domain in bad_domains:
        payload = {
            "domain": domain,
            "resource_summary": {"script_domains":[],"style_domains":[],
                                 "connect_domains":[],"inline_script":False,
                                 "eval_detected":False,"wildcard_used":False,
                                 "wildcard_domains":[]},
            "generated_csp": "default-src 'self'",
            "risk_score": 0, "risk_level": "Low", "issues": [], "resource_stats": {},
        }
        resp = await client.post("/analyze", json=payload)
        assert resp.status_code == 400, f"Expected 400 for domain={domain!r}"