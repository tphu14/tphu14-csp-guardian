# CSP Guardian v3 – backend/tests/test_security.py

import pytest
import os
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from fastapi import HTTPException
from security import sanitize_domain, validate_llm_response


# ── sanitize_domain ───────────────────────────────────────────────────────────
def test_sanitize_domain_valid():
    assert sanitize_domain("example.com")       == "example.com"
    assert sanitize_domain("  Example.COM  ")   == "example.com"
    assert sanitize_domain("sub.example.co.uk") == "sub.example.co.uk"
    assert sanitize_domain("localhost")         == "localhost"


def test_sanitize_domain_rejects_url():
    with pytest.raises(HTTPException) as exc:
        sanitize_domain("https://example.com")
    assert exc.value.status_code == 400


def test_sanitize_domain_rejects_path():
    with pytest.raises(HTTPException):
        sanitize_domain("example.com/path")


def test_sanitize_domain_rejects_too_long():
    with pytest.raises(HTTPException):
        sanitize_domain("a" * 300)


# ── validate_llm_response ─────────────────────────────────────────────────────
def test_validate_llm_cleans_script_tag():
    data = {
        "hardened_csp":    "default-src 'self' <script>alert(1)</script>",
        "explanation":     {"script-src": "Allows <script>evil</script>"},
        "recommendations": ["Do this <script>x</script>"],
    }
    result = validate_llm_response(data)
    assert "<script" not in result["hardened_csp"]
    assert "<script" not in result["explanation"]["script-src"]
    assert "<script" not in result["recommendations"][0]


def test_validate_llm_cleans_javascript_uri():
    data = {
        "hardened_csp":    "javascript:alert(1)",
        "explanation":     {},
        "recommendations": [],
    }
    result = validate_llm_response(data)
    assert "javascript:" not in result["hardened_csp"]


def test_validate_llm_passes_clean_response():
    data = {
        "hardened_csp":    "default-src 'self'; script-src 'strict-dynamic'",
        "explanation":     {"default-src": "Fallback for all resource types."},
        "recommendations": ["Use nonces for inline scripts"],
    }
    result = validate_llm_response(data)
    assert result["hardened_csp"] == data["hardened_csp"]
    assert result["explanation"] == data["explanation"]


def test_validate_llm_handles_string_explanation():
    data = {
        "hardened_csp":    "default-src 'self'",
        "explanation":     "Plain text explanation",
        "recommendations": [],
    }
    result = validate_llm_response(data)
    assert result["explanation"] == "Plain text explanation"