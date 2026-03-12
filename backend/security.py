# CSP Guardian v3 – backend/security.py
# III. Bảo mật: CORS restrict, API key validation, request validation

import os
import hmac
import hashlib
import time
import logging
from typing import Optional

from fastapi import Request, HTTPException, Security
from fastapi.security import APIKeyHeader

logger = logging.getLogger("csp-guardian.security")

# ── API Key Auth ──────────────────────────────────────────────────────────────
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
_API_KEY = os.environ.get("CSP_GUARDIAN_API_KEY", "")  # Set in .env for production


async def verify_api_key(api_key: Optional[str] = Security(API_KEY_HEADER)):
    """
    Optional API key verification.
    If CSP_GUARDIAN_API_KEY is not set in .env, auth is disabled (dev mode).
    """
    if not _API_KEY:
        return  # Auth disabled in dev mode

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if not hmac.compare_digest(api_key, _API_KEY):
        logger.warning(f"Invalid API key attempt")
        raise HTTPException(status_code=403, detail="Invalid API key")


# ── Origin Validation ─────────────────────────────────────────────────────────
ALLOWED_EXTENSION_IDS = os.environ.get("ALLOWED_EXTENSION_IDS", "").split(",")


def get_allowed_origins() -> list[str]:
    """Build CORS allow list from env."""
    origins = ["http://localhost:8000", "http://127.0.0.1:8000"]

    # Add Chrome extension origins
    for ext_id in ALLOWED_EXTENSION_IDS:
        ext_id = ext_id.strip()
        if ext_id:
            origins.append(f"chrome-extension://{ext_id}")

    # In dev mode, allow all
    if os.environ.get("ENV", "development") == "development":
        origins = ["*"]

    return origins


# ── Domain Sanitizer ──────────────────────────────────────────────────────────
import re

SAFE_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


def sanitize_domain(domain: str) -> str:
    """Validate and sanitize domain input."""
    domain = domain.strip().lower()

    # Strip protocol if accidentally included
    if "://" in domain:
        raise HTTPException(400, "Send domain only (e.g. example.com), not URL")

    if "/" in domain or "\\" in domain:
        raise HTTPException(400, "Invalid domain format")

    if len(domain) > 255:
        raise HTTPException(400, "Domain too long")

    if not SAFE_DOMAIN_RE.match(domain):
        raise HTTPException(400, f"Invalid domain: {domain!r}")

    return domain


# ── LLM Response Validator ────────────────────────────────────────────────────
DANGEROUS_PATTERNS = [
    r"<script",
    r"javascript:",
    r"data:text/html",
    r"\\u0000",
    r"\x00",
]

def validate_llm_response(data: dict) -> dict:
    """
    Sanitize LLM response before sending to extension.
    Prevent prompt injection / XSS from malicious LLM outputs.
    """
    import re

    def sanitize_str(s: str) -> str:
        if not isinstance(s, str):
            return str(s)
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, s, re.IGNORECASE):
                logger.warning(f"Dangerous pattern in LLM output: {pattern}")
                s = re.sub(pattern, "[REMOVED]", s, flags=re.IGNORECASE)
        return s

    # Sanitize hardened_csp
    if "hardened_csp" in data:
        data["hardened_csp"] = sanitize_str(data["hardened_csp"])

    # Sanitize explanation
    if isinstance(data.get("explanation"), dict):
        data["explanation"] = {
            k: sanitize_str(v) for k, v in data["explanation"].items()
        }
    elif isinstance(data.get("explanation"), str):
        data["explanation"] = sanitize_str(data["explanation"])

    # Sanitize recommendations
    if isinstance(data.get("recommendations"), list):
        data["recommendations"] = [
            sanitize_str(r) for r in data["recommendations"]
        ]

    return data


# ── Rate limit key with IP + domain ──────────────────────────────────────────
def rate_limit_key(request: Request) -> str:
    """More granular rate limiting key."""
    ip = request.client.host if request.client else "unknown"
    return f"{ip}"