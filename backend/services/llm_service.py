# CSP Guardian v2 – services/llm_service.py
# Multi-LLM provider support: Groq, Gemini, Anthropic, OpenAI

import os
import json
import logging
from typing import Any
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("csp-guardian.llm")

# ── System prompt (shared across all providers) ───────────────────────────────
SYSTEM_PROMPT = """You are a senior web security engineer specializing in Content Security Policy (CSP).
Given a resource summary, a rule-based CSP draft, and a risk report, your job is to:
1. Harden the CSP (add strict-dynamic, trusted types, upgrade-insecure-requests if appropriate)
2. Explain each directive in plain language
3. Provide 3-5 concrete security recommendations

CRITICAL: Return ONLY valid JSON, no markdown, no preamble:
{
  "hardened_csp": "<complete CSP header string>",
  "explanation": {
    "default-src": "Explanation...",
    "script-src": "Explanation..."
  },
  "recommendations": ["rec1", "rec2", "rec3"]
}"""


def build_user_prompt(body: Any) -> str:
    rs = body.resource_summary
    return f"""Analyze and harden this CSP for domain: {body.domain}

Resource Summary:
- Script domains: {rs.script_domains or ["(none)"]}
- Style domains: {rs.style_domains or ["(none)"]}
- Connect domains: {rs.connect_domains or ["(none)"]}
- Inline scripts: {rs.inline_script}
- eval() detected: {rs.eval_detected}
- Wildcard-risk domains: {rs.wildcard_domains or ["(none)"]}

Rule-based CSP:
{body.generated_csp}

Risk: {body.risk_score}/100 ({body.risk_level})
Issues: {body.issues or ["(none)"]}

Return ONLY JSON."""


def parse_llm_response(raw: str, fallback_csp: str) -> dict:
    """Parse LLM JSON response with fallback."""
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse LLM JSON, using fallback. Raw: {raw[:100]}")
        return {
            "hardened_csp": fallback_csp,
            "explanation": {"note": "AI response could not be parsed."},
            "recommendations": ["Retry the AI analysis."],
        }
    parsed.setdefault("hardened_csp", fallback_csp)
    parsed.setdefault("explanation", {})
    parsed.setdefault("recommendations", [])
    return parsed


# ── Provider: Groq ────────────────────────────────────────────────────────────
async def _call_groq(prompt: str, fallback: str) -> tuple[dict, str]:
    from groq import AsyncGroq
    client = AsyncGroq(api_key=os.environ["GROQ_API_KEY"])
    response = await client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
    )
    raw = response.choices[0].message.content
    return parse_llm_response(raw, fallback), "groq/llama-3.3-70b"


# ── Provider: Gemini ──────────────────────────────────────────────────────────
async def _call_gemini(prompt: str, fallback: str) -> tuple[dict, str]:
    from google import genai
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    full_prompt = f"{SYSTEM_PROMPT}\n\n{prompt}"
    response = client.models.generate_content(
        model="gemini-2.0-flash", contents=full_prompt
    )
    return parse_llm_response(response.text, fallback), "gemini/gemini-2.0-flash"


# ── Provider: Anthropic Claude ────────────────────────────────────────────────
async def _call_anthropic(prompt: str, fallback: str) -> tuple[dict, str]:
    import anthropic
    client = anthropic.AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    message = await client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = message.content[0].text
    return parse_llm_response(raw, fallback), "anthropic/claude-sonnet-4"


# ── Provider: OpenAI ──────────────────────────────────────────────────────────
async def _call_openai(prompt: str, fallback: str) -> tuple[dict, str]:
    from openai import AsyncOpenAI
    client = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])
    response = await client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
    )
    raw = response.choices[0].message.content
    return parse_llm_response(raw, fallback), "openai/gpt-4o-mini"


# ── Auto-select provider based on available keys ──────────────────────────────
PROVIDERS = {
    "groq":      ("GROQ_API_KEY",      _call_groq),
    "gemini":    ("GEMINI_API_KEY",     _call_gemini),
    "anthropic": ("ANTHROPIC_API_KEY",  _call_anthropic),
    "openai":    ("OPENAI_API_KEY",     _call_openai),
}


def get_active_provider() -> str:
    """Return the first provider that has an API key configured."""
    preferred = os.environ.get("LLM_PROVIDER", "").lower()
    if preferred and preferred in PROVIDERS:
        key_env, _ = PROVIDERS[preferred]
        if os.environ.get(key_env):
            return preferred

    # Auto-detect
    for name, (key_env, _) in PROVIDERS.items():
        if os.environ.get(key_env):
            return name

    return None


async def analyze_csp_with_llm(body: Any) -> tuple[dict, str]:
    """
    Call the configured LLM provider.
    Returns (result_dict, provider_name)
    """
    provider_name = get_active_provider()
    if not provider_name:
        logger.error("No LLM API key configured!")
        raise ValueError(
            "No LLM provider configured. Set one of: "
            "GROQ_API_KEY, GEMINI_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY"
        )

    prompt = build_user_prompt(body)
    _, call_fn = PROVIDERS[provider_name]

    logger.info(f"Using LLM provider: {provider_name}")
    result, model_id = await call_fn(prompt, body.generated_csp)
    return result, model_id