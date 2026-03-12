import os, json, logging
from dotenv import load_dotenv
from groq import AsyncGroq

load_dotenv()
logger = logging.getLogger("csp-guardian.llm")
client = AsyncGroq(api_key=os.environ.get("GROQ_API_KEY"))

async def analyze_csp_with_llm(body) -> dict:
    rs = body.resource_summary

    prompt = f"""You are a senior web security engineer. Analyze this CSP and return JSON only.

Domain: {body.domain}
Script domains: {rs.script_domains}
Inline scripts: {rs.inline_script}
eval detected: {rs.eval_detected}
Wildcard domains: {rs.wildcard_domains}
Current CSP: {body.generated_csp}
Risk: {body.risk_score}/100 ({body.risk_level})
Issues: {body.issues}

Return ONLY this JSON format, no markdown, no explanation:
{{"hardened_csp": "...", "explanation": {{"default-src": "...", "script-src": "..."}}, "recommendations": ["..."]}}"""

    response = await client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )

    raw = response.choices[0].message.content.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1])

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {
            "hardened_csp": body.generated_csp,
            "explanation": {"note": "Could not parse AI response."},
            "recommendations": ["Retry the analysis."],
        }

    parsed.setdefault("hardened_csp", body.generated_csp)
    parsed.setdefault("explanation", {})
    parsed.setdefault("recommendations", [])
    return parsed