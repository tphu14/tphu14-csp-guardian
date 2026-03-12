// CSP Guardian – utils/risk-scorer.js
// Module 3: Risk Scoring Engine

"use strict";

/**
 * Score the security risk of a page based on collected resources.
 * @param {Object} resources - Collected resources
 * @param {Object} cspResult  - Output from csp-generator.js
 * @returns {{ risk_score: number, risk_level: string, issues: string[], breakdown: Object }}
 */
export function calculateRiskScore(resources, cspResult) {
  let score = 0;
  const issues = [];
  const breakdown = {};

  // ── Rule 1: HTTP resources (+20) ──────────────────────────────────────────
  const allResources = [
    ...(resources.scripts || []),
    ...(resources.styles || []),
    ...(resources.images || []),
    ...(resources.xhr || []),
    ...(resources.fonts || []),
    ...(resources.media || []),
    ...(resources.frames || []),
  ];

  const httpResources = allResources.filter((r) => r.scheme === "http");
  if (httpResources.length > 0) {
    score += 20;
    breakdown["HTTP resources"] = 20;
    issues.push(
      `HTTP (non-HTTPS) resources detected: ${httpResources.map((r) => r.url).slice(0, 3).join(", ")}${httpResources.length > 3 ? "…" : ""}`
    );
  }

  // ── Rule 2: Inline scripts (+25) ─────────────────────────────────────────
  const inlineCount = resources.inlineScripts?.length ?? 0;
  if (inlineCount > 0) {
    score += 25;
    breakdown["Inline scripts"] = 25;
    issues.push(`Inline script detected (${inlineCount} occurrence${inlineCount > 1 ? "s" : ""})`);
  }

  // ── Rule 3: eval / new Function (+30) ────────────────────────────────────
  if (resources.evalDetected) {
    score += 30;
    breakdown["eval() / new Function()"] = 30;
    issues.push("eval() or new Function() usage detected – unsafe-eval risk");
  }

  // ── Rule 4: Wildcard-risk domains (+15) ──────────────────────────────────
  const wildcardCount = resources.wildcardDomains?.length ?? 0;
  if (wildcardCount > 0) {
    score += 15;
    breakdown["Wildcard domains"] = 15;
    issues.push(
      `Wildcard-risk domain(s) detected: ${(resources.wildcardDomains || []).slice(0, 3).join(", ")}`
    );
  }

  // ── Rule 5: Too many third-party domains (+10) ────────────────────────────
  const thirdPartyDomains = new Set();

  // Try to get current tab's hostname for comparison (fallback: count all)
  allResources.forEach((r) => {
    if (r.domain) thirdPartyDomains.add(r.domain);
  });

  // Remove 'self' references – simple heuristic: if >5 unique external domains
  if (thirdPartyDomains.size > 5) {
    score += 10;
    breakdown["Many third-party domains"] = 10;
    issues.push(`${thirdPartyDomains.size} third-party domains loaded (threshold: 5)`);
  }

  // ── Clamp score to 0–100 ─────────────────────────────────────────────────
  score = Math.min(100, Math.max(0, score));

  // ── Risk level ───────────────────────────────────────────────────────────
  let risk_level;
  let risk_color;
  if (score >= 70) {
    risk_level = "High";
    risk_color = "#ef4444"; // red
  } else if (score >= 35) {
    risk_level = "Medium";
    risk_color = "#f59e0b"; // amber
  } else {
    risk_level = "Low";
    risk_color = "#22c55e"; // green
  }

  return {
    risk_score: score,
    risk_level,
    risk_color,
    issues,
    breakdown,
    stats: {
      totalResources: allResources.length,
      thirdPartyDomains: thirdPartyDomains.size,
      inlineScripts: inlineCount,
      wildcardDomains: wildcardCount,
    },
  };
}