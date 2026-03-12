// CSP Guardian – utils/csp-generator.js
// Module 2: Rule-based CSP Generator

"use strict";

/**
 * Generate a Content Security Policy from collected resources.
 * @param {Object} resources - Collected resource data from background.js
 * @param {Object} options   - Generator options
 * @returns {{ csp: string, directives: Object, warnings: string[] }}
 */
export function generateCSP(resources, options = {}) {
  const warnings = [];

  // ─── Directive buckets ─────────────────────────────────────────────────
  const directives = {
    "default-src": new Set(["'self'"]),
    "script-src": new Set(["'self'"]),
    "style-src": new Set(["'self'"]),
    "img-src": new Set(["'self'", "data:"]),
    "connect-src": new Set(["'self'"]),
    "frame-src": new Set(["'none'"]),
    "font-src": new Set(["'self'"]),
    "media-src": new Set(["'self'"]),
    "object-src": new Set(["'none'"]),
    "base-uri": new Set(["'self'"]),
    "frame-ancestors": new Set(["'none'"]),
    "form-action": new Set(["'self'"]),
  };

  // ─── Helper: add domain to directive ──────────────────────────────────
  function addToDirect(directive, entry) {
    const { url, scheme } = entry;
    if (!url) return;

    if (scheme === "http") {
      warnings.push(`⚠️ HTTP (non-HTTPS) resource detected: ${url}`);
    }

    directives[directive].add(url);
  }

  // ─── Scripts ──────────────────────────────────────────────────────────
  resources.scripts?.forEach((r) => addToDirect("script-src", r));

  // Handle inline scripts
  const hasInline = resources.inlineScripts?.length > 0;
  if (hasInline) {
    warnings.push(
      "⚠️ Inline scripts detected. Use nonces or hashes instead of 'unsafe-inline'."
    );
    // We suggest nonce instead of unsafe-inline
    directives["script-src"].add("'nonce-REPLACE_WITH_RANDOM_NONCE'");
    // Do NOT add 'unsafe-inline'
  }

  // Handle eval
  if (resources.evalDetected) {
    warnings.push(
      "🚨 eval() or new Function() detected. Avoid 'unsafe-eval' – refactor the code instead."
    );
    // We explicitly do NOT add 'unsafe-eval'; log warning only
  }

  // ─── Styles ───────────────────────────────────────────────────────────
  resources.styles?.forEach((r) => addToDirect("style-src", r));

  // ─── Images ───────────────────────────────────────────────────────────
  resources.images?.forEach((r) => addToDirect("img-src", r));

  // ─── XHR / Fetch / WebSocket ──────────────────────────────────────────
  resources.xhr?.forEach((r) => addToDirect("connect-src", r));

  // ─── Frames ───────────────────────────────────────────────────────────
  if (resources.frames?.length > 0) {
    directives["frame-src"].delete("'none'");
    resources.frames.forEach((r) => addToDirect("frame-src", r));
  }

  // ─── Fonts ────────────────────────────────────────────────────────────
  resources.fonts?.forEach((r) => addToDirect("font-src", r));

  // ─── Media ────────────────────────────────────────────────────────────
  resources.media?.forEach((r) => addToDirect("media-src", r));

  // ─── Wildcard domain warnings ─────────────────────────────────────────
  resources.wildcardDomains?.forEach((domain) => {
    warnings.push(
      `⚠️ Wildcard-risk domain detected: ${domain}. Consider restricting to specific subdomains.`
    );
  });

  // ─── Prune empty / redundant directives ───────────────────────────────
  // If a directive only contains 'self' and the parent default-src already covers it,
  // we still keep it explicit for clarity (best practice).

  // ─── Remove default 'none' frames if frames were added ────────────────
  // Already handled above

  // ─── Build CSP string ─────────────────────────────────────────────────
  const cspParts = [];
  for (const [directive, values] of Object.entries(directives)) {
    if (values.size === 0) continue;
    cspParts.push(`${directive} ${[...values].join(" ")}`);
  }

  // Add upgrade-insecure-requests if any HTTP resources found
  const hasHttpResources = warnings.some((w) => w.includes("HTTP (non-HTTPS)"));
  if (hasHttpResources) {
    cspParts.push("upgrade-insecure-requests");
    warnings.push("ℹ️ upgrade-insecure-requests added to handle HTTP resources.");
  }

  const csp = cspParts.join("; ");

  return {
    csp,
    directives: Object.fromEntries(
      Object.entries(directives).map(([k, v]) => [k, [...v]])
    ),
    warnings,
    hasInlineScripts: hasInline,
    hasEval: resources.evalDetected,
  };
}

/**
 * Generate nonce value (for display purposes – actual nonce must be server-generated per request)
 */
export function generateNonceExample() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array));
}