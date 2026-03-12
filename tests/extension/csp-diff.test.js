// CSP Guardian v3 – tests/extension/csp-diff.test.js
// vitest unit tests for CSP diff engine

import { describe, it, expect } from "vitest";
import { parseCSP, diffCSP, renderDiffHTML } from "../../extension/utils/csp-diff.js";

// ── parseCSP ──────────────────────────────────────────────────────────────────
describe("parseCSP", () => {
  it("parses a simple CSP string", () => {
    const csp = "default-src 'self'; script-src 'self' cdn.com";
    const result = parseCSP(csp);
    expect(result["default-src"]).toEqual(["'self'"]);
    expect(result["script-src"]).toEqual(["'self'", "cdn.com"]);
  });

  it("handles empty string", () => {
    expect(parseCSP("")).toEqual({});
    expect(parseCSP(null)).toEqual({});
  });

  it("handles directives without values", () => {
    const result = parseCSP("upgrade-insecure-requests; default-src 'self'");
    expect(result["upgrade-insecure-requests"]).toEqual([]);
    expect(result["default-src"]).toEqual(["'self'"]);
  });

  it("lowercases directive names", () => {
    const result = parseCSP("DEFAULT-SRC 'self'");
    expect(result["default-src"]).toEqual(["'self'"]);
  });
});

// ── diffCSP ───────────────────────────────────────────────────────────────────
describe("diffCSP", () => {
  it("detects added directives", () => {
    const old = "default-src 'self'";
    const neo = "default-src 'self'; upgrade-insecure-requests";
    const diff = diffCSP(old, neo);
    expect(diff.added).toBe(1);
    const addedLine = diff.lines.find(l => l.type === "added");
    expect(addedLine?.directive).toBe("upgrade-insecure-requests");
  });

  it("detects removed directives", () => {
    const old = "default-src 'self'; frame-src 'none'";
    const neo = "default-src 'self'";
    const diff = diffCSP(old, neo);
    expect(diff.removed).toBe(1);
  });

  it("detects changed directives (added values)", () => {
    const old = "script-src 'self'";
    const neo = "script-src 'self' 'strict-dynamic'";
    const diff = diffCSP(old, neo);
    expect(diff.changed).toBe(1);
    const changedLine = diff.lines.find(l => l.type === "changed");
    expect(changedLine?.newValues).toContain("'strict-dynamic'");
  });

  it("detects unchanged directives", () => {
    const csp = "default-src 'self'; object-src 'none'";
    const diff = diffCSP(csp, csp);
    expect(diff.added).toBe(0);
    expect(diff.removed).toBe(0);
    expect(diff.changed).toBe(0);
    expect(diff.lines.every(l => l.type === "unchanged")).toBe(true);
  });

  it("handles empty CSPs", () => {
    const diff = diffCSP("", "default-src 'self'");
    expect(diff.added).toBe(1);
  });
});

// ── renderDiffHTML ────────────────────────────────────────────────────────────
describe("renderDiffHTML", () => {
  it("renders summary with counts", () => {
    const diff = diffCSP(
      "default-src 'self'",
      "default-src 'self'; script-src 'strict-dynamic'"
    );
    const html = renderDiffHTML(diff);
    expect(html).toContain("added");
    expect(html).toContain("diff-summary");
  });

  it("escapes HTML in values", () => {
    // Simulate malicious CSP value
    const diff = {
      lines: [{ type: "added", directive: "script-src", values: ["<script>alert(1)</script>"] }],
      added: 1, removed: 0, changed: 0,
    };
    const html = renderDiffHTML(diff);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("returns fallback for empty diff", () => {
    const html = renderDiffHTML({ lines: [], added: 0, removed: 0, changed: 0 });
    expect(html).toContain("No differences");
  });
});