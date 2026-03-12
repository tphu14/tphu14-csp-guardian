// CSP Guardian v3 – utils/csp-diff.js
// CSP diff engine (compiled from TypeScript)

"use strict";

/**
 * Parse a CSP string into a directive map.
 */
export function parseCSP(csp) {
  if (!csp?.trim()) return {};
  return Object.fromEntries(
    csp.split(";")
      .map(d => d.trim())
      .filter(Boolean)
      .map(d => {
        const parts = d.split(/\s+/);
        return [parts[0].toLowerCase(), parts.slice(1)];
      })
  );
}

/**
 * Compute a diff between two CSP strings.
 */
export function diffCSP(oldCSP, newCSP) {
  const oldMap = parseCSP(oldCSP);
  const newMap = parseCSP(newCSP);
  const allDirectives = new Set([...Object.keys(oldMap), ...Object.keys(newMap)]);

  const lines = [];
  let added = 0, removed = 0, changed = 0;

  for (const directive of allDirectives) {
    const oldVals = oldMap[directive] ?? null;
    const newVals = newMap[directive] ?? null;

    if (!oldVals && newVals) {
      lines.push({ type: "added", directive, values: newVals });
      added++;
    } else if (oldVals && !newVals) {
      lines.push({ type: "removed", directive, values: oldVals });
      removed++;
    } else if (oldVals && newVals) {
      const oldSet = new Set(oldVals);
      const newSet = new Set(newVals);
      const addedVals   = newVals.filter(v => !oldSet.has(v));
      const removedVals = oldVals.filter(v => !newSet.has(v));

      if (!addedVals.length && !removedVals.length) {
        lines.push({ type: "unchanged", directive, values: newVals });
      } else {
        lines.push({ type: "changed", directive, values: newVals, oldValues: removedVals, newValues: addedVals });
        changed++;
      }
    }
  }

  const order = { removed: 0, changed: 1, added: 2, unchanged: 3 };
  lines.sort((a, b) => (order[a.type] ?? 3) - (order[b.type] ?? 3));

  return { lines, added, removed, changed };
}

/**
 * Render diff as HTML.
 */
export function renderDiffHTML(diff) {
  if (!diff.lines.length) return "<p class='muted'>No differences found.</p>";

  const esc = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

  const summary = [];
  if (diff.added)   summary.push(`<span class='diff-stat diff-added'>+${diff.added} directive${diff.added>1?'s':''} added</span>`);
  if (diff.removed) summary.push(`<span class='diff-stat diff-removed'>−${diff.removed} removed</span>`);
  if (diff.changed) summary.push(`<span class='diff-stat diff-changed'>~${diff.changed} changed</span>`);

  const summaryHTML = summary.length
    ? `<div class="diff-summary">${summary.join(" · ")}</div>`
    : `<div class="diff-summary"><span class='diff-stat muted'>No changes</span></div>`;

  const linesHTML = diff.lines.map(line => {
    if (line.type === "unchanged") {
      return `<div class="diff-line diff-unchanged">
        <span class="diff-sign"> </span>
        <span class="diff-directive">${esc(line.directive)}</span>
        <span class="diff-values">${line.values.map(esc).join(" ")}</span>
      </div>`;
    }
    if (line.type === "added") {
      return `<div class="diff-line diff-added">
        <span class="diff-sign">+</span>
        <span class="diff-directive">${esc(line.directive)}</span>
        <span class="diff-values">${line.values.map(esc).join(" ")}</span>
      </div>`;
    }
    if (line.type === "removed") {
      return `<div class="diff-line diff-removed">
        <span class="diff-sign">−</span>
        <span class="diff-directive">${esc(line.directive)}</span>
        <span class="diff-values diff-strike">${line.values.map(esc).join(" ")}</span>
      </div>`;
    }
    // changed
    const removedSpans = (line.oldValues||[]).map(v=>`<span class="diff-token-removed">${esc(v)}</span>`).join(" ");
    const addedSpans   = (line.newValues||[]).map(v=>`<span class="diff-token-added">${esc(v)}</span>`).join(" ");
    const kept = line.values.filter(v=>!(line.newValues||[]).includes(v)&&!(line.oldValues||[]).includes(v));
    const keptSpans = kept.map(v=>`<span class="diff-token">${esc(v)}</span>`).join(" ");
    return `<div class="diff-line diff-changed">
      <span class="diff-sign">~</span>
      <span class="diff-directive">${esc(line.directive)}</span>
      <span class="diff-values">${keptSpans} ${removedSpans} ${addedSpans}</span>
    </div>`;
  }).join("\n");

  return summaryHTML + `<div class="diff-lines">${linesHTML}</div>`;
}