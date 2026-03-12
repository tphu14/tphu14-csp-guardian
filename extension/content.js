// CSP Guardian – content.js
// Module 1: Inline script & eval detection

(function () {
  "use strict";

  // Avoid double-injection
  if (window.__cspGuardianInjected) return;
  window.__cspGuardianInjected = true;

  // ─── Detect Inline <script> tags ─────────────────────────────────────────
  function scanInlineScripts() {
    const scripts = document.querySelectorAll("script:not([src])");
    scripts.forEach((el) => {
      const content = (el.textContent || "").trim();
      if (!content) return;

      const hasEval =
        /\beval\s*\(/.test(content) ||
        /new\s+Function\s*\(/.test(content) ||
        /setTimeout\s*\(\s*['"]/.test(content) ||
        /setInterval\s*\(\s*['"]/.test(content);

      const snippet = content.substring(0, 120) + (content.length > 120 ? "…" : "");

      chrome.runtime.sendMessage({
        type: "INLINE_SCRIPT_DETECTED",
        data: {
          snippet,
          hasEval,
          source: "inline-tag",
        },
      }).catch(() => {}); // extension may not be listening
    });
  }

  // ─── Detect eval() via script injection override ─────────────────────────
  // We inject a tiny page-level script via a blob to monitor eval usage
  function injectEvalMonitor() {
    const script = document.createElement("script");
    script.textContent = `
      (function() {
        var _eval = window.eval;
        window.eval = function(code) {
          window.dispatchEvent(new CustomEvent('__csp_eval_detected__', {
            detail: { snippet: String(code).substring(0, 80) }
          }));
          return _eval.apply(this, arguments);
        };

        var _Function = window.Function;
        window.Function = function() {
          window.dispatchEvent(new CustomEvent('__csp_eval_detected__', {
            detail: { snippet: 'new Function() call' }
          }));
          return _Function.apply(this, arguments);
        };
        window.Function.prototype = _Function.prototype;
      })();
    `;
    (document.head || document.documentElement).appendChild(script);
    script.remove();
  }

  // Listen for eval events dispatched from page context
  window.addEventListener("__csp_eval_detected__", (e) => {
    chrome.runtime.sendMessage({
      type: "INLINE_SCRIPT_DETECTED",
      data: {
        snippet: e.detail?.snippet || "eval() detected",
        hasEval: true,
        source: "eval-monitor",
      },
    }).catch(() => {});
  });

  // ─── MutationObserver: catch dynamically added inline scripts ─────────────
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (
          node.tagName === "SCRIPT" &&
          !node.src &&
          node.textContent?.trim()
        ) {
          const content = node.textContent.trim();
          const hasEval =
            /\beval\s*\(/.test(content) || /new\s+Function\s*\(/.test(content);
          const snippet = content.substring(0, 120) + (content.length > 120 ? "…" : "");

          chrome.runtime.sendMessage({
            type: "INLINE_SCRIPT_DETECTED",
            data: { snippet, hasEval, source: "dynamic-injection" },
          }).catch(() => {});
        }
      }
    }
  });

  // ─── Init ─────────────────────────────────────────────────────────────────
  function init() {
    injectEvalMonitor();
    scanInlineScripts();
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();