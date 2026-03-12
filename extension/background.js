// CSP Guardian – background.js (Service Worker)
// Module 1: Resource Collector + orchestration

// ─── State ───────────────────────────────────────────────────────────────────
let isRecording = false;
let recordingTabId = null;

const defaultResources = () => ({
  scripts: [],
  styles: [],
  images: [],
  xhr: [],
  frames: [],
  fonts: [],
  media: [],
  inlineScripts: [],
  evalDetected: false,
  wildcardDomains: [],
});

let resources = defaultResources();
const seenUrls = new Set();

// ─── URL Normalization ────────────────────────────────────────────────────────
function normalizeUrl(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.hostname}`;
  } catch {
    return null;
  }
}

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function isWildcardRisk(domain) {
  // Flag CDN-style wildcard domains
  const wildcardPatterns = [
    /\.cloudfront\.net$/,
    /\.cdn\./,
    /\.akamai(hd)?\.net$/,
    /\.fastly\.net$/,
    /\.amazonaws\.com$/,
    /\.azureedge\.net$/,
    /\.googleusercontent\.com$/,
  ];
  return wildcardPatterns.some((p) => p.test(domain));
}

// ─── Resource Type Mapping ────────────────────────────────────────────────────
const TYPE_MAP = {
  script: "scripts",
  stylesheet: "styles",
  image: "images",
  xmlhttprequest: "xhr",
  fetch: "xhr",
  sub_frame: "frames",
  font: "fonts",
  media: "media",
  object: "scripts", // treat object as script-like
  ping: "xhr",
  websocket: "xhr",
};

// ─── webRequest Listener ──────────────────────────────────────────────────────
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!isRecording) return;
    if (details.tabId !== recordingTabId) return;
    if (details.url.startsWith("chrome-extension://")) return;

    const normalized = normalizeUrl(details.url);
    if (!normalized) return;

    const category = TYPE_MAP[details.type];
    if (!category) return;

    const domain = extractDomain(details.url);
    const dedupKey = `${category}::${normalized}`;

    if (!seenUrls.has(dedupKey)) {
      seenUrls.add(dedupKey);

      const entry = {
        url: normalized,
        domain,
        isInline: false,
        scheme: new URL(details.url).protocol.replace(":", ""),
      };

      resources[category].push(entry);

      // Flag wildcard-risk domains
      if (domain && isWildcardRisk(domain)) {
        if (!resources.wildcardDomains.includes(domain)) {
          resources.wildcardDomains.push(domain);
        }
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

// ─── Message Handler ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  switch (msg.type) {
    // ── Start Recording ──
    case "START_RECORDING": {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs[0]) return sendResponse({ ok: false, error: "No active tab" });
        isRecording = true;
        recordingTabId = tabs[0].id;
        resources = defaultResources();
        seenUrls.clear();
        sendResponse({ ok: true, tabId: recordingTabId });
      });
      return true; // async
    }

    // ── Stop & Get Resources ──
    case "STOP_RECORDING": {
      isRecording = false;
      sendResponse({ ok: true, resources });
      return true;
    }

    // ── Inline Script detected by content.js ──
    case "INLINE_SCRIPT_DETECTED": {
      if (!isRecording || sender.tab?.id !== recordingTabId) break;
      const { snippet, hasEval, source } = msg.data;
      resources.inlineScripts.push({ snippet, hasEval, source });
      if (hasEval) resources.evalDetected = true;
      sendResponse({ ok: true });
      break;
    }

    // ── Status check ──
    case "GET_STATUS": {
      sendResponse({
        isRecording,
        tabId: recordingTabId,
        count: seenUrls.size,
      });
      break;
    }

    // ── Get current resources without stopping ──
    case "GET_RESOURCES": {
      sendResponse({ ok: true, resources });
      break;
    }

    default:
      sendResponse({ ok: false, error: "Unknown message type" });
  }
});

// ─── Tab closed: auto-stop ────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  if (tabId === recordingTabId) {
    isRecording = false;
    recordingTabId = null;
  }
});

// ─── Navigation: capture page-level navigations ───────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (!isRecording || tabId !== recordingTabId) return;
  if (changeInfo.status === "loading" && changeInfo.url) {
    const domain = extractDomain(changeInfo.url);
    if (domain && isWildcardRisk(domain)) {
      if (!resources.wildcardDomains.includes(domain)) {
        resources.wildcardDomains.push(domain);
      }
    }
  }
});

console.log("[CSP Guardian] Background service worker loaded");