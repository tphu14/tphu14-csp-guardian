🛡️ CSP Guardian
AI-powered Content Security Policy (CSP) builder, analyzer, and real-time violation monitor — built as a Chrome Extension + FastAPI backend.

📖 Project Description
CSP Guardian is a full-stack security tool that helps developers automatically generate, analyze, and harden Content Security Policies (CSP) for any website. It combines a Chrome Extension that intercepts network resources in real time with an AI-powered FastAPI backend that produces hardened CSP headers, explains each directive, and detects CSP violations live via WebSocket.
Instead of manually crafting CSP headers — a notoriously tedious and error-prone process — CSP Guardian records all resources loaded by a page, builds a rule-based CSP draft, scores the security risk, and then calls a configurable LLM (Groq, Gemini, Anthropic Claude, or OpenAI) to harden the policy and provide human-readable explanations.

✨ Features

🔴 Live Resource Recording — Chrome extension intercepts scripts, styles, images, XHR, fonts, frames, and more while you browse.
🧠 AI-Powered CSP Hardening — Sends resource summaries to a configurable LLM provider (Groq / Gemini / Anthropic / OpenAI) for hardened policy generation.
📊 Risk Scoring Engine — Automatically scores risk (0–100) based on HTTP resources, inline scripts, eval() usage, and wildcard domains.
🔍 CSP Diff View — Side-by-side token-level diff between the rule-based CSP and the AI-hardened version.
📡 Real-Time Violation Monitoring — Receives CSP violation reports from browsers via /csp-report and streams them to the extension popup via WebSocket.
🗄️ Analysis History — Full CRUD history of past analyses stored in SQLite (or PostgreSQL), queryable by domain.
📈 Prometheus Metrics — Production-ready /metrics endpoint with counters, histograms, and gauges for Grafana dashboards.
🚨 Sentry Integration — Optional error tracking and performance tracing via Sentry SDK.
🔐 API Key Auth & CORS — Optional API key protection and configurable CORS for extension IDs.
📤 JSON Export — One-click export of the full analysis report from the popup.


🛠️ Tech Stack
Backend
LayerTechnologyFrameworkFastAPIORMSQLAlchemyDatabaseSQLite (default) / PostgreSQLAI ProvidersGroq (Llama 3.3), Gemini 2.0 Flash, Anthropic Claude Sonnet, OpenAI GPT-4oReal-timeWebSocket (FastAPI native)MetricsPrometheus ClientError TrackingSentry SDKRate LimitingSlowAPITestingpytest, pytest-asyncio, httpx
Frontend (Chrome Extension)
LayerTechnologyExtension PlatformChrome Manifest V3LanguageJavaScript (ES Modules) + TypeScript (types)CSP EngineCustom rule-based generator (csp-generator.js)Risk ScorerCustom scoring engine (risk-scorer.js)Diff EngineCustom CSP diff + HTML renderer (csp-diff.js)TestingVitest
DevOps / Monitoring

Prometheus — metrics scraping
Grafana — pre-built dashboard JSON (grafana/dashboard.json)


📁 Project Structure
csp-guardian/
├── backend/                    # FastAPI backend
│   ├── main.py                 # App entrypoint, middleware, WebSocket, health check
│   ├── security.py             # API key auth, CORS, domain sanitizer, LLM output validator
│   ├── requirements.txt        # Python dependencies
│   ├── db/
│   │   ├── models.py           # SQLAlchemy ORM: AnalysisRecord, ViolationReport
│   │   └── database.py         # Engine, session, init_db()
│   ├── routers/
│   │   ├── analyze.py          # POST /analyze — AI analysis endpoint
│   │   ├── violations.py       # POST /csp-report, GET /violations
│   │   ├── history.py          # GET/DELETE /history — analysis history CRUD
│   │   └── monitoring.py       # GET /metrics, /metrics/summary, /metrics/health/detailed
│   ├── services/
│   │   ├── llm_service.py      # Multi-LLM dispatcher (Groq, Gemini, Anthropic, OpenAI)
│   │   ├── notifier.py         # WebSocket connection manager & broadcaster
│   │   ├── metrics.py          # Prometheus counters, histograms, gauges
│   │   └── sentry_service.py   # Sentry init, capture helpers, transaction decorator
│   └── tests/
│       ├── test_api.py         # Full API integration tests
│       ├── test_monitoring.py  # Monitoring endpoints tests
│       └── test_security.py    # Security utility unit tests
│
├── extension/                  # Chrome Extension (Manifest V3)
│   ├── manifest.json           # Extension manifest
│   ├── background.js           # Service worker: resource interception, message hub
│   ├── content.js              # Inline script & eval() detection via DOM + MutationObserver
│   ├── popup/
│   │   ├── popup.html          # Extension popup UI
│   │   ├── popup.js            # Popup logic: recording, AI call, diff, violations, history
│   │   └── popup.css           # Dark-theme UI styles
│   ├── utils/
│   │   ├── csp-generator.js    # Rule-based CSP builder from collected resources
│   │   ├── risk-scorer.js      # Risk scoring engine (0–100)
│   │   └── csp-diff.js         # CSP diff engine + HTML renderer
│   └── types/
│       └── index.ts            # TypeScript type definitions
│
├── tests/
│   └── extension/
│       └── csp-diff.test.js    # Vitest unit tests for diff engine
│
├── grafana/
│   └── dashboard.json          # Pre-built Grafana monitoring dashboard
│
├── prometheus.yml              # Prometheus scrape configuration
├── package.json                # Node.js dev dependencies (Vitest)
└── vitest.config.js            # Vitest configuration

⚙️ Installation
Prerequisites

Python 3.10+
Node.js 18+ (for extension tests)
Chrome browser
At least one LLM API key (Groq, Gemini, Anthropic, or OpenAI)


1. Clone the Repository
bashgit clone https://github.com/tphu14/tphu14-csp-guardian.git
cd tphu14-csp-guardian

2. Backend Setup
bashcd backend

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
Create your .env file inside backend/:
env# LLM Provider — set at least ONE
GROQ_API_KEY=your_groq_api_key

# Optional: explicitly select a provider (groq | gemini | anthropic | openai)
LLM_PROVIDER=groq

# Optional: API key for endpoint protection
CSP_GUARDIAN_API_KEY=your_secret_key

# Optional: Sentry error tracking
SENTRY_DSN=https://your_dsn@sentry.io/project

# Optional: production database
DATABASE_URL=sqlite:///./csp_guardian.db
Start the backend:
bashuvicorn main:app --reload --host 0.0.0.0 --port 8000
The API will be available at http://localhost:8000.
Interactive docs at http://localhost:8000/docs.

3. Chrome Extension Setup

Open Chrome and navigate to chrome://extensions/
Enable Developer Mode (toggle in the top right)
Click Load unpacked
Select the extension/ folder from this repository
The 🛡️ CSP Guardian icon will appear in your toolbar


4. Run Tests
Backend (pytest):
bashcd backend
pytest tests/ -v
Frontend (Vitest):
bash# From project root
npm install
npm test

5. Optional: Prometheus + Grafana Monitoring
bash# Run Prometheus
prometheus --config.file=prometheus.yml
Then import grafana/dashboard.json into your Grafana instance and set the datasource to Prometheus at http://localhost:9090.

🚀 Usage
Recording & Analyzing a Page

Navigate to any website in Chrome
Click the CSP Guardian 🛡️ icon in the toolbar
Click ▶ Start Recording — the extension begins intercepting all network requests
Browse the page normally (click links, trigger XHR, etc.)
Click ⏹ Stop & Analyze — a rule-based CSP is generated instantly with a risk score

AI Hardening

In the Hardened ✨ tab, click ✨ Analyze with AI
The backend calls your configured LLM provider and returns:

A hardened CSP string with strict-dynamic, nonces, and other improvements
Per-directive explanations in plain English
3–5 concrete security recommendations


Switch to the Diff tab to see a token-level comparison of what changed

Violation Monitoring
Add the report URI to your site's CSP header:
Content-Security-Policy: default-src 'self'; ...; report-uri http://localhost:8000/csp-report
Violations will appear in the Violations tab in real time via WebSocket.
Exporting Results
Click ⬇ Export JSON in the footer to download a full analysis report including the generated CSP, hardened CSP, risk breakdown, AI recommendations, and resource summary.

📸 Example Output
Risk Score: 55 / 100  [Medium]

Breakdown:
  +25  Inline scripts
  +20  HTTP resources
  +10  Many third-party domains

Generated CSP:
  default-src 'self';
  script-src 'self' https://cdn.example.com 'nonce-REPLACE_WITH_RANDOM_NONCE';
  style-src 'self' https://fonts.googleapis.com;
  img-src 'self' data:;
  object-src 'none';
  frame-ancestors 'none';

Hardened CSP (AI):
  default-src 'self';
  script-src 'self' https://cdn.example.com 'strict-dynamic' 'nonce-abc123';
  style-src 'self' https://fonts.googleapis.com;
  upgrade-insecure-requests;
  object-src 'none';
  frame-ancestors 'none';

AI Recommendations:
  1. Replace static nonce placeholder with a server-generated per-request nonce
  2. Remove unsafe-inline from style-src — use nonces for inline styles instead
  3. Add trusted-types policy to prevent DOM XSS attacks
  4. Consider adding require-trusted-types-for 'script'

🔭 Future Improvements

 DevTools Panel — Embed CSP Guardian directly into Chrome DevTools as a dedicated panel
 Nonce Auto-Integration — Server-side middleware snippets (Express, Django, FastAPI) for injecting per-request nonces
 CSP Violation Alerts — Email / Slack / webhook notifications when new violation patterns are detected
 Multi-Tab Recording — Support recording across multiple tabs simultaneously
 CSP Policy Templates — Pre-built policy templates for popular frameworks (React, Next.js, WordPress)
 PostgreSQL Migration Guide — Documented steps for production PostgreSQL deployment
 Standalone Dashboard UI — React web dashboard for the monitoring and history API
 Firefox Support — Port the extension manifest to Firefox WebExtensions API
 CI/CD Pipeline — GitHub Actions workflow for automated testing, linting, and build

👤 Author
tphu14

GitHub: @tphu14
Contact: tfunov14@gmail.com


📄 License
This project is licensed under the MIT License.
