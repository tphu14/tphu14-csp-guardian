// CSP Guardian v3 – types/index.ts
// Central TypeScript type definitions

// ── Resource Types ────────────────────────────────────────────────────────────
export type ResourceCategory =
  | "scripts" | "styles" | "images" | "xhr"
  | "frames" | "fonts" | "media";

export interface ResourceEntry {
  url: string;
  domain: string;
  isInline: boolean;
  scheme: "https" | "http" | string;
}

export interface InlineScriptEntry {
  snippet: string;
  hasEval: boolean;
  source: "inline-tag" | "eval-monitor" | "dynamic-injection";
}

export interface CollectedResources {
  scripts:       ResourceEntry[];
  styles:        ResourceEntry[];
  images:        ResourceEntry[];
  xhr:           ResourceEntry[];
  frames:        ResourceEntry[];
  fonts:         ResourceEntry[];
  media:         ResourceEntry[];
  inlineScripts: InlineScriptEntry[];
  evalDetected:  boolean;
  wildcardDomains: string[];
}

// ── CSP Generator Types ───────────────────────────────────────────────────────
export interface CSPDirectives {
  [directive: string]: string[];
}

export interface CSPResult {
  csp:             string;
  directives:      CSPDirectives;
  warnings:        string[];
  hasInlineScripts: boolean;
  hasEval:         boolean;
}

// ── Risk Score Types ──────────────────────────────────────────────────────────
export type RiskLevel = "Low" | "Medium" | "High";

export interface RiskBreakdown {
  [reason: string]: number;
}

export interface RiskStats {
  totalResources:  number;
  thirdPartyDomains: number;
  inlineScripts:   number;
  wildcardDomains: number;
}

export interface RiskResult {
  risk_score:  number;
  risk_level:  RiskLevel;
  risk_color:  string;
  issues:      string[];
  breakdown:   RiskBreakdown;
  stats:       RiskStats;
}

// ── CSP Diff Types ────────────────────────────────────────────────────────────
export type DiffLineType = "added" | "removed" | "unchanged";

export interface DiffLine {
  type:      DiffLineType;
  directive: string;
  values:    string[];
  oldValues?: string[];
  newValues?: string[];
}

export interface CSPDiff {
  lines:    DiffLine[];
  added:    number;
  removed:  number;
  changed:  number;
}

// ── Backend API Types ─────────────────────────────────────────────────────────
export interface ResourceSummary {
  script_domains:   string[];
  style_domains:    string[];
  connect_domains:  string[];
  inline_script:    boolean;
  eval_detected:    boolean;
  wildcard_used:    boolean;
  wildcard_domains: string[];
}

export interface AnalyzeRequest {
  domain:           string;
  resource_summary: ResourceSummary;
  generated_csp:    string;
  risk_score:       number;
  risk_level:       string;
  issues:           string[];
  resource_stats:   Partial<RiskStats>;
}

export interface AIAnalysisResult {
  hardened_csp:    string;
  explanation:     Record<string, string> | string;
  recommendations: string[];
  analysis_id?:    number;
  provider?:       string;
}

// ── WebSocket Types ───────────────────────────────────────────────────────────
export interface WSMessage {
  type: "violation" | "analysis_complete" | "pong";
  data?: ViolationData | AnalysisRecord;
}

export interface ViolationData {
  id:                   number;
  domain:               string;
  violated_directive:   string;
  effective_directive:  string;
  blocked_uri:          string;
  document_uri:         string;
  received_at:          string;
  disposition:          string;
  source_file?:         string;
  line_number?:         number;
}

export interface AnalysisRecord {
  id:              number;
  domain:          string;
  created_at:      string;
  risk_score:      number;
  risk_level:      RiskLevel;
  generated_csp:   string;
  hardened_csp?:   string;
  issues:          string[];
  recommendations: string[];
  llm_provider?:   string;
  violation_count: number;
}

// ── Extension State ───────────────────────────────────────────────────────────
export interface ExtensionState {
  isRecording:    boolean;
  resources:      CollectedResources | null;
  cspResult:      CSPResult | null;
  riskResult:     RiskResult | null;
  aiResult:       AIAnalysisResult | null;
  analysisId:     number | null;
  currentDomain:  string | null;
  violations:     ViolationData[];
}

// ── Message Types (background <-> popup) ──────────────────────────────────────
export type MessageType =
  | "START_RECORDING"
  | "STOP_RECORDING"
  | "GET_STATUS"
  | "GET_RESOURCES"
  | "INLINE_SCRIPT_DETECTED"
  | "DEVTOOLS_RESOURCE";

export interface ExtensionMessage {
  type: MessageType;
  data?: Record<string, unknown>;
}

export interface RecordingStatus {
  isRecording: boolean;
  tabId:       number | null;
  count:       number;
}