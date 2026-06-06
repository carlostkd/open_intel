"use client";

import { useMemo, useState } from "react";
import type { OpsecData, OpsecFinding } from "@/lib/hooks/useEntityAnalysis";

// ─── Score helpers ────────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score <= 50) return "var(--danger)";
  if (score <= 70) return "var(--warning)";
  return "var(--success)";
}

function riskLevelColor(level: string): string {
  switch (level) {
    case "CRITICAL":
    case "HIGH":
      return "var(--danger)";
    case "MEDIUM":
      return "var(--warning)";
    default:
      return "var(--success)";
  }
}

// ─── Severity badge ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: OpsecFinding["severity"] }) {
  const map: Record<string, { bg: string; text: string }> = {
    critical: { bg: "var(--danger-dim)", text: "var(--danger)" },
    high: { bg: "var(--danger-dim)", text: "var(--danger)" },
    medium: { bg: "var(--warning-dim)", text: "var(--warning)" },
    low: { bg: "var(--bg-raised)", text: "var(--text-muted)" },
  };
  const s = severity.toLowerCase() as OpsecFinding["severity"];
  const style = map[s] ?? map.low;
  return (
    <span
      className="rounded px-1.5 py-0.5 text-[9px] uppercase tracking-tighter shrink-0 font-bold border"
      style={{
        backgroundColor: style.bg,
        color: style.text,
        borderColor: "rgba(255, 255, 255, 0.05)",
      }}
    >
      {severity}
    </span>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

type Props = {
  entityId: string;
  data: OpsecData | null;
  loading: boolean;
  error: string | null;
  onExpand: () => void;
};

export function OpsecPanel({ entityId: _entityId, data, loading, error, onExpand }: Props) {
  const [expanded, setExpanded] = useState(false);

  const handleToggle = () => {
    const next = !expanded;
    setExpanded(next);
    if (next) onExpand();
  };

  const insufficientData = data?.error === "insufficient_data";
  const analysisFailed =
    (error && !insufficientData) || data?.error === "analysis_failed";
  const hasData = data && !data.error && data.opsec_score !== null;

  const score = data?.opsec_score ?? 0;
  const riskLevel = data?.risk_level ?? "LOW";

  return (
    <div
      className="rounded-lg border border-[var(--border-dim)] bg-[var(--bg-surface)] font-sans overflow-hidden transition-all"
    >
      {/* Header */}
      <button
        type="button"
        onClick={handleToggle}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-[var(--bg-raised)] transition-colors"
      >
        <div className="flex items-center gap-3">
          <svg className={`h-4 w-4 transition-colors ${hasData ? "text-[var(--accent)]" : "text-[var(--text-muted)]"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <div className="flex flex-col">
              <span className="text-[11px] font-bold text-[var(--text-primary)] tracking-tight uppercase">
                OPSEC Assessment
              </span>
              {hasData && (
                <span className="text-[9px] font-medium text-[var(--text-muted)] uppercase tracking-widest">
                  Foundations & Anomalies
                </span>
              )}
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          {hasData && (
            <div className="flex items-center gap-2 px-2 py-0.5 rounded border border-[var(--border-subtle)] bg-[var(--bg-void)]">
               <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: riskLevelColor(riskLevel) }} />
               <span className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-secondary)]">Risk: {riskLevel}</span>
            </div>
          )}
          <svg
            className={`h-4 w-4 text-[var(--text-muted)] transition-transform duration-300 ${expanded ? "rotate-180" : ""}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[var(--border-dim)] p-5 space-y-6 animate-in slide-in-from-top-2 duration-300">

          {loading && (
            <div className="flex items-center gap-3">
              <div className="h-3 w-3 animate-spin rounded-full border border-[var(--accent)] border-t-transparent" />
              <p className="text-[11px] font-mono text-[var(--accent)] uppercase tracking-widest">Initialising Vulnerability Scan</p>
            </div>
          )}

          {analysisFailed && !loading && (
            <div className="flex items-center gap-3 rounded-md bg-[var(--danger-dim)] p-3 border border-[rgba(255,0,0,0.1)]">
                <span className="text-[var(--danger)]">⚠</span>
                <p className="text-[var(--danger)] text-[11px] font-medium">
                  Analysis interrupted. {error ?? data?.message ?? "System modules unavailable."}
                </p>
            </div>
          )}

          {insufficientData && !loading && (
            <div className="space-y-2">
              <p className="text-[var(--warning)] text-[11px] font-bold uppercase tracking-widest">Insufficient Signal</p>
              <p className="text-[var(--text-secondary)] text-[12px] leading-relaxed">
                {data?.message || "Entity exhibits zero textual footprints. Unable to calculate vulnerability scores."}
              </p>
            </div>
          )}

          {hasData && !loading && (
            <>
              {/* Score Display */}
              <div className="flex items-end justify-between">
                <div className="space-y-1">
                  <span className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Composite Security Score</span>
                  <div className="flex items-baseline gap-2">
                    <span className="text-4xl font-bold font-mono tracking-tighter" style={{ color: scoreColor(score) }}>{score}</span>
                    <span className="text-[12px] font-bold text-[var(--text-muted)] uppercase">/ 100</span>
                  </div>
                </div>
                <div className="text-right space-y-1">
                    <span className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Threat Impact</span>
                    <p className="text-[11px] font-bold text-[var(--text-primary)]">{riskLevel === "LOW" ? "Negligible" : riskLevel === "MEDIUM" ? "Moderate" : "Significant"}</p>
                </div>
              </div>

              {/* Score bar */}
              <div className="h-1.5 w-full rounded-full bg-[var(--bg-void)] overflow-hidden">
                <div
                  className="h-full transition-all duration-1000 ease-out"
                  style={{
                    width: `${score}%`,
                    backgroundColor: scoreColor(score),
                  }}
                />
              </div>

              {/* Findings Section */}
              <div className="space-y-4 pt-2">
                <div className="flex items-center justify-between border-b border-[var(--border-dim)] pb-2">
                    <h4 className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-secondary)]">Detected Irregularities</h4>
                    <span className="font-mono text-[10px] text-[var(--text-muted)]">[{data.findings.length}]</span>
                </div>

                {data.findings.length === 0 ? (
                  <div className="flex items-center gap-3 p-4 rounded-lg border border-[var(--border-dim)] bg-[var(--bg-raised)]">
                    <div className="flex h-6 w-6 items-center justify-center rounded-full bg-[var(--success-dim)] text-[var(--success)] text-[10px]">✓</div>
                    <div className="space-y-0.5">
                        <p className="text-[11px] font-bold text-[var(--text-primary)]">Clean Trace</p>
                        <p className="text-[10px] text-[var(--text-muted)]">No active OPSEC deviations identified in this data subset.</p>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {data.findings.map((finding, i) => (
                      <div key={i} className="group relative rounded-lg border border-[var(--border-dim)] bg-[var(--bg-raised)] p-4 transition-all hover:border-[var(--border-strong)]">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-3">
                            <SeverityBadge severity={finding.severity} />
                            <span className="text-[11px] font-bold text-[var(--text-primary)] uppercase tracking-tight">
                              {finding.type.replace(/_/g, " ")}
                            </span>
                          </div>
                          {finding.first_detected && (
                            <span className="font-mono text-[9px] text-[var(--text-muted)]">{finding.first_detected.split('T')[0]}</span>
                          )}
                        </div>
                        <p className="text-[12px] text-[var(--text-secondary)] leading-relaxed mb-3">
                          {finding.description}
                        </p>
                        <div className="rounded border border-[var(--border-dim)] bg-[var(--bg-void)] p-2.5">
                            <span className="block text-[8px] font-bold uppercase tracking-widest text-[var(--text-muted)] mb-1">Evidence Hash</span>
                            <p className="font-mono text-[10px] text-[var(--accent)] break-all leading-snug">
                                {finding.evidence}
                            </p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              
              <footer className="pt-4 flex items-center justify-between border-t border-[var(--border-dim)] text-[9px] text-[var(--text-muted)] uppercase tracking-widest font-medium">
                  <span>Samples: {data.pages_analyzed}</span>
                  <span>Integrity Verified</span>
              </footer>
            </>
          )}
        </div>
      )}
    </div>
  );
}

