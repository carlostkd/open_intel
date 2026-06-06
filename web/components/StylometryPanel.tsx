"use client";

import { useMemo, useState } from "react";
import type { StylometryData } from "@/lib/hooks/useEntityAnalysis";

// ─── Baseline values (hardcoded reference points from spec) ─────────────────

const BASELINE: Record<string, { label: string; max: number; baseline: number }> = {
  avg_word_length: {
    label: "Avg Word Length",
    max: 12,
    baseline: 4.8,
  },
  avg_sentence_length: {
    label: "Avg Sentence Length",
    max: 40,
    baseline: 12.1,
  },
  punctuation_density: {
    label: "Punctuation Density",
    max: 0.3,
    baseline: 0.12,
  },
  uppercase_ratio: {
    label: "Uppercase Ratio",
    max: 0.5,
    baseline: 0.09,
  },
  vocabulary_richness: {
    label: "Vocabulary Richness",
    max: 1.0,
    baseline: 0.52,
  },
  digit_ratio: {
    label: "Digit Ratio",
    max: 0.2,
    baseline: 0.04,
  },
};

// ─── Deviation helpers ────────────────────────────────────────────────────────

function deviation(value: number, baseline: number): number {
  if (baseline === 0) return 0;
  return (value - baseline) / baseline;
}

function deviationColor(dev: number): string {
  const abs = Math.abs(dev);
  if (abs >= 0.5) return "var(--danger)";
  if (abs >= 0.25) return "var(--warning)";
  return "var(--success)";
}

// ─── Feature bar ─────────────────────────────────────────────────────────────

function FeatureBar({
  label,
  value,
  max,
  baseline,
}: {
  label: string;
  value: number;
  max: number;
  baseline: number;
}) {
  const pct = Math.min(100, (value / max) * 100);
  const baselinePct = Math.min(100, (baseline / max) * 100);
  const dev = deviation(value, baseline);
  const color = deviationColor(dev);

  return (
    <div className="flex flex-col gap-2 p-3 rounded-md border border-[var(--border-dim)] bg-[var(--bg-raised)] group hover:border-[var(--border-strong)] transition-all">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-secondary)]">{label}</span>
        <div className="flex items-baseline gap-1.5">
            <span className="font-mono text-[12px] font-bold" style={{ color }}>{value.toFixed(3)}</span>
            <span className="font-mono text-[9px] text-[var(--text-muted)]">[{baseline}]</span>
        </div>
      </div>
      
      <div className="relative h-1 w-full bg-[var(--bg-void)] rounded-full overflow-hidden">
        {/* Value Fill */}
        <div
          className="h-full transition-all duration-1000 ease-out"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
        {/* Baseline Marker */}
        <div
          className="absolute top-0 bottom-0 w-0.5 bg-white/20 z-10"
          style={{ left: `${baselinePct}%` }}
        />
      </div>
    </div>
  );
}

// ─── Confidence badge ─────────────────────────────────────────────────────────

function ConfidenceBadge({ level }: { level: "low" | "medium" | "high" }) {
  const colors: Record<string, string> = {
    low: "var(--danger)",
    medium: "var(--warning)",
    high: "var(--success)",
  };
  return (
    <span
      className="rounded px-2 py-0.5 text-[9px] font-bold uppercase tracking-widest border border-[rgba(255,255,255,0.05)]"
      style={{
        color: colors[level],
        backgroundColor: "var(--bg-void)",
      }}
    >
      {level}
    </span>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

type Props = {
  entityId: string;
  data: StylometryData | null;
  loading: boolean;
  error: string | null;
  onExpand: () => void;
};

export function StylometryPanel({ entityId: _entityId, data, loading, error, onExpand }: Props) {
  const [expanded, setExpanded] = useState(false);

  const handleToggle = () => {
    const next = !expanded;
    setExpanded(next);
    if (next) onExpand();
  };

  const insufficientData = data?.error === "insufficient_data";
  const analysisFailed =
    (error && !insufficientData) || data?.error === "analysis_failed";
  const hasData = data && !data.error;

  const features = Object.entries(BASELINE)
    .map(([key, meta]) => ({
      key,
      ...meta,
      value: data?.profile?.[key] ?? null,
    }))
    .filter((f) => f.value !== null) as Array<{
    key: string;
    label: string;
    max: number;
    baseline: number;
    value: number;
  }>;

  return (
    <div className="rounded-lg border border-[var(--border-dim)] bg-[var(--bg-surface)] font-sans overflow-hidden transition-all">
      {/* Header */}
      <button
        type="button"
        onClick={handleToggle}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-[var(--bg-raised)] transition-colors"
      >
        <div className="flex items-center gap-3">
          <svg className={`h-4 w-4 transition-colors ${hasData ? "text-[var(--accent)]" : "text-[var(--text-muted)]"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
          </svg>
          <div className="flex flex-col">
            <span className="text-[11px] font-bold text-[var(--text-primary)] tracking-tight uppercase">
              Stylometric Fingerprint
            </span>
            {hasData && (
              <span className="text-[9px] font-medium text-[var(--text-muted)] uppercase tracking-widest">
                Linguistic Analysis
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4">
          {hasData && (
            <div className="flex items-center gap-2">
              <span className="text-[9px] font-bold text-[var(--text-muted)] uppercase tracking-widest">Confidence</span>
              <ConfidenceBadge level={data.confidence} />
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
               <p className="text-[11px] font-mono text-[var(--accent)] uppercase tracking-widest">Processing Linguistic Footprint</p>
             </div>
          )}

          {analysisFailed && !loading && (
             <div className="flex items-center gap-3 rounded-md bg-[var(--danger-dim)] p-3 border border-[rgba(255,0,0,0.1)]">
                 <p className="text-[var(--danger)] text-[11px] font-medium">Linguistic engine unreachable. {error ?? "Analysis failed."}</p>
             </div>
          )}

          {insufficientData && !loading && (
            <div className="space-y-2">
              <p className="text-[var(--warning)] text-[11px] font-bold uppercase tracking-widest">Sample Size Inadequate</p>
              <p className="text-[var(--text-secondary)] text-[12px] leading-relaxed">
                Minimum of 3 textual artifacts are required to establish a reliable fingerprint.
              </p>
            </div>
          )}

          {hasData && !loading && (
            <>
              {/* Feature grid */}
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-[var(--border-dim)] pb-2 text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">
                   <span>Technical Metrics</span>
                   <span>Value vs Baseline</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {features.map((f) => (
                    <FeatureBar
                      key={f.key}
                      label={f.label}
                      value={f.value}
                      max={f.max}
                      baseline={f.baseline}
                    />
                  ))}
                </div>
              </div>

              {/* Notable Traits */}
              {data.notable_traits && data.notable_traits.length > 0 && (
                <div className="space-y-3 pt-2">
                  <h4 className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-secondary)]">Heuristic Anomalies</h4>
                  <div className="space-y-2">
                    {data.notable_traits.map((trait, i) => (
                      <div key={i} className="flex items-start gap-3 p-3 rounded-md bg-[var(--bg-raised)] border border-[var(--border-dim)]">
                        <span className="text-[var(--warning)] mt-0.5">◈</span>
                        <p className="text-[11px] text-[var(--text-secondary)] leading-tight">{trait}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <footer className="pt-4 flex flex-col gap-4 border-t border-[var(--border-dim)]">
                {data.similar_actors && data.similar_actors.length > 0 && (
                  <div className="space-y-3">
                    <div className="text-[10px] font-bold uppercase tracking-widest text-[var(--danger)] flex items-center gap-2">
                       <span className="h-1.5 w-1.5 rounded-full bg-[var(--danger)] animate-pulse" />
                       Possible Same Actor Matches
                    </div>
                    <div className="space-y-2">
                      {data.similar_actors.map((match) => (
                        <div
                          key={match.canonical_value}
                          className="flex items-center justify-between p-3 rounded-md bg-[var(--bg-void)] border border-[rgba(255,0,0,0.1)] hover:border-[rgba(255,0,0,0.3)] transition-all group"
                        >
                          <div className="flex flex-col gap-0.5">
                            <span className="font-mono text-[12px] font-bold text-[var(--text-primary)] group-hover:text-[var(--danger)] transition-colors">
                              {match.canonical_value}
                            </span>
                            <span className="text-[9px] text-[var(--text-muted)] font-mono uppercase tracking-tighter">
                              {match.entity_type}
                            </span>
                          </div>
                          <div className="flex items-center gap-3">
                            <div className="flex flex-col items-end">
                              <span className={`text-[11px] font-mono font-bold ${
                                match.confidence === 'high' ? 'text-[var(--danger)]' :
                                match.confidence === 'medium' ? 'text-[var(--warning)]' :
                                'text-[var(--text-muted)]'
                              }`}>
                                {(match.similarity_score * 100).toFixed(0)}% Match
                              </span>
                              <span className="text-[8px] text-[var(--text-muted)] uppercase tracking-widest font-bold">
                                Confidence: {match.confidence}
                              </span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                    <p className="text-[9px] text-[var(--text-muted)] italic font-medium leading-tight">
                      Note: Stylometric attribution is probabilistic. Cross-reference with metadata and 
                      infrastructure analysis before confirming attribution.
                    </p>
                  </div>
                )}

                <div className="flex items-center justify-between text-[9px] text-[var(--text-muted)] uppercase tracking-widest font-medium">
                  <span>Samples: {data.text_samples}</span>
                  <span>{data.total_chars.toLocaleString()} Chars</span>
                </div>
              </footer>
            </>
          )}
        </div>
      )}
    </div>
  );
}

