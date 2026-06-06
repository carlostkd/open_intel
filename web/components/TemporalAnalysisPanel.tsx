"use client";

import { useEffect, useState } from "react";
import { useTemporalAnalysis } from "@/lib/hooks/useTemporalAnalysis";

// ─── Heatmap color helper ────────────────────────────────────────────────────

function heatmapColor(value: number, max: number): string {
  if (value === 0) return "var(--bg-void)";
  const ratio = max > 0 ? value / max : 0;
  if (ratio < 0.25) return "var(--accent-dim)";
  if (ratio < 0.6) return "var(--accent-border)";
  return "var(--accent)";
}

// ─── Main component ───────────────────────────────────────────────────────────

type Props = {
  investigationId: string;
};

export function TemporalAnalysisPanel({ investigationId }: Props) {
  const [expanded, setExpanded] = useState(false);
  const { data, loading, error, fetched, trigger } = useTemporalAnalysis(investigationId);

  // Fetch when panel is first expanded
  useEffect(() => {
    if (expanded && !fetched) {
      void trigger();
    }
  }, [expanded, fetched, trigger]);

  const hours = Array.from({ length: 24 }, (_, i) => i);
  const hourValues = hours.map((h) => data?.activity_by_hour?.[String(h)] ?? 0);
  const maxHour = Math.max(...hourValues, 1);

  const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  const dayValues = days.map((d) => data?.activity_by_day?.[d] ?? 0);
  const maxDay = Math.max(...dayValues, 1);

  const insufficientData = data?.error === "insufficient_data";
  const analysisFailed = data?.error === "analysis_failed" || (error && !insufficientData);

  return (
    <div className="rounded-lg border border-[var(--border-dim)] bg-[var(--bg-surface)] font-sans overflow-hidden transition-all">
      {/* Header */}
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-[var(--bg-raised)] transition-colors"
      >
        <div className="flex items-center gap-3">
          <svg className={`h-4 w-4 transition-colors ${data && !data.error ? "text-[var(--accent)]" : "text-[var(--text-muted)]"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div className="flex flex-col">
            <span className="text-[11px] font-bold text-[var(--text-primary)] tracking-tight uppercase">
              Temporal Patterns
            </span>
            {data && !data.error && (
              <span className="text-[9px] font-medium text-[var(--text-muted)] uppercase tracking-widest">
                Signal Chronology
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4">
          {data && !data.error && (
            <div className="flex items-center gap-2">
              <span className="text-[9px] font-bold text-[var(--text-muted)] uppercase tracking-widest">Span</span>
              <span className="font-mono text-[9px] text-[var(--text-secondary)] bg-[var(--bg-void)] px-1.5 py-0.5 rounded border border-[rgba(255,255,255,0.05)]">
                {data.total_timespan_days}d
              </span>
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
        <div className="border-t border-[var(--border-dim)] p-5 space-y-8 animate-in slide-in-from-top-2 duration-300">
          
          {loading && (
             <div className="flex items-center gap-3">
               <div className="h-3 w-3 animate-spin rounded-full border border-[var(--accent)] border-t-transparent" />
               <p className="text-[11px] font-mono text-[var(--accent)] uppercase tracking-widest">Reconstructing Timeline</p>
             </div>
          )}

          {analysisFailed && !loading && (
             <div className="flex items-center gap-3 rounded-md bg-[var(--danger-dim)] p-3 border border-[rgba(255,0,0,0.1)]">
                 <p className="text-[var(--danger)] text-[11px] font-medium">Temporal engine error. {error ?? "Analysis failed."}</p>
             </div>
          )}

          {insufficientData && !loading && (
            <div className="space-y-2">
              <p className="text-[var(--warning)] text-[11px] font-bold uppercase tracking-widest">Trace Sparse</p>
              <p className="text-[var(--text-secondary)] text-[12px] leading-relaxed">
                Chronological artifacts are too fragmented to establish a reliable activity baseline.
              </p>
            </div>
          )}

          {data && !data.error && !loading && (
            <>
              {/* Hourly Grid */}
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-[var(--border-dim)] pb-2 text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">
                   <span>Activity Intensity (24h UTC)</span>
                   <span className="text-[var(--accent)]">Peak: {String(data.peak_hour).padStart(2, "0")}:00</span>
                </div>
                
                <div className="grid grid-cols-12 gap-1.5">
                  {hours.map((h) => {
                    const v = data.activity_by_hour[String(h)] ?? 0;
                    return (
                      <div key={h} className="group relative">
                        <div 
                          className="aspect-square rounded-sm border border-[rgba(255,255,255,0.03)] transition-all group-hover:scale-110 group-hover:z-10 group-hover:shadow-[0_0_10px_var(--accent-dim)]"
                          style={{ backgroundColor: heatmapColor(v, maxHour) }}
                        />
                        <div className="mt-1 text-center font-mono text-[8px] text-[var(--text-muted)] opacity-50 select-none">
                            {String(h).padStart(2, "0")}
                        </div>
                        {/* Tooltip (CSS only simulation) */}
                        <div className="pointer-events-none absolute -top-8 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 bg-[var(--bg-surface)] border border-[var(--border-strong)] px-2 py-1 rounded text-[9px] whitespace-nowrap z-20 transition-opacity">
                            {h}:00 — {v} events
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Weekly and Anomalies */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-2">
                {/* Weekly Distribution */}
                <div className="space-y-4">
                   <h4 className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-secondary)] border-b border-[var(--border-dim)] pb-2">Periodic Distribution</h4>
                   <div className="flex items-end gap-1.5 h-16">
                      {days.map((d, i) => {
                        const v = data.activity_by_day[d] ?? 0;
                        const ratio = maxDay > 0 ? v / maxDay : 0;
                        return (
                          <div key={d} className="flex-1 flex flex-col items-center gap-1 group">
                             <div 
                                className="w-full rounded-t-sm bg-[var(--accent)] opacity-20 group-hover:opacity-60 transition-all duration-500"
                                style={{ height: `${Math.max(10, ratio * 100)}%`, backgroundColor: ratio > 0 ? "var(--accent)" : "var(--bg-raised)" }}
                             />
                             <span className="font-mono text-[8px] text-[var(--text-muted)] uppercase tracking-tighter">
                                {d.slice(0, 2)}
                             </span>
                          </div>
                        );
                      })}
                   </div>
                </div>

                {/* Anomalies List */}
                <div className="space-y-4">
                   <h4 className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-secondary)] border-b border-[var(--border-dim)] pb-2">Anomalous Deviations</h4>
                   {(data.anomalies.length > 0 || data.silence_breaks.length > 0) ? (
                      <div className="space-y-2">
                        {data.anomalies.map((a, i) => (
                          <div key={i} className="flex items-start gap-2 border-l-2 border-[var(--warning)] bg-[var(--warning-dim)] p-2">
                             <span className="text-[9px] font-mono text-[var(--text-muted)] opacity-50 shrink-0">{a.date.split('-').slice(1).join('/')}</span>
                             <p className="text-[10px] text-[var(--warning)] leading-tight">{a.description}</p>
                          </div>
                        ))}
                        {data.silence_breaks.map((s, i) => (
                          <div key={`sb-${i}`} className="flex items-start gap-2 border-l-2 border-[var(--danger)] bg-[var(--danger-dim)] p-2">
                             <span className="text-[9px] font-mono text-[var(--text-muted)] opacity-50 shrink-0">{s.gap_days}d</span>
                             <p className="text-[10px] text-[var(--danger)] leading-tight">Timeline fracture: Prolonged inactivity.</p>
                          </div>
                        ))}
                      </div>
                   ) : (
                      <div className="flex items-center gap-3 p-3 rounded-md border border-[var(--border-dim)] bg-[var(--bg-raised)]">
                         <span className="text-[var(--success)] text-[10px]">✓</span>
                         <p className="text-[10px] text-[var(--text-muted)]">Timeline follows expected periodicity.</p>
                      </div>
                   )}
                </div>
              </div>

              <footer className="pt-4 flex items-center justify-between border-t border-[var(--border-dim)] text-[9px] text-[var(--text-muted)] uppercase tracking-widest font-medium">
                  <span>Datapoints: {data.data_points}</span>
                  <span>Source: UTC-Z</span>
              </footer>
            </>
          )}
        </div>
      )}
    </div>
  );
}

