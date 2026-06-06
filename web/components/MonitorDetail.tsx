"use client";

import type { Monitor } from "@/types/monitor";
import { useMonitorAlerts } from "@/hooks/useMonitorAlerts";

type Props = {
  monitor: Monitor;
  onTrigger: () => void;
  onDelete: () => void;
  triggerLoading: boolean;
  triggerError: string | null;
  onAlertsAcknowledged?: () => void;
};

function intervalLabel(hours: number): string {
  if (hours === 24) return "every 24 hours";
  if (hours === 48) return "every 48 hours";
  if (hours === 72) return "every 72 hours";
  if (hours >= 168) return "weekly";
  if (hours < 1) return `every ${Math.round(hours * 60)} minutes`;
  return `every ${hours} hours`;
}

function ChannelBadge({ channel }: { channel: string }) {
  const labels: Record<string, string> = {
    webhook: "WEBHOOK",
    telegram: "TELEGRAM",
    email: "EMAIL",
  };
  return (
    <span className="inline-block rounded-sm border border-[var(--border-strong)] bg-[var(--bg-raised)] px-2 py-0.5 text-[9px] font-bold tracking-widest text-[var(--accent)]">
      {labels[channel] ?? channel.toUpperCase()}
    </span>
  );
}

function relativeFromUtc(iso: string): string {
  const t = new Date(iso).getTime();
  const diff = Date.now() - t;
  const abs = Math.abs(diff);
  if (abs < 60_000) return "just now";
  if (abs < 3_600_000) return `${Math.floor(abs / 60_000)}m ago`;
  if (abs < 86_400_000) return `${Math.floor(abs / 3_600_000)}h ago`;
  return `${Math.floor(abs / 86_400_000)}d ago`;
}

function SeverityBadge({
  severity,
  acknowledged,
}: {
  severity: string;
  acknowledged: boolean;
}) {
  const s = severity.toLowerCase();
  const dim = acknowledged ? "opacity-40" : "";
  
  if (s === "critical") {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 border border-[var(--danger)]/30 bg-[var(--danger-dim)] text-[9px] font-bold text-[var(--danger)] uppercase tracking-widest ${dim}`}>
        <span className="h-1.5 w-1.5 rounded-full bg-[var(--danger)] animate-pulse" />
        Critical
      </span>
    );
  }
  if (s === "warning") {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 border border-[var(--warning)]/30 bg-[var(--warning-dim)] text-[9px] font-bold text-[var(--warning)] uppercase tracking-widest ${dim}`}>
        <span className="h-1.5 w-1.5 rounded-full bg-[var(--warning)]" />
        Warning
      </span>
    );
  }
  return (
    <span className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 border border-[var(--border-dim)] bg-[var(--bg-raised)] text-[9px] font-bold text-[var(--text-muted)] uppercase tracking-widest ${dim}`}>
       <span className="h-1.5 w-1.5 rounded-full bg-[var(--text-muted)] opacity-50" />
       Info
    </span>
  );
}

export function MonitorDetail({
  monitor,
  onTrigger,
  onDelete,
  triggerLoading,
  triggerError,
  onAlertsAcknowledged,
}: Props) {
  const { alerts, loading, error, acknowledgeAll } = useMonitorAlerts(
    monitor.id
  );

  const handleMarkAll = async () => {
    const ok = await acknowledgeAll();
    if (ok) onAlertsAcknowledged?.();
  };

  return (
    <div className="bg-[var(--bg-void)] p-8 space-y-8">
      {/* Target & Control Row */}
      <div className="flex flex-wrap items-start justify-between gap-6">
        <div className="space-y-1.5">
          <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-[var(--accent)]">Watchpoint Target</p>
          <p className="text-xl font-heading font-bold text-[var(--text-primary)] leading-tight">{monitor.query}</p>
          <div className="flex items-center gap-3 pt-1">
             <span className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Subsystem ID:</span>
             <span className="font-mono text-[10px] text-[var(--text-secondary)] bg-[var(--bg-surface)] px-1.5 py-0.5 rounded border border-[var(--border-dim)] uppercase">{monitor.id}</span>
          </div>
        </div>

        <div className="flex gap-2">
           <button
             type="button"
             onClick={onTrigger}
             disabled={triggerLoading}
             className="px-6 h-10 text-[11px] font-bold uppercase tracking-[0.15em] rounded bg-[var(--accent)] text-[var(--text-inverse)] hover:shadow-[0_0_20px_var(--accent-dim)] transition-all disabled:opacity-50"
           >
             {triggerLoading ? "PROBING..." : "PROBE NOW"}
           </button>
           <button
             type="button"
             onClick={onDelete}
             className="px-4 h-10 text-[11px] font-bold uppercase tracking-[0.15em] rounded border border-[var(--danger)] text-[var(--danger)] hover:bg-[var(--danger-dim)] transition-all"
           >
             TERMINATE
           </button>
        </div>
      </div>

      {/* Surveillance Metadata */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 p-5 rounded-lg border border-[var(--border-dim)] bg-[var(--bg-raised)]">
        <div className="space-y-1">
          <p className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Classification</p>
          <p className="text-[11px] font-bold text-[var(--text-secondary)] uppercase">{monitor.type === "keyword" ? "Keyword Analysis" : "URL Surveillance"}</p>
        </div>
        <div className="space-y-1">
          <p className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Duty Cycle</p>
          <p className="text-[11px] font-bold text-[var(--text-secondary)] uppercase">{intervalLabel(monitor.check_interval_hours)}</p>
        </div>
        <div className="space-y-1">
          <p className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Last Recon</p>
          <p className="text-[11px] font-mono text-[var(--text-secondary)]">{monitor.last_checked_at ? new Date(monitor.last_checked_at).toISOString().replace("T", " ").slice(0, 16) + " Z" : "Never"}</p>
        </div>
        <div className="space-y-1">
          <p className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Alert Trigger</p>
          <p className="text-[11px] font-bold text-[var(--text-secondary)] uppercase">{monitor.alert_on.replace(/_/g, " ")}</p>
        </div>
      </div>

      {/* Notification Stream */}
      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-[var(--border-dim)] pb-3">
           <h4 className="text-[11px] font-bold uppercase tracking-widest text-[var(--text-primary)]">Intelligence Feed</h4>
           {alerts.length > 0 && (
             <button
               type="button"
               onClick={() => void handleMarkAll()}
               className="text-[10px] font-bold uppercase tracking-widest text-[var(--accent)] hover:underline"
             >
               ACKNOWLEDGE ALL
             </button>
           )}
        </div>

        {error && (
          <div className="p-3 bg-[var(--danger-dim)] border border-[var(--danger)]/20 rounded-md">
             <p className="text-[11px] text-[var(--danger)] font-medium">Node Sync Error: {error}</p>
          </div>
        )}
        
        {loading && (
          <div className="flex items-center gap-3 py-6">
             <div className="h-4 w-4 animate-spin rounded-full border border-[var(--accent)] border-t-transparent" />
             <p className="text-[11px] font-mono text-[var(--accent)] uppercase tracking-[0.2em]">Synchronizing Stream...</p>
          </div>
        )}

        {!loading && alerts.length === 0 && (
          <div className="py-12 flex flex-col items-center opacity-30">
             <p className="text-[11px] font-bold uppercase tracking-widest">No spectral movements detected.</p>
          </div>
        )}

        <div className="space-y-3">
          {alerts.map((a) => (
            <div
              key={a.id}
              className={`group p-4 rounded-md border border-[var(--border-dim)] bg-[var(--bg-surface)] hover:border-[var(--border-strong)] transition-all ${a.acknowledged ? "opacity-60 saturate-0" : ""}`}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex flex-wrap items-center gap-3">
                  <SeverityBadge severity={a.severity} acknowledged={a.acknowledged} />
                  <span className="font-mono text-[10px] text-[var(--text-muted)] uppercase tracking-tight">
                    {new Date(a.triggered_at).toISOString().replace("T", " ").slice(11, 19)} UTC
                  </span>
                  <span className="text-[10px] text-[var(--text-muted)] font-medium">
                     {relativeFromUtc(a.triggered_at)}
                  </span>
                </div>
              </div>

              <div className="space-y-1">
                <p className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)] opacity-50">{a.change_type}</p>
                <p className="text-[12px] text-[var(--text-secondary)] leading-snug">{a.summary || "Target state verified."}</p>
              </div>

              {a.delivery_channels && a.delivery_channels.length > 0 && (
                <div className="mt-4 pt-3 border-t border-[var(--border-dim)]/50 flex flex-wrap items-center gap-3">
                  <span className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Exfiltration:</span>
                  <div className="flex gap-2">
                    {a.delivery_channels.map((ch) => (
                      <ChannelBadge key={ch} channel={ch} />
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {triggerError && (
        <div className="p-3 bg-[var(--danger-dim)] border border-[var(--danger)] border-l-4">
           <p className="text-[11px] text-[var(--danger)] font-bold">EXECUTION FAULT: {triggerError}</p>
        </div>
      )}
    </div>
  );
}
