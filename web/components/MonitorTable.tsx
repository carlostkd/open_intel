"use client";

import { Fragment, useState } from "react";
import type { Monitor } from "@/types/monitor";
import { MonitorDetail } from "@/components/MonitorDetail";

type Props = {
  monitors: Monitor[];
  onTrigger: (id: string) => Promise<{ error?: string }>;
  onDelete: (id: string) => Promise<{ error?: string }>;
  onAlertsAcknowledged?: () => void;
};

function relativeTime(iso: string | null): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const abs = Math.abs(diff);
  if (abs < 60_000) return "just now";
  if (abs < 3_600_000) return `${Math.floor(abs / 60_000)}m ago`;
  if (abs < 86_400_000) return `${Math.floor(abs / 3_600_000)}h ago`;
  return `${Math.floor(abs / 86_400_000)}d ago`;
}

function relativeNext(iso: string | null): string {
  if (!iso) return "—";
  const diff = new Date(iso).getTime() - Date.now();
  if (diff <= 0) return "imminent";
  if (diff < 3_600_000) return `in ${Math.floor(diff / 60_000)}m`;
  if (diff < 86_400_000) return `in ${Math.floor(diff / 3_600_000)}h`;
  return `in ${Math.floor(diff / 86_400_000)}d`;
}

function TypeBadge({ type }: { type: "keyword" | "url" }) {
  const isKeyword = type === "keyword";
  return (
    <span className={`inline-block border px-1.5 py-0.5 text-[9px] font-bold tracking-widest rounded ${isKeyword ? "border-[var(--accent-dim)] bg-[var(--accent-dim)] text-[var(--accent)]" : "border-[var(--entity-onion-url)]/30 bg-[var(--entity-onion-url)]/10 text-[var(--entity-onion-url)]"}`}>
      {type.toUpperCase()}
    </span>
  );
}

function StatusDot({ status }: { status: Monitor["status"] }) {
  const isActive = status === "active";
  return (
    <span className={`inline-flex items-center gap-1.5 text-[10px] font-bold tracking-widest ${isActive ? "text-[var(--success)]" : "text-[var(--text-muted)]"}`}>
      <span
        className={`inline-block h-1.5 w-1.5 rounded-full ${isActive ? "bg-[var(--success)] animate-pulse" : "bg-[var(--text-muted)] opacity-50"}`}
        aria-hidden
      />
      {status.toUpperCase()}
    </span>
  );
}

function RunStatusBadge({ status }: { status: string | null | undefined }) {
  if (!status) return null;
  return (
    <span className={`inline-block border px-1.5 py-0.5 text-[9px] font-bold tracking-widest rounded ${
      status === "completed"
        ? "border-[var(--success)]/30 bg-[var(--success)]/10 text-[var(--success)]"
        : status === "failed"
        ? "border-[var(--danger)]/30 bg-[var(--danger)]/10 text-[var(--danger)]"
        : "border-[var(--accent-dim)] bg-[var(--accent-dim)]/10 text-[var(--accent)]"
    }`}>
      {status.toUpperCase()}
    </span>
  );
}

export function MonitorTable({
  monitors,
  onTrigger,
  onDelete,
  onAlertsAcknowledged,
}: Props) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [triggerLoading, setTriggerLoading] = useState<string | null>(null);
  const [triggerError, setTriggerError] = useState<Record<string, string>>({});
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  if (monitors.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 px-4 rounded-xl border border-dashed border-[var(--border-dim)] bg-[var(--bg-raised)]">
        <div className="mb-4 text-[var(--text-muted)] opacity-20">
           <svg className="h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
           </svg>
        </div>
        <p className="text-[12px] font-bold tracking-widest text-[var(--text-muted)] uppercase">Node Monitoring Offline</p>
        <p className="text-[11px] text-[var(--text-muted)] mt-1">Zero active watchpoints deployed.</p>
      </div>
    );
  }

  const handleRowClick = (id: string) => {
    setExpanded((prev) => (prev === id ? null : id));
    setDeleteConfirm(null);
  };

  const handleTrigger = async (id: string) => {
    setTriggerLoading(id);
    setTriggerError((prev) => ({ ...prev, [id]: "" }));
    const result = await onTrigger(id);
    setTriggerLoading(null);
    if (result.error) {
      setTriggerError((prev) => ({ ...prev, [id]: result.error! }));
    }
  };

  const handleDelete = async (id: string) => {
    if (deleteConfirm !== id) {
      setDeleteConfirm(id);
      return;
    }
    setDeleteConfirm(null);
    await onDelete(id);
  };

  return (
    <div className="overflow-x-auto rounded-lg border border-[var(--border-dim)] bg-[var(--bg-surface)] backdrop-blur-md">
      <table className="w-full border-collapse text-[12px]">
        <thead>
          <tr className="border-b border-[var(--border-dim)] bg-[var(--bg-raised)]">
            {["TYPE", "QUERY / IDENTIFIER", "STATUS", "ACTIVITY", "LAST CHECK", "NEXT CHECK", "ACTIONS"].map(
              (h) => (
                <th
                  key={h}
                  className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-[var(--text-muted)] uppercase"
                >
                  {h}
                </th>
              )
            )}
          </tr>
        </thead>
        <tbody>
          {monitors.map((m) => (
            <Fragment key={m.id}>
              <tr
                onClick={() => handleRowClick(m.id)}
                className={`cursor-pointer border-b border-[var(--border-dim)] transition-all hover:bg-[var(--bg-raised)] ${
                  expanded === m.id ? "bg-[var(--bg-raised)]" : ""
                }`}
              >
                <td className="px-4 py-4">
                  <TypeBadge type={m.type} />
                </td>
                <td className="max-w-[300px] px-4 py-4">
                  <div className="flex items-center gap-3">
                    <span className="truncate font-mono text-[11px] text-[var(--text-primary)] font-medium">{m.query}</span>
                    {m.alert_count > 0 && (
                      <span className="inline-flex shrink-0 px-1.5 py-0.5 rounded bg-[var(--danger-dim)] border border-[var(--danger)]/30 font-mono text-[9px] text-[var(--danger)] font-bold">
                        {m.alert_count} ALERTS
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-4">
                  <StatusDot status={m.status} />
                </td>
                <td className="px-4 py-4">
                  <div className="flex flex-col gap-1">
                    {m.last_run_at ? (
                      <>
                        <span className="font-mono text-[10px] text-[var(--text-muted)]">
                          {relativeTime(m.last_run_at)} · <RunStatusBadge status={m.last_run_status} />
                        </span>
                        {(m.last_entity_count ?? 0) > 0 && (
                          <span className="font-mono text-[9px] text-[var(--text-muted)]">
                            {m.last_entity_count} entities delta
                          </span>
                        )}
                      </>
                    ) : (
                      <span className="font-mono text-[10px] text-[var(--text-muted)]">Never run</span>
                    )}
                    {(m.total_runs ?? 0) > 0 && (
                      <span className="font-mono text-[9px] text-[var(--text-muted)]">
                        {m.total_runs} total runs
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-4 text-[var(--text-muted)] font-mono text-[11px]">
                  {relativeTime(m.last_checked_at)}
                </td>
                <td className="px-4 py-4 text-[var(--text-muted)] font-mono text-[11px]">
                  {relativeNext(m.next_check_at)}
                </td>
                <td className="px-4 py-4">
                  <div
                    className="flex items-center gap-2"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <button
                      type="button"
                      onClick={() => void handleTrigger(m.id)}
                      disabled={triggerLoading === m.id}
                      className="px-3 py-1 text-[10px] font-bold uppercase tracking-widest rounded border border-[var(--border-dim)] bg-[var(--bg-surface)] text-[var(--text-secondary)] transition-all hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:opacity-50"
                    >
                      {triggerLoading === m.id ? "..." : "Execute"}
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleDelete(m.id)}
                      className={`h-7 w-7 flex items-center justify-center rounded border transition-all ${
                        deleteConfirm === m.id
                          ? "border-[var(--danger)] bg-[var(--danger-dim)] text-[var(--danger)] animate-pulse"
                          : "border-[var(--border-dim)] text-[var(--text-muted)] hover:border-[var(--danger)] hover:text-[var(--danger)]"
                      }`}
                    >
                      <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                </td>
              </tr>
              {expanded === m.id && (
                <tr>
                  <td colSpan={7} className="p-0 bg-[var(--bg-void)]">
                    <div className="p-6 border-b border-[var(--border-dim)] animate-in slide-in-from-top-2 duration-300">
                      <MonitorDetail
                        monitor={m}
                        onTrigger={() => void handleTrigger(m.id)}
                        onDelete={() => void handleDelete(m.id)}
                        triggerLoading={triggerLoading === m.id}
                        triggerError={triggerError[m.id] ?? null}
                        onAlertsAcknowledged={onAlertsAcknowledged}
                      />
                    </div>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}
