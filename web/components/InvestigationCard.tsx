"use client";

import { StatusBadge } from "@/components/InvestigationSummary";
import { formatRelativeTime } from "@/lib/utils/formatRelativeTime";

export interface InvestigationListItem {
  id: number;
  query: string;
  refined_query?: string | null;
  status: string;
  created_at: string;
  completed_at?: string | null;
  entity_count: number;
  page_count: number;
  graph_status?: string | null;
  model_used?: string | null;
}

interface InvestigationCardProps {
  investigation: InvestigationListItem;
  onClick: () => void;
}

export function InvestigationCard({ investigation, onClick }: InvestigationCardProps) {
  const showCounts = investigation.entity_count > 0 || investigation.page_count > 0;

  return (
    <div
      onClick={onClick}
      className="group cursor-pointer rounded-lg border border-[var(--border-dim)] bg-[var(--bg-surface)] px-5 py-4 transition-all hover:border-[var(--border-strong)] hover:bg-[var(--bg-raised)]"
      data-testid="investigation-card"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-3">
            <span
              className="truncate font-heading text-[15px] font-semibold text-[var(--text-primary)]"
              title={investigation.query}
              data-testid="investigation-query"
            >
              {investigation.query.length > 80
                ? investigation.query.slice(0, 80) + "…"
                : investigation.query}
            </span>
            {investigation.graph_status === "skipped_overflow" && (
              <span
                className="shrink-0 rounded-full border border-[var(--warning)]/30 bg-[var(--warning)]/10 px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider text-[var(--warning)]"
                data-testid="graph-overflow-pill"
              >
                Graph overflow
              </span>
            )}
          </div>

          {investigation.refined_query && investigation.refined_query !== investigation.query && (
            <div className="mt-1 text-[12px] text-[var(--text-muted)]" data-testid="refined-query-row">
              Refined to: <span className="text-[var(--text-secondary)]">{investigation.refined_query}</span>
            </div>
          )}

          <div className="mt-2 flex items-center gap-3 text-[11px] text-[var(--text-muted)]">
            {investigation.created_at && (
              <span data-testid="investigation-time">{formatRelativeTime(investigation.created_at)}</span>
            )}
            {showCounts && (
              <span data-testid="investigation-counts">
                {investigation.entity_count} entities · {investigation.page_count} pages
              </span>
            )}
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-3">
          <StatusBadge status={investigation.status} />
          <svg
            width="16"
            height="16"
            viewBox="0 0 16 16"
            fill="none"
            className="text-[var(--text-muted)] transition-transform group-hover:translate-x-0.5"
          >
            <path
              d="M6 4l4 4-4 4"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
      </div>
    </div>
  );
}