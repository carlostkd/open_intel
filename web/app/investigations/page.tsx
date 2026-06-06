"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { InvestigationCard, InvestigationListItem } from "@/components/InvestigationCard";

interface InvestigationsResponse {
  items: InvestigationListItem[];
  total: number;
  skip: number;
  limit: number;
}

const LIMIT = 20;

function SkeletonRow() {
  return (
    <div className="animate-pulse rounded-lg border border-[var(--border-dim)] bg-[var(--bg-surface)] px-5 py-4">
      <div className="flex items-start justify-between gap-4">
        <div className="h-5 w-2/3 rounded bg-[var(--bg-raised)]" />
        <div className="h-5 w-20 rounded-full bg-[var(--bg-raised)]" />
      </div>
      <div className="mt-2 h-3 w-1/3 rounded bg-[var(--bg-raised)]" />
    </div>
  );
}

export default function InvestigationsPage() {
  const router = useRouter();
  const [items, setItems] = useState<InvestigationListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [skip, setSkip] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchInvestigations = useCallback(async (skipVal: number) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/investigations?skip=${skipVal}&limit=${LIMIT}`);
      if (!res.ok) throw new Error("Failed to fetch investigations");
      const data: InvestigationsResponse = await res.json();
      setItems(data.items);
      setTotal(data.total);
      setSkip(data.skip);
    } catch (e) {
      setError(e instanceof Error ? e.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchInvestigations(0);
  }, [fetchInvestigations]);

  const currentPage = Math.floor(skip / LIMIT) + 1;
  const totalPages = Math.max(1, Math.ceil(total / LIMIT));
  const hasNext = skip + LIMIT < total;
  const hasPrev = skip > 0;

  const handlePrev = () => {
    if (hasPrev) {
      const newSkip = Math.max(0, skip - LIMIT);
      fetchInvestigations(newSkip);
    }
  };

  const handleNext = () => {
    if (hasNext) {
      fetchInvestigations(skip + LIMIT);
    }
  };

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-10 flex h-[56px] shrink-0 items-center justify-between border-b border-[var(--border-dim)] bg-[var(--bg-void)]/60 px-6 backdrop-blur-xl">
        <div className="flex items-center gap-6">
          <button
            onClick={() => router.push("/")}
            className="flex items-center gap-2 font-heading transition-opacity hover:opacity-80"
          >
            <span className="text-[var(--accent)]" aria-hidden>●</span>
            <span className="text-[15px] font-bold tracking-tight text-[var(--text-primary)]">voidaccess</span>
          </button>
          <div className="h-4 w-px bg-[var(--border-dim)]" />
          <h1 className="text-[15px] font-semibold text-[var(--text-primary)]">Investigations</h1>
          <span className="font-mono text-[11px] text-[var(--text-muted)]">{total} total</span>
        </div>
        <button
          onClick={() => router.push("/investigations/new")}
          className="flex h-8 items-center gap-2 rounded border border-[var(--accent)]/30 bg-[var(--accent)]/10 px-3 text-[11px] font-semibold text-[var(--accent)] transition-colors hover:border-[var(--accent)]/60 hover:bg-[var(--accent)]/20"
        >
          New investigation
        </button>
      </header>

      <main className="flex-1 px-6 py-8">
        <div className="mx-auto max-w-4xl">
          {error && (
            <div className="mb-6 flex items-center justify-between rounded-lg border border-[var(--danger)]/30 bg-[var(--danger)]/10 px-4 py-3">
              <span className="text-[13px] text-[var(--danger)]">{error}</span>
              <button
                onClick={() => fetchInvestigations(skip)}
                className="text-[11px] font-semibold text-[var(--danger)] underline"
              >
                Retry
              </button>
            </div>
          )}

          {loading && !error && (
            <div className="space-y-3">
              {[...Array(5)].map((_, i) => (
                <SkeletonRow key={i} />
              ))}
            </div>
          )}

          {!loading && !error && items.length === 0 && total === 0 && (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <div className="mb-4 text-4xl opacity-20">📋</div>
              <h2 className="mb-2 text-[18px] font-semibold text-[var(--text-primary)]">No investigations yet</h2>
              <p className="mb-6 max-w-sm text-[13px] text-[var(--text-muted)]">
                Run your first investigation to start building your intelligence database.
              </p>
              <button
                onClick={() => router.push("/investigations/new")}
                className="flex h-9 items-center gap-2 rounded border border-[var(--accent)]/30 bg-[var(--accent)]/10 px-4 text-[12px] font-semibold text-[var(--accent)] transition-colors hover:border-[var(--accent)]/60 hover:bg-[var(--accent)]/20"
              >
                New investigation
              </button>
            </div>
          )}

          {!loading && !error && items.length > 0 && (
            <>
              <div className="mb-4 flex items-center justify-between">
                <span className="text-[12px] text-[var(--text-muted)]">
                  Showing {skip + 1}–{Math.min(skip + LIMIT, total)} of {total}
                </span>
              </div>

              <div className="space-y-3" data-testid="investigations-list">
                {items.map((inv) => (
                  <InvestigationCard
                    key={inv.id}
                    investigation={inv}
                    onClick={() => router.push(`/investigations/${inv.id}`)}
                  />
                ))}
              </div>

              <div className="mt-8 flex items-center justify-center gap-4">
                <button
                  onClick={handlePrev}
                  disabled={!hasPrev}
                  className="flex h-8 items-center gap-1.5 rounded border border-[var(--border-dim)] bg-[var(--bg-surface)] px-3 text-[11px] font-medium text-[var(--text-secondary)] transition-colors disabled:cursor-not-allowed disabled:opacity-40 hover:border-[var(--border-strong)] hover:text-[var(--text-primary)]"
                >
                  <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
                    <path d="M10 4l-4 4 4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  Previous
                </button>

                <span className="font-mono text-[11px] text-[var(--text-muted)]" data-testid="pagination-info">
                  Page {currentPage} of {totalPages}
                </span>

                <button
                  onClick={handleNext}
                  disabled={!hasNext}
                  className="flex h-8 items-center gap-1.5 rounded border border-[var(--border-dim)] bg-[var(--bg-surface)] px-3 text-[11px] font-medium text-[var(--text-secondary)] transition-colors disabled:cursor-not-allowed disabled:opacity-40 hover:border-[var(--border-strong)] hover:text-[var(--text-primary)]"
                >
                  Next
                  <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
                    <path d="M6 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </button>
              </div>
            </>
          )}
        </div>
      </main>
    </div>
  );
}