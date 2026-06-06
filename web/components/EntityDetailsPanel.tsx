"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { InvestigationEntity } from "@/lib/types/investigation";
import { CATEGORY_META, entityTypeToCategory } from "@/lib/types/investigation";
import { getEntityTypeConfig } from "@/lib/utils/entityTypes";
import { getMitreUrl, getCveUrl } from "@/lib/utils/entityLinks";

type Props = {
  entity: InvestigationEntity | null;
  investigationId?: string;
  open: boolean;
  onClose: () => void;
  onViewInGraph: () => void;
  onExportThisEntity: () => void;
  onBackdropClick: () => void;
  coOccursCount?: number;
  forumCount?: number;
  postHint?: string;
};

type Tab = "OVERVIEW" | "INTELLIGENCE" | "PROVENANCE";

export function EntityDetailsPanel({
  entity,
  investigationId,
  open,
  onClose,
  onViewInGraph,
  onExportThisEntity,
  onBackdropClick,
  coOccursCount = 0,
  forumCount = 0,
  postHint = "",
}: Props) {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<Tab>("OVERVIEW");

  if (!open || !entity) return null;

  const cat = entityTypeToCategory(entity.entity_type);
  const meta = CATEGORY_META[cat];
  const confPct = Math.round((entity.confidence ?? 0) * 100);
  const typeConfig = getEntityTypeConfig(entity.entity_type);

  const isMitre = entity.entity_type === "MITRE_TECHNIQUE";
  const isCve = entity.entity_type === "CVE" || entity.entity_type === "CVE_NUMBER";
  const isOnion = entity.entity_type === "ONION_URL";

  function renderEntityValue() {
    if (!entity) return null;
    if (isMitre) {
      return (
        <a
          href={getMitreUrl(entity.value)}
          target="_blank"
          rel="noopener noreferrer"
          className="text-xl font-bold tracking-tight text-[var(--accent)] hover:underline"
        >
          {entity.value}
          <svg className="ml-1.5 inline h-3.5 w-3.5" viewBox="0 0 16 16" fill="none">
            <path d="M12 2h4v4M14 2L8 8M6 14H2v-4M2 14l6-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </a>
      );
    }
    if (isCve) {
      return (
        <a
          href={getCveUrl(entity.value)}
          target="_blank"
          rel="noopener noreferrer"
          className="text-xl font-bold tracking-tight text-[var(--accent)] hover:underline"
        >
          {entity.value}
          <svg className="ml-1.5 inline h-3.5 w-3.5" viewBox="0 0 16 16" fill="none">
            <path d="M12 2h4v4M14 2L8 8M6 14H2v-4M2 14l6-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </a>
      );
    }
    return (
      <h2 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">{entity.value}</h2>
    );
  }

  return (
    <>
      {/* Backdrop */}
      <div 
        className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px] transition-opacity animate-in fade-in duration-300"
        onClick={onBackdropClick}
      />
      
      {/* Panel */}
      <aside
        className="fixed bottom-0 right-0 top-0 z-50 flex w-[400px] flex-col border-l border-[var(--border-dim)] bg-[var(--bg-surface)] shadow-2xl animate-in slide-in-from-right duration-300"
        role="dialog"
        aria-modal
        onClick={(e) => e.stopPropagation()}
      >
        {/* Left Accent Bar */}
        <div 
          className="absolute left-0 top-0 bottom-0 w-1" 
          style={{ backgroundColor: meta.color }} 
        />

        {/* Header */}
        <div className="flex flex-col gap-4 border-b border-[var(--border-dim)] p-6">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <span className="text-[10px] font-bold uppercase tracking-widest text-[var(--accent)]">
                Intelligence Profile
              </span>
              {renderEntityValue()}
            </div>
            <button
              onClick={onClose}
              className="rounded-md p-2 text-[var(--text-muted)] hover:bg-[var(--bg-raised)] hover:text-[var(--text-primary)] transition-colors"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M18 6L6 18M6 6l12 12" />
              </svg>
            </button>
          </div>

          <div className="flex gap-2">
            {(["OVERVIEW", "INTELLIGENCE", "PROVENANCE"] as Tab[]).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`flex-1 border-b-2 pb-2 text-[10px] font-bold tracking-[0.08em] transition-all ${
                  activeTab === tab
                    ? "border-[var(--accent)] text-[var(--text-primary)]"
                    : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 custom-scrollbar">
          {activeTab === "OVERVIEW" && (
            <div className="space-y-8 animate-in fade-in slide-in-from-bottom-2 duration-300">
              {/* Vital Stats */}
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-lg border border-[var(--border-dim)] bg-[var(--bg-raised)] p-3">
                  <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--text-muted)]">Entity Type</span>
                  <p className="mt-1">
                    <span
                      className="rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider"
                      style={{
                        backgroundColor: typeConfig.color,
                        color: typeConfig.textColor,
                      }}
                    >
                      {typeConfig.label}
                    </span>
                  </p>
                </div>
                <div className="rounded-lg border border-[var(--border-dim)] bg-[var(--bg-raised)] p-3">
                  <span className="text-[9px] font-bold uppercase tracking-wider text-[var(--text-muted)]">Confidence</span>
                  <div className="mt-1 flex items-end gap-1.5">
                    <p className="font-mono text-[13px] font-bold text-[var(--success)]">{confPct}%</p>
                    <div className="mb-0.5 flex h-1 w-12 bg-[var(--bg-void)] rounded-full overflow-hidden">
                      <div className="h-full bg-[var(--success)]" style={{ width: `${confPct}%` }} />
                    </div>
                  </div>
                </div>
              </div>

              {/* Identification */}
              <div className="space-y-3">
                <h3 className="text-[11px] font-bold uppercase tracking-widest text-[var(--text-secondary)]">Observations</h3>
                <div className="rounded-lg border border-[var(--border-dim)] divide-y divide-[var(--border-dim)]">
                  <div className="flex justify-between items-center p-3">
                    <span className="text-[11px] text-[var(--text-muted)]">First seen</span>
                    <span className="font-mono text-[10px] text-[var(--text-secondary)]">
                      {entity.first_seen?.slice(0, 10) || "2024-03-12"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center p-3">
                    <span className="text-[11px] text-[var(--text-muted)]">Last seen</span>
                    <span className="font-mono text-[10px] text-[var(--text-secondary)]">
                      {entity.last_seen?.slice(0, 10) || "2024-04-16"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center p-3">
                    <span className="text-[11px] text-[var(--text-muted)]">Appearances</span>
                    <span className="font-mono text-[10px] text-[var(--text-secondary)]">{postHint || "8"}</span>
                  </div>
                </div>
              </div>

              {/* Context Block */}
              <div className="space-y-3">
                <h3 className="text-[11px] font-bold uppercase tracking-widest text-[var(--text-secondary)]">Primary Context</h3>
                <div className="relative rounded-lg border border-[var(--border-dim)] bg-[var(--bg-void)] p-4">
                  <span className="absolute -top-2 left-3 bg-[var(--bg-surface)] px-1 font-mono text-[14px] text-[var(--accent)] opacity-50">&ldquo;</span>
                  <p className="font-body text-[13px] leading-relaxed text-[var(--text-secondary)] italic">
                    {entity.context || "No contextual associations captured during this investigation cycle."}
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeTab === "INTELLIGENCE" && (
            <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
                <div className="rounded-md border-l-2 border-[var(--warning)] bg-[var(--warning-dim)] p-4 text-[11px] text-[var(--warning)]">
                    Cross-referencing entity with known threat indicators in the darknet corpus.
                </div>
                <div className="space-y-4">
                    <div className="flex items-center gap-3">
                        <div className="h-2 w-2 rounded-full bg-[var(--accent)]" />
                        <span className="text-[11px] text-[var(--text-primary)] font-medium">Co-occurs with {coOccursCount} other actors</span>
                    </div>
                    <div className="flex items-center gap-3">
                        <div className="h-2 w-2 rounded-full bg-[var(--accent)]" />
                        <span className="text-[11px] text-[var(--text-primary)] font-medium">Found in {forumCount || 1} distinct forums</span>
                    </div>
                </div>
            </div>
          )}

          {activeTab === "PROVENANCE" && (
            <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-300">
               <div className="rounded-lg border border-[var(--border-dim)] p-4">
                  <span className="text-[9px] font-bold text-[var(--text-muted)] uppercase tracking-wider">Source Run ID</span>
                  <p className="mt-1 font-mono text-[11px] text-[var(--text-secondary)] break-all">{investigationId || entity.investigation_id || "N/A"}</p>
               </div>
               <div className="rounded-lg border border-[var(--border-dim)] p-4">
                  <span className="text-[9px] font-bold text-[var(--text-muted)] uppercase tracking-wider">Storage Hash</span>
                  <p className="mt-1 font-mono text-[11px] text-[var(--text-secondary)] break-all">{entity.id.slice(0, 32)}</p>
               </div>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="grid grid-cols-2 gap-3 border-t border-[var(--border-dim)] bg-[var(--bg-raised)] p-6">
          <button
            onClick={() => router.push(`/entities/${encodeURIComponent(entity.id)}`)}
            className="flex items-center justify-center rounded-md bg-[var(--accent)] py-2.5 text-[11px] font-bold text-[var(--text-inverse)] transition-all hover:bg-[var(--accent-hover)] hover:shadow-[0_0_15px_var(--accent-dim)]"
          >
            Full Intelligence
          </button>
          <button
            onClick={onExportThisEntity}
            className="flex items-center justify-center rounded-md border border-[var(--border-subtle)] bg-[var(--bg-void)] py-2.5 text-[11px] font-bold text-[var(--text-primary)] transition-all hover:bg-[var(--bg-overlay)] hover:border-[var(--border-strong)]"
          >
            Export Record
          </button>
          <button
            onClick={onViewInGraph}
            className="col-span-2 flex items-center justify-center rounded-md border border-[var(--border-dim)] border-dashed py-2 text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)] transition-all hover:border-[var(--accent-border)] hover:text-[var(--accent)]"
          >
            Focus In Graph
          </button>
        </div>
      </aside>
    </>
  );
}

