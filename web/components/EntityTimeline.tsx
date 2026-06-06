"use client";

import Link from "next/link";
import type { EntityProfile } from "@/lib/types/entity";

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return iso.slice(0, 10);
}

function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 10);
  return d.toLocaleString("en-GB", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

type Props = {
  entity: EntityProfile;
};

export function EntityTimeline({ entity }: Props) {
  const { appearances, historical_context, is_seed, first_seen, last_seen } = entity;

  return (
    <div className="flex flex-col gap-6 font-sans">
      <div className="flex items-center justify-between border-b border-[var(--border-dim)] pb-2">
         <h4 className="text-[10px] font-bold uppercase tracking-widest text-[var(--accent)]">Signal Timeline</h4>
         <span className="text-[9px] font-mono text-[var(--text-muted)] uppercase tracking-widest">{entity.appearance_count} Recorded Events</span>
      </div>

      {appearances.length === 0 ? (
        <div className="p-4 rounded border border-dashed border-[var(--border-dim)] bg-[var(--bg-raised)] text-center">
          <p className="text-[11px] text-[var(--text-muted)] font-medium">No cross-investigation history detected.</p>
        </div>
      ) : (
        <div className="relative pl-6 ml-2 space-y-6">
          {/* Vertical Line */}
          <div className="absolute left-0 top-1 bottom-1 w-[1px] bg-[var(--border-dim)]" />

          {appearances.map((ap, i) => (
            <div key={ap.investigation_id} className="relative">
              {/* Event Marker */}
              <div className={`absolute -left-[28px] top-1.5 h-3 w-3 rounded-full border-2 border-[var(--bg-void)] ring-1 ${i === 0 ? "bg-[var(--accent)] ring-[var(--accent-border)]" : "bg-[var(--border-strong)] ring-[var(--border-dim)]"}`} />
              
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                   <time className="text-[10px] font-mono font-bold text-[var(--text-muted)] opacity-60 uppercase">{formatDateTime(ap.created_at)}</time>
                   <span className="px-1.5 py-0.5 rounded-full bg-[var(--bg-surface)] border border-[var(--border-dim)] text-[8px] font-bold text-[var(--text-muted)] uppercase">Extraction</span>
                </div>
                <div className="group p-3 rounded-md bg-[var(--bg-surface)] border border-[var(--border-dim)] hover:border-[var(--border-strong)] transition-all">
                   <p className="text-[12px] font-bold text-[var(--text-primary)] leading-snug">{ap.query}</p>
                   <Link
                     href={`/investigations/${ap.run_id}`}
                     className="mt-2 inline-flex items-center text-[10px] font-bold text-[var(--accent)] hover:underline opacity-0 group-hover:opacity-100 transition-opacity"
                   >
                     Inspect Context →
                   </Link>
                </div>
              </div>
            </div>
          ))}

          {/* First Seen Marker */}
          {first_seen && (
            <div className="relative">
               <div className="absolute -left-[28px] top-1.5 h-3 w-3 rounded-full border-2 border-[var(--bg-void)] ring-1 bg-[var(--warning)] ring-[var(--warning-dim)]" />
               <div className="space-y-1">
                  <time className="text-[10px] font-mono font-bold text-[var(--warning)] opacity-60 uppercase">{formatDate(first_seen)}</time>
                  <div className="p-3 rounded-md bg-[var(--warning-dim)]/20 border border-[var(--warning)]/10">
                     <p className="text-[11px] font-bold text-[var(--warning)] uppercase tracking-widest leading-none">Inception Point</p>
                     <p className="text-[11px] text-[var(--text-muted)] mt-1.5">
                        {is_seed ? "Initial injection from archival threat intelligence seed." : "Primary discovery in VoidAccess persistent node."}
                     </p>
                  </div>
               </div>
            </div>
          )}
        </div>
      )}

      {/* Historical Intel Block */}
      {historical_context && (
        <div className="space-y-3 pt-2">
           <h4 className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Archival Footprint</h4>
           <div className="p-4 rounded border border-[var(--border-dim)] bg-[var(--bg-surface)] relative overflow-hidden">
              <div className="absolute top-0 right-0 p-2 opacity-10">
                 <svg className="h-10 w-10 text-[var(--text-muted)]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5s3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                 </svg>
              </div>
              <p className="text-[12px] leading-relaxed text-[var(--text-secondary)] italic">
                 &ldquo;{historical_context}&rdquo;
              </p>
              <div className="flex items-center gap-4 mt-4 pt-3 border-t border-[var(--border-dim)]/30">
                 <div className="flex flex-col">
                    <span className="text-[8px] font-bold uppercase tracking-widest text-[var(--text-muted)] opacity-50">Sourced From</span>
                    <span className="text-[10px] font-bold text-[var(--accent)]">{is_seed ? "Seed Intelligence" : "Field Extraction"}</span>
                 </div>
                 {last_seen && (
                   <div className="flex flex-col">
                      <span className="text-[8px] font-bold uppercase tracking-widest text-[var(--text-muted)] opacity-50">Last Active</span>
                      <span className="text-[10px] font-bold text-[var(--text-secondary)] font-mono">{formatDate(last_seen)}</span>
                   </div>
                 )}
              </div>
           </div>
        </div>
      )}

      {/* Summary Footer */}
      <footer className="pt-4 border-t border-[var(--border-dim)] grid grid-cols-2 gap-4">
        <div className="flex flex-col">
           <span className="text-[8px] font-bold uppercase tracking-tighter text-[var(--text-muted)] opacity-50">Trace Start</span>
           <span className="text-[11px] font-mono text-[var(--text-secondary)]">{formatDate(first_seen)}</span>
        </div>
        <div className="flex flex-col text-right">
           <span className="text-[8px] font-bold uppercase tracking-tighter text-[var(--text-muted)] opacity-50">Total Sightings</span>
           <span className="text-[11px] font-mono text-[var(--accent)] font-bold">{entity.appearance_count}</span>
        </div>
      </footer>
    </div>
  );
}
