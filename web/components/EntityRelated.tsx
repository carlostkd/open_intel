"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { CATEGORY_META, entityTypeToCategory } from "@/lib/types/investigation";
import type { EntityNeighbor } from "@/lib/types/entity";

const PAGE_SIZE = 24;

type Props = {
  neighbors: EntityNeighbor[];
};

export function EntityRelated({ neighbors }: Props) {
  const router = useRouter();
  const [showAll, setShowAll] = useState(false);

  if (neighbors.length === 0) {
    return (
      <div className="border border-dashed border-[var(--border-dim)] rounded-lg p-6 bg-[var(--bg-raised)] text-center">
        <p className="text-[11px] font-bold uppercase tracking-widest text-[var(--text-muted)] opacity-50">Zero associations indexed</p>
      </div>
    );
  }

  // Group by entity_type category
  const grouped = new Map<string, EntityNeighbor[]>();
  for (const nbr of neighbors) {
    const cat = entityTypeToCategory(nbr.entity_type);
    if (!grouped.has(cat)) grouped.set(cat, []);
    grouped.get(cat)!.push(nbr);
  }

  const all = neighbors;
  const visible = showAll ? all : all.slice(0, PAGE_SIZE);
  const hidden = all.length - visible.length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-[var(--border-dim)] pb-2">
         <h4 className="text-[10px] font-bold uppercase tracking-widest text-[var(--accent)]">Associated Entities</h4>
         <span className="text-[9px] font-mono text-[var(--text-muted)] uppercase tracking-widest">{neighbors.length} Neighbors</span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
        {visible.map((nbr) => {
          const cat = entityTypeToCategory(nbr.entity_type);
          const meta = CATEGORY_META[cat];
          const label = nbr.value.length > 32 ? `${nbr.value.slice(0, 16)}...${nbr.value.slice(-12)}` : nbr.value;

          return (
            <button
              key={nbr.id}
              type="button"
              title={`${nbr.value}\n${nbr.relationship_type} · confidence ${Math.round(nbr.confidence * 100)}%`}
              onClick={() => router.push(`/entities/${encodeURIComponent(nbr.id)}`)}
              className="flex items-center gap-3 p-2 rounded-md border border-[var(--border-dim)] bg-[var(--bg-surface)] hover:bg-[var(--bg-raised)] hover:border-[var(--border-strong)] transition-all text-left"
            >
              <div 
                className="h-2 w-2 rounded-full shrink-0" 
                style={{ backgroundColor: meta.color, boxShadow: `0 0 8px ${meta.color}66` }} 
              />
              <div className="min-w-0 flex-1">
                 <div className="flex justify-between items-center mb-0.5">
                    <span className="text-[8px] font-bold uppercase tracking-widest opacity-60" style={{ color: meta.color }}>{meta.short}</span>
                    <span className="text-[8px] font-mono text-[var(--text-muted)]">{Math.round(nbr.confidence * 100)}%</span>
                 </div>
                 <p className="font-mono text-[11px] text-[var(--text-primary)] truncate leading-none">{label}</p>
              </div>
            </button>
          );
        })}
      </div>

      {hidden > 0 && (
        <button
          type="button"
          onClick={() => setShowAll(true)}
          className="w-full h-10 rounded border border-dashed border-[var(--border-dim)] flex items-center justify-center text-[10px] font-bold uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--accent)] hover:border-[var(--accent)] transition-all"
        >
          Expand Registry ({hidden} Hidden)
        </button>
      )}
    </div>
  );
}
