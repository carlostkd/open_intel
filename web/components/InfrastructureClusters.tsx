"use client";

import { useState } from "react";

export type InfraCluster = {
  type: "shared_ip" | "shared_nameserver" | string;
  ip?: string;
  nameserver?: string;
  domains: string[];
  description: string;
};

interface InfrastructureClustersProps {
  clusters: InfraCluster[];
  onHighlightDomains?: (domains: string[]) => void;
}

export function InfrastructureClusters({
  clusters,
  onHighlightDomains,
}: InfrastructureClustersProps) {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

  if (!clusters || clusters.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-[var(--text-muted)] font-mono text-xs">
        No infrastructure clusters detected
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <p className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)] mb-3">
        {clusters.length} infrastructure cluster{clusters.length !== 1 ? "s" : ""} detected —
        shared hosting, nameservers, and SSL certificates reveal threat actor infrastructure reuse
      </p>

      {clusters.map((cluster, i) => {
        const isSharedIp = cluster.type === "shared_ip";
        const connectingElement = isSharedIp ? cluster.ip : cluster.nameserver;
        const label = isSharedIp ? "Shared IP" : "Shared Nameserver";
        const isExpanded = expandedIndex === i;

        return (
          <div
            key={i}
            className="rounded-md border border-[var(--border-dim)] bg-[var(--bg-raised)] overflow-hidden"
          >
            <button
              className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-[var(--bg-void)] transition-colors"
              onClick={() => setExpandedIndex(isExpanded ? null : i)}
            >
              {/* Icon */}
              <span className="shrink-0 mt-0.5 text-[var(--accent)] text-base">⛓</span>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[10px] font-bold uppercase tracking-widest text-[var(--accent)] bg-[var(--accent-dim)] px-1.5 py-0.5 rounded">
                    {label}
                  </span>
                  <span className="font-mono text-[12px] text-[var(--text-primary)] truncate">
                    {connectingElement}
                  </span>
                  <span className="text-[10px] text-[var(--text-muted)]">
                    {cluster.domains.length} domains
                  </span>
                </div>

                {!isExpanded && (
                  <p className="mt-1 text-[11px] text-[var(--text-secondary)] truncate">
                    {cluster.domains.join(", ")}
                  </p>
                )}
              </div>

              <span className={`shrink-0 text-[var(--text-muted)] transition-transform duration-200 ${isExpanded ? "rotate-180" : ""}`}>
                ▾
              </span>
            </button>

            {isExpanded && (
              <div className="border-t border-[var(--border-dim)] px-4 py-3 bg-[var(--bg-void)]">
                <p className="text-[11px] text-[var(--text-secondary)] mb-3">
                  {cluster.description}
                </p>

                <div className="flex flex-wrap gap-2 mb-3">
                  {cluster.domains.map((domain, di) => (
                    <span
                      key={di}
                      className="font-mono text-[11px] text-[var(--accent)] bg-[var(--accent-dim)] px-2 py-0.5 rounded border border-[var(--accent-border)]"
                    >
                      {domain}
                    </span>
                  ))}
                </div>

                {onHighlightDomains && (
                  <button
                    onClick={() => onHighlightDomains(cluster.domains)}
                    className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)] hover:text-[var(--accent)] transition-colors"
                  >
                    Highlight in graph →
                  </button>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
