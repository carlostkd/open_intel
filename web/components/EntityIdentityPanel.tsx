"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { CATEGORY_META, entityTypeToCategory } from "@/lib/types/investigation";
import type { EntityProfile } from "@/lib/types/entity";

// ─── helpers ────────────────────────────────────────────────────────────────

function confidenceColor(conf: number): string {
  if (conf >= 0.9) return "var(--success)";
  if (conf >= 0.7) return "var(--warning)";
  return "var(--danger)";
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return iso.slice(0, 10);
}

function blockchainExplorerUrl(entityType: string, value: string): string | null {
  if (entityType === "BITCOIN_ADDRESS")
    return `https://blockchair.com/bitcoin/address/${value}`;
  if (entityType === "ETHEREUM_ADDRESS")
    return `https://etherscan.io/address/${value}`;
  if (entityType === "MONERO_ADDRESS")
    return `https://xmrchain.net/search?value=${value}`;
  return null;
}

function blockchainLabel(entityType: string): string {
  if (entityType === "BITCOIN_ADDRESS") return "BTC";
  if (entityType === "ETHEREUM_ADDRESS") return "ETH";
  if (entityType === "MONERO_ADDRESS") return "XMR";
  return "";
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        });
      }}
      className="ml-1.5 rounded border border-[var(--border-dim)] px-2 py-0.5 font-mono text-[9px] text-[var(--text-muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-all"
    >
      {copied ? "COPIED" : "COPY"}
    </button>
  );
}

// ─── component ───────────────────────────────────────────────────────────────

type Props = {
  entity: EntityProfile;
};

export function EntityIdentityPanel({ entity }: Props) {
  const router = useRouter();
  const cat = entityTypeToCategory(entity.entity_type);
  const meta = CATEGORY_META[cat];
  const confPct = Math.round(entity.confidence * 100);
  const confColor = confidenceColor(entity.confidence);

  const isWallet = ["BITCOIN_ADDRESS", "ETHEREUM_ADDRESS", "MONERO_ADDRESS"].includes(
    entity.entity_type
  );
  const isOnion = entity.entity_type === "ONION_URL";
  const isCve = entity.entity_type === "CVE_NUMBER";
  const isEmail = entity.entity_type === "EMAIL_ADDRESS";
  const isPgp = entity.entity_type === "PGP_KEY_BLOCK";

  const explorerUrl = isWallet ? blockchainExplorerUrl(entity.entity_type, entity.value) : null;
  const snippet = (entity.context_snippet ?? entity.context ?? "").trim();

  function handleExport(format: "stix" | "json") {
    const url = `/api/entities/${encodeURIComponent(entity.id)}/export?format=${format}`;
    const a = document.createElement("a");
    a.href = url;
    a.download = `voidaccess_entity_${entity.id}.json`;
    a.click();
  }

  return (
    <div className="flex flex-col gap-6 font-sans">
      {/* header */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
           <p className="text-[10px] font-bold uppercase tracking-widest text-[var(--accent)]">Intelligence Identity</p>
           <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full border border-[var(--border-dim)] bg-[var(--bg-raised)]">
              <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: meta.color }} />
              <span className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-secondary)]">{meta.short}</span>
           </div>
        </div>

        {/* value display */}
        <div className="p-4 rounded-lg border border-[var(--border-dim)] bg-[var(--bg-surface)]">
          {isWallet ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-[var(--bg-void)] border border-[var(--border-dim)] text-[var(--text-muted)] uppercase">{blockchainLabel(entity.entity_type)}</span>
                <CopyButton text={entity.value} />
              </div>
              <p className="font-mono text-[13px] font-bold text-[var(--text-primary)] break-all leading-tight">
                {entity.value}
              </p>
              {explorerUrl && (
                <a
                  href={explorerUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center text-[10px] font-bold text-[var(--accent)] hover:underline"
                >
                  Block Explorer ↗
                </a>
              )}
            </div>
          ) : isOnion ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-[var(--entity-onion-url)] px-2 py-0.5 bg-[var(--entity-onion-url)]/10 border border-[var(--entity-onion-url)]/30 rounded">Tor Hidden Service</span>
                  <CopyButton text={entity.value} />
              </div>
              <p className="font-mono text-[13px] font-bold text-[var(--entity-onion-url)] break-all">{entity.value}</p>
            </div>
          ) : (
            <div className="space-y-2">
               <div className="flex justify-between items-center">
                  <span className="text-[9px] font-bold text-[var(--text-muted)] uppercase tracking-wider">Identifier</span>
                  <CopyButton text={entity.value} />
               </div>
               <p className="font-mono text-[14px] font-bold break-all leading-tight" style={{ color: meta.color }}>
                 {entity.value}
               </p>
            </div>
          )}
        </div>
      </div>

      {/* confidence & metadata */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Signal Confidence</span>
            <span className="font-mono text-[11px] font-bold" style={{ color: confColor }}>{confPct}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-[var(--bg-void)] overflow-hidden border border-[var(--border-dim)]">
            <div
              className="h-full rounded-full transition-all duration-700 ease-out"
              style={{ width: `${confPct}%`, backgroundColor: confColor }}
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
           <div className="space-y-1">
             <p className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">First Spotted</p>
             <p className="text-[11px] font-mono text-[var(--text-secondary)]">{formatDate(entity.first_seen)}</p>
           </div>
           <div className="space-y-1">
             <p className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Frequency</p>
             <p className="text-[11px] font-mono text-[var(--text-secondary)]">{entity.appearance_count} Hits</p>
           </div>
        </div>
      </div>

      {/* Contextual Intelligence */}
      {(snippet || entity.historical_context) && (
        <div className="space-y-4 pt-2">
           <h4 className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)] border-b border-[var(--border-dim)] pb-2">Intelligence Context</h4>
           
           {snippet && (
             <div className="p-4 rounded border-l-2 border-[var(--border-dim)] bg-[var(--bg-raised)] italic">
               <p className="text-[12px] leading-relaxed text-[var(--text-secondary)]">
                 &ldquo;{snippet.length > 500 ? `${snippet.slice(0, 497)}…` : snippet}&rdquo;
               </p>
             </div>
           )}

           {entity.historical_context && (
             <div className="space-y-2">
                <p className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Known History</p>
                <p className="text-[12px] leading-relaxed text-[var(--text-secondary)]">{entity.historical_context}</p>
             </div>
           )}
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-3 pt-4 border-t border-[var(--border-dim)]">
        <button
          type="button"
          onClick={() => handleExport("stix")}
          className="flex-1 h-10 text-[11px] font-bold uppercase tracking-widest rounded bg-[var(--accent)] text-[var(--text-inverse)] hover:shadow-lg transition-all"
        >
          Export STIX
        </button>
        <button
          type="button"
          onClick={() => handleExport("json")}
          className="flex-1 h-10 text-[11px] font-bold uppercase tracking-widest rounded border border-[var(--border-dim)] text-[var(--text-secondary)] hover:bg-[var(--bg-surface)] transition-all"
        >
          JSON Schema
        </button>
      </div>

      <button
        type="button"
        onClick={() => router.back()}
        className="self-start text-[10px] font-bold uppercase tracking-[0.2em] text-[var(--text-muted)] hover:text-[var(--accent)] transition-colors"
      >
        ← Return to Source
      </button>
    </div>
  );
}
