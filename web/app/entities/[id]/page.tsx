"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEntityProfile } from "@/lib/hooks/useEntityProfile";
import { useEntityAnalysis } from "@/lib/hooks/useEntityAnalysis";
import { EntityIdentityPanel } from "@/components/EntityIdentityPanel";
import { EntityMiniGraph } from "@/components/EntityMiniGraph";
import { EntityRelated } from "@/components/EntityRelated";
import { EntityTimeline } from "@/components/EntityTimeline";
import { StylometryPanel } from "@/components/StylometryPanel";
import { OpsecPanel } from "@/components/OpsecPanel";
import { CATEGORY_META, entityTypeToCategory } from "@/lib/types/investigation";

export default function EntityProfilePage() {
  const params = useParams();
  const router = useRouter();
  const entityId = typeof params.id === "string" ? params.id : null;

  const { entity, related, loading, error } = useEntityProfile(entityId);
  const {
    stylometry,
    opsec,
    fetchStylometry,
    fetchOpsec,
  } = useEntityAnalysis(entityId);

  // ── loading state ──
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[var(--bg-void)]">
        <div className="flex flex-col items-center gap-6">
          <div className="h-10 w-10 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent shadow-[0_0_15px_var(--accent-dim)]" />
          <div className="space-y-1 text-center">
            <p className="font-heading text-lg font-bold tracking-tight text-[var(--text-primary)]">Accessing Intelligence Profile</p>
            <p className="font-mono text-[10px] uppercase tracking-widest text-[var(--text-muted)]">Decrypting archival data nodes...</p>
          </div>
        </div>
      </div>
    );
  }

  // ── 404 / error state ──
  if (error || !entity) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-6 bg-[var(--bg-void)]">
        <div className="p-1.5 rounded-full border border-[var(--danger)] bg-[var(--danger-dim)]">
           <svg className="h-8 w-8 text-[var(--danger)]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
           </svg>
        </div>
        <div className="text-center space-y-2">
           <p className="font-heading text-xl font-bold text-[var(--text-primary)]">Profile Not Found</p>
           <p className="text-[12px] text-[var(--text-muted)] max-w-xs">{error ?? "The requested entity identifier does not exist in the decentralized database."}</p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => router.back()}
            className="px-6 h-10 rounded border border-[var(--border-dim)] text-[11px] font-bold uppercase tracking-widest text-[var(--text-secondary)] hover:bg-[var(--bg-surface)] transition-all"
          >
            Go Back
          </button>
          <Link href="/" className="flex items-center justify-center px-6 h-10 rounded bg-[var(--accent)] text-[var(--text-inverse)] text-[11px] font-bold uppercase tracking-widest hover:shadow-lg transition-all">
            Return Home
          </Link>
        </div>
      </div>
    );
  }

  const cat = entityTypeToCategory(entity.entity_type);
  const meta = CATEGORY_META[cat];

  return (
    <div className="relative min-h-screen bg-[var(--bg-void)] font-sans text-[var(--text-primary)] overflow-x-hidden">
      {/* Design System Noise/Overlay */}
      <div className="pointer-events-none fixed inset-0 z-50 opacity-[0.03] contrast-150" style={{ backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E")` }} />
      
      {/* Dynamic Background */}
      <div className="fixed inset-0 z-0">
         <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_0%,_rgba(var(--accent-rgb),0.05)_0%,_transparent_50%)]" />
         <div className="absolute inset-0 bg-[linear-gradient(to_bottom,rgba(255,255,255,0.02)_0px,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:100%_40px] opacity-10" />
      </div>

      {/* 1. Command Header */}
      <header className="sticky top-0 z-[100] h-14 border-b border-[var(--border-dim)] bg-[var(--bg-surface)]/80 backdrop-blur-md px-6">
        <div className="mx-auto flex h-full max-w-[1600px] items-center justify-between">
          <div className="flex items-center gap-6">
            <button
              onClick={() => router.back()}
              className="h-8 w-8 flex items-center justify-center rounded border border-[var(--border-dim)] text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] transition-all"
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
            </button>
            <div className="flex items-center gap-3">
               <div className="h-2 w-2 rounded-full" style={{ backgroundColor: meta.color, boxShadow: `0 0 10px ${meta.color}` }} />
               <div className="space-y-0.5">
                  <p className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)] opacity-60 leading-none">Intelligence Dossier</p>
                  <p className="font-heading text-lg font-bold tracking-tight text-[var(--text-primary)] leading-none truncate max-w-[300px] md:max-w-md">{entity.value}</p>
               </div>
            </div>
          </div>

          <div className="flex items-center gap-8">
            <div className="hidden sm:flex flex-col items-end">
               <span className="text-[9px] font-bold uppercase tracking-tighter text-[var(--text-muted)]">Source Confidence</span>
               <span className="text-[12px] font-mono font-bold" style={{ color: entity.confidence >= 0.7 ? 'var(--success)' : 'var(--danger)' }}>
                  {Math.round(entity.confidence * 100)}%
               </span>
            </div>
            <button
              onClick={() => {
                const url = `/api/entities/${encodeURIComponent(entity.id)}/export?format=json`;
                const a = document.createElement("a");
                a.href = url;
                a.download = `entity_${entity.id}.json`;
                a.click();
              }}
              className="px-5 h-9 bg-[var(--accent)] text-[var(--text-inverse)] text-[10px] font-bold uppercase tracking-widest rounded transition-all hover:shadow-[0_0_15px_rgba(var(--accent-rgb),0.4)]"
            >
              Export
            </button>
          </div>
        </div>
      </header>

      {/* 2. Intelligence Workspace */}
      <main className="relative z-10 mx-auto max-w-[1600px] px-6 py-8">
        <div className="grid grid-cols-12 gap-8">
          
          {/* Left Panel: Core Identity */}
          <aside className="col-span-12 lg:col-span-3 space-y-8">
             <div className="p-6 rounded-xl border border-[var(--border-dim)] bg-[var(--bg-surface)] backdrop-blur-sm shadow-xl">
                <EntityIdentityPanel entity={entity} />
             </div>
          </aside>

          {/* Center Panel: Network & Associations */}
          <section className="col-span-12 lg:col-span-6 space-y-8">
            {/* Network Visualization */}
            <div className="rounded-xl border border-[var(--border-dim)] bg-[var(--bg-surface)] overflow-hidden">
               <div className="flex items-center justify-between px-5 py-3 border-b border-[var(--border-dim)] bg-[var(--bg-raised)]">
                  <h3 className="text-[10px] font-bold uppercase tracking-[0.2em] text-[var(--text-primary)]">Relational Network</h3>
                  <span className="text-[9px] font-mono font-bold text-[var(--text-muted)]">{related?.neighbors.length || 0} Nodes</span>
               </div>
               <div className="h-[460px] relative bg-[var(--bg-void)]">
                 <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_transparent_0%,_var(--bg-void)_90%)] z-10 opacity-30 pointer-events-none" />
                 <EntityMiniGraph data={related} loading={!entity && loading} />
               </div>
            </div>

            {/* Related Registry */}
            <div className="p-6 rounded-xl border border-[var(--border-dim)] bg-[var(--bg-surface)]">
               <EntityRelated neighbors={related?.neighbors ?? []} />
            </div>
          </section>

          {/* Right Panel: Temporal Trace */}
          <aside className="col-span-12 lg:col-span-3 space-y-8">
             <div className="p-6 rounded-xl border border-[var(--border-dim)] bg-[var(--bg-surface)] backdrop-blur-sm">
                <EntityTimeline entity={entity} />
             </div>
          </aside>
        </div>

        {/* 3. Deep Analysis Modules (THREAT_ACTOR and ONION_URL only) */}
        {(cat === "THREAT_ACTOR" || cat === "ONION_URL") && (
          <div className="mt-12 pt-12 border-t border-[var(--border-dim)] grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div className="space-y-4">
               <div className="flex items-center gap-3">
                  <div className="h-1.5 w-1.5 rounded-full bg-[var(--accent)]" />
                  <h3 className="text-[11px] font-bold uppercase tracking-widest text-[var(--text-primary)]">Linguistic Fingerprinting</h3>
               </div>
               {entity.entity_type === "THREAT_ACTOR" && (
                <div className="p-1 rounded-xl bg-[var(--bg-surface)] border border-[var(--border-dim)]">
                  <StylometryPanel
                    entityId={entity.id}
                    data={stylometry.data}
                    loading={stylometry.loading}
                    error={stylometry.error}
                    onExpand={fetchStylometry}
                  />
                </div>
              )}
            </div>

            <div className="space-y-4">
              <div className="flex items-center gap-3">
                  <div className="h-1.5 w-1.5 rounded-full bg-[var(--danger)]" />
                  <h3 className="text-[11px] font-bold uppercase tracking-widest text-[var(--text-primary)]">Vulnerability Vectors</h3>
               </div>
               <div className="p-1 rounded-xl bg-[var(--bg-surface)] border border-[var(--border-dim)]">
                <OpsecPanel
                  entityId={entity.id}
                  data={opsec.data}
                  loading={opsec.loading}
                  error={opsec.error}
                  onExpand={fetchOpsec}
                />
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
