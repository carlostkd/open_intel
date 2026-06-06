"use client";

import Link from "next/link";
import { ParticleCanvas } from "@/components/ParticleCanvas";
import { StatusBar } from "@/components/StatusBar";
import { MonitorTable } from "@/components/MonitorTable";
import { CreateMonitorForm } from "@/components/CreateMonitorForm";
import { useMonitors } from "@/hooks/useMonitors";

export default function MonitorPage() {
  const {
    monitors,
    total_unacknowledged,
    loading,
    error,
    createMonitor,
    deleteMonitor,
    triggerMonitor,
    refresh,
  } = useMonitors();

  return (
    <div className="relative min-h-screen bg-[var(--bg-void)] font-sans text-[var(--text-primary)] transition-all">
      {/* Design System Grain Overlay */}
      <div className="pointer-events-none fixed inset-0 z-[50] opacity-[0.03] contrast-150" style={{ backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E")` }} />
      
      {/* Background Layers */}
      <div className="fixed inset-0 z-0">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,_#111111_0%,_transparent_50%)] opacity-40" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_100%_100%,_#0a0a0a_0%,_transparent_40%)] opacity-30" />
      </div>

      <ParticleCanvas />

      {/* Navigation */}
      <header className="fixed border-b border-[var(--border-dim)] backdrop-blur-md left-0 right-0 top-0 z-[100] h-14 bg-[var(--bg-surface)]/80">
        <div className="mx-auto flex h-full max-w-[1400px] items-center justify-between px-6">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="h-6 w-6 rounded bg-[var(--accent)] flex items-center justify-center text-[var(--text-inverse)] font-bold text-[10px] transform group-hover:rotate-12 transition-transform">V</div>
            <span className="font-heading text-lg font-bold tracking-tight text-[var(--text-primary)]">VoidAccess</span>
          </Link>

          <nav className="flex items-center gap-8">
            <Link href="/investigations" className="text-[11px] font-bold uppercase tracking-widest text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors">
              Investigations
            </Link>
            <Link href="/monitor" className="relative text-[11px] font-bold uppercase tracking-widest text-[var(--accent)] transition-colors">
              Monitor
              {total_unacknowledged > 0 && (
                <span className="absolute -top-1 -right-4 flex h-3 w-3 items-center justify-center rounded-full bg-[var(--danger)] text-[8px] font-bold text-white shadow-[0_0_8px_var(--danger)]">
                  {total_unacknowledged}
                </span>
              )}
            </Link>
            <Link href="/docs" className="text-[11px] font-bold uppercase tracking-widest text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors">
              Documentation
            </Link>
          </nav>
        </div>
      </header>

      {/* Main content */}
      <main className="relative z-10 mx-auto max-w-[1200px] px-6 pt-24 pb-20 space-y-12">
        {/* Page header */}
        <div className="flex items-end justify-between border-b border-[var(--border-dim)] pb-6">
          <div className="space-y-1">
            <h1 className="font-heading text-3xl font-bold tracking-tight text-[var(--text-primary)]">
              Network Monitoring Node
            </h1>
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-[var(--accent)]">
              Real-time dark web surveillance hub
            </p>
          </div>
          <div className="hidden md:flex flex-col items-end gap-1">
             <span className="text-[9px] font-bold uppercase tracking-widest text-[var(--text-muted)] opacity-50">Local System Time</span>
             <span className="font-mono text-[12px] tabular-nums text-[var(--text-secondary)]">{new Date().toISOString().replace('T', ' ').slice(0, 19)} Z</span>
          </div>
        </div>

        {/* Section 1 — Active Watches */}
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-1.5 w-1.5 rounded-full bg-[var(--accent)] shadow-[0_0_8px_var(--accent)]" />
              <h2 className="text-[11px] font-bold uppercase tracking-widest text-[var(--text-primary)]">Deployed Watchpoints</h2>
            </div>
            <div className="font-mono text-[9px] text-[var(--text-muted)] uppercase tracking-tight">
              {loading ? "Synchronizing..." : `${monitors.length} Active Probes`}
            </div>
          </div>

          <div className="min-h-[200px]">
            {loading ? (
              <div className="flex flex-col items-center justify-center py-20 bg-[var(--bg-surface)] rounded-xl border border-[var(--border-dim)] gap-4">
                <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent shadow-[0_0_15px_var(--accent-dim)]" />
                <span className="text-[11px] font-mono uppercase tracking-[0.2em] text-[var(--accent)]">Polling Node Status...</span>
              </div>
            ) : error ? (
              <div className="py-12 bg-[var(--danger-dim)] border border-[var(--danger)]/20 rounded-xl text-center">
                <p className="text-[12px] font-bold uppercase tracking-widest text-[var(--danger)]">Connection Failed: {error}</p>
              </div>
            ) : (
              <MonitorTable
                monitors={monitors}
                onTrigger={triggerMonitor}
                onDelete={deleteMonitor}
                onAlertsAcknowledged={() => void refresh()}
              />
            )}
          </div>
        </section>

        {/* Section 2 — Create New Monitor */}
        <section className="space-y-4 pt-4">
          <div className="flex items-center gap-3">
            <div className="h-1.5 w-1.5 rounded-full bg-[var(--text-muted)] opacity-40" />
            <h2 className="text-[11px] font-bold uppercase tracking-widest text-[var(--text-primary)]">Deployment Module</h2>
          </div>
          <CreateMonitorForm onSubmit={createMonitor} />
        </section>
      </main>

      <StatusBar />
    </div>
  );
}
