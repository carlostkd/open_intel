"use client";

import { useEffect, useState } from "react";

const FACTS = [
  // OSINT tradecraft
  "OSINT analysts use passive DNS reanalysis to uncover previously hidden infrastructure changes without alerting targets.",
  "Threat actors on dark web forums often reuse operational handles across platforms — a single handle can link dozens of personas.",
  "Bitcoin transaction graph analysis can de-anonymize wallets with as few as three confirmed co-spend events.",
  "The average dwell time of an APT inside a compromised network before detection is 197 days.",
  "Domain generation algorithms (DGAs) can produce thousands of C2 candidates per day, but all share a statistical fingerprint.",
  "Silk Road's downfall began when an admin posted on Stack Overflow using their real identity months before launch.",
  "Most ransomware groups use affiliate programs — the core developers write the code, affiliates deploy it for a revenue split.",
  "Monero's ring signature size determines the anonymity set — most legitimate transactions use 16 decoys by default.",
  "A single RDP brute-force success sells for $10–$50 on dark web access brokers, scaled by domain privilege.",
  "Telegram is the most common exfiltration channel for initial access brokers, replacing older IRC and forum models.",
  // Threat intelligence
  "MITRE ATT&CK catalogues over 400 unique adversary techniques organized across 14 tactical phases.",
  "Nation-state APTs frequently timestamp malware compilations to match business hours in their home timezone — a classic OPSEC failure.",
  "The average ransomware demand in 2023 was $1.54M — but the median payment was significantly lower due to negotiation.",
  "Cobalt Strike's watermark system allows defenders to attribute payloads to specific licensed customers when leaked.",
  "LockBit's affiliate panel included a real-time chat feature for negotiating ransoms directly with victims.",
  "Exploit brokers like Zerodium pay up to $2.5M for full iOS zero-click chains — the most expensive class of vulnerability.",
  "The Conti group's internal Jabber logs, leaked in 2022, revealed a structured corporate hierarchy with HR, R&D, and management.",
  "Most cybercriminal groups operate on a 9-to-5 schedule aligned with Moscow Standard Time, including scheduled lunch breaks.",
  "RedLine Stealer is the most prevalent infostealer by volume — its logs are the dominant product on Genesis Market.",
  "Initial access brokers typically wait 60–90 days before selling access to allow full enumeration of the network's value.",
  // Dark web mechanics
  "V3 onion addresses are 56 characters long and use ed25519 keys — V2 addresses were deprecated in 2021.",
  "Tor's hidden service protocol routes traffic through 6 relays — 3 for the client and 3 for the server — via a rendezvous point.",
  "The vast majority of .onion addresses are never indexed — discovery relies on referrals, paste sites, or dedicated link lists.",
  "Most dark web marketplaces implement a 2-of-3 multisig escrow to prevent exit scams from administrators.",
  "Exit node operators on Tor can observe plaintext traffic for non-HTTPS connections — a known deanonymization vector.",
  "The Tor network has approximately 7,000 relays but only ~1,500 are exit nodes, creating a bandwidth bottleneck.",
  "Many .onion sites implement proof-of-work puzzles to defend against DDoS attacks while preserving anonymity.",
  // Crypto & financial crime
  "Chain analysis firms estimate that only 0.24% of crypto transactions in 2023 were associated with illicit activity.",
  "Tornado Cash handled over $7B in transactions before OFAC sanctions — roughly 25% of funds had traceable criminal origins.",
  "Hydra Market processed over $5.2B in Bitcoin before its 2022 takedown — the largest dark web market seizure in history.",
  "UTXO consolidation is a common de-anonymization vector — when wallets merge inputs, they reveal common ownership.",
  "Privacy coins like Zcash have optional shielded transactions — but most Zcash transactions are transparent by default.",
  // Technical tradecraft
  "Living-off-the-land (LotL) attacks use legitimate system binaries like PowerShell and WMI to avoid EDR detection.",
  "The average time from public CVE disclosure to active exploitation in the wild is now under 15 days.",
  "Phishing-as-a-Service kits like EvilGinx use reverse proxies to steal session cookies, bypassing MFA entirely.",
  "Supply chain attacks cost on average 4x more to remediate than standard breaches due to their downstream blast radius.",
  "Adversary simulation teams use purple teaming — real-time collaboration between red and blue teams — to accelerate detection tuning.",
];

// Returns display duration in ms per fact based on length
function getFactDuration(fact: string): number {
  return fact.length >= 100 ? 15000 : 10000;
}

const STEPS = ["SEARCH", "SCRAPE", "EXTRACT", "GRAPH", "SUMMARIZE"] as const;

// Map API pipeline step (1-13) to display step index (0-4)
function apiStepToDisplayIndex(apiStep: number | null | undefined): number {
  if (!apiStep || apiStep <= 0) return 0;
  if (apiStep <= 2) return 0; // SEARCH
  if (apiStep <= 4) return 1; // SCRAPE
  if (apiStep <= 6) return 2; // EXTRACT
  if (apiStep <= 7) return 3; // GRAPH
  return 4;                    // SUMMARIZE
}

interface Props {
  query: string;
  currentStep?: number | null;
  createdAt?: string | null;
  onCancelRequest?: () => void;
  cancelling?: boolean;
}

export function InvestigationLoadingScreen({ query, currentStep, createdAt, onCancelRequest, cancelling }: Props) {
  const [factIndex, setFactIndex] = useState(() => Math.floor(Math.random() * FACTS.length));
  const [visible, setVisible] = useState(true);
  const [dots, setDots] = useState(".");

  // Initialise elapsed from investigation start time, not from tab open
  const [elapsed, setElapsed] = useState(() => {
    if (!createdAt) return 0;
    const diff = Math.floor((Date.now() - new Date(createdAt).getTime()) / 1000);
    return Math.max(0, diff);
  });

  // Track current fact duration for progress bar animation
  const [factDuration, setFactDuration] = useState(() => getFactDuration(FACTS[Math.floor(Math.random() * FACTS.length)]));

  // Rotate facts using setTimeout so duration adapts per fact
  useEffect(() => {
    const duration = getFactDuration(FACTS[factIndex]);
    setFactDuration(duration);
    const timer = setTimeout(() => {
      setVisible(false);
      setTimeout(() => {
        setFactIndex((i) => (i + 1) % FACTS.length);
        setVisible(true);
      }, 400);
    }, duration);
    return () => clearTimeout(timer);
  }, [factIndex]);

  // Animate dots
  useEffect(() => {
    const interval = setInterval(() => {
      setDots((d) => (d.length >= 3 ? "." : d + "."));
    }, 500);
    return () => clearInterval(interval);
  }, []);

  // Tick elapsed every second
  useEffect(() => {
    const interval = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => clearInterval(interval);
  }, []);

  const elapsedLabel =
    elapsed < 60
      ? `${elapsed}s`
      : elapsed < 3600
        ? `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`
        : `${Math.floor(elapsed / 3600)}h ${Math.floor((elapsed % 3600) / 60)}m`;

  return (
    <div
      className="fixed inset-0 z-50 flex flex-col overflow-hidden"
      style={{ backgroundColor: "#080B11" }}
    >
      {/* Grid background — same as homepage */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage: `
            linear-gradient(rgba(30, 58, 95, 0.15) 1px, transparent 1px),
            linear-gradient(90deg, rgba(30, 58, 95, 0.15) 1px, transparent 1px)
          `,
          backgroundSize: "60px 60px",
        }}
      />

      {/* Radial vignette overlay */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse at center, rgba(8, 11, 17, 0) 0%, rgba(8, 11, 17, 0.8) 100%)",
        }}
      />

      {/* Header bar */}
      <div className="relative z-10 flex h-[56px] shrink-0 items-center justify-between border-b border-[var(--border-dim)] px-6">
        <div
          className="flex items-center gap-2"
          style={{ fontFamily: "var(--font-display)" }}
        >
          <span className="text-[var(--accent)]">●</span>
          <span className="text-[15px] font-bold tracking-tight text-[var(--text-primary)]">
            voidaccess
          </span>
        </div>
        <div className="flex items-center gap-2.5 rounded-full border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-3 py-1">
          <span className="h-1.5 w-1.5 rounded-full bg-[var(--warning)] animate-pulse" />
          <span
            className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-secondary)]"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            Analyzing Environment{dots}
          </span>
        </div>
      </div>

      {/* Main content */}
      <div className="relative z-10 flex flex-1 flex-col items-center justify-center gap-12 px-6">

        {/* Radar animation + query */}
        <div className="flex flex-col items-center gap-6 text-center">
          {/* Radar sonar rings */}
          <div className="radar-container">
            <div className="radar-ring" />
            <div className="radar-ring" />
            <div className="radar-ring" />
            <div className="radar-dot" />
          </div>

          <div className="flex flex-col items-center gap-2">
            <p
              className="text-[10px] font-bold uppercase tracking-[0.25em] text-[var(--text-muted)]"
              style={{ fontFamily: "var(--font-display)", letterSpacing: "0.15em", fontWeight: 500 }}
            >
              Active Investigation
            </p>
            <h2
              className="text-2xl font-bold tracking-tight text-[var(--text-primary)] max-w-md"
              style={{ fontFamily: "var(--font-display)", fontWeight: 600 }}
            >
              {query}
            </h2>
          </div>

          {/* Step pipeline — SEARCH ──●── SCRAPE … */}
          <div className="flex items-center gap-0">
            {STEPS.map((step, i) => {
              const activeIdx = apiStepToDisplayIndex(currentStep);
              const isDone    = i < activeIdx;
              const isCurrent = i === activeIdx;
              return (
                <div key={step} className="flex items-center">
                  <div className="flex flex-col items-center gap-1.5">
                    {isDone ? (
                      <div className="step-dot-done">✓</div>
                    ) : isCurrent ? (
                      <div className="step-dot" />
                    ) : (
                      <div className="step-dot-upcoming" />
                    )}
                    <span
                      className={`text-[9px] uppercase tracking-widest ${
                        isDone    ? "text-[var(--success)]" :
                        isCurrent ? "text-[var(--text-secondary)]" :
                                    "text-[var(--text-muted)]"
                      }`}
                      style={{ fontFamily: "var(--font-mono)", fontWeight: 500 }}
                    >
                      {step}
                    </span>
                  </div>
                  {i < STEPS.length - 1 && (
                    <div className={`mb-4 h-px w-8 ${isDone ? "bg-[var(--success)]" : "bg-[var(--border-dim)]"}`} />
                  )}
                </div>
              );
            })}
          </div>

          {/* Elapsed */}
          <p
            className="text-[10px] text-[var(--text-muted)] tracking-widest"
            style={{ fontFamily: "var(--font-mono)", fontWeight: 400 }}
          >
            ELAPSED: {elapsedLabel}
          </p>
        </div>

        {/* Fact rotator */}
        <div
          className="mx-auto w-full max-w-2xl rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-6"
          style={{ minHeight: "120px" }}
        >
          <div className="mb-3 flex items-center gap-2">
            <span
              className="text-[9px] font-bold uppercase tracking-[0.25em] text-[var(--accent)]"
              style={{ fontFamily: "var(--font-mono)" }}
            >
              Intelligence Briefing
            </span>
            <div className="flex-1 h-px bg-[var(--border-dim)]" />
            {/* Counter intentionally removed */}
          </div>

          <div
            style={{
              opacity: visible ? 1 : 0,
              transform: visible ? "translateY(0)" : "translateY(4px)",
              transition: "opacity 0.4s ease, transform 0.4s ease",
            }}
          >
            <p
              className="text-[13px] leading-relaxed text-[var(--text-secondary)]"
              style={{ fontFamily: "var(--font-body)", fontWeight: 400 }}
            >
              {FACTS[factIndex]}
            </p>
          </div>

          {/* Progress bar — duration adapts per fact */}
          <div className="mt-4 h-[2px] w-full overflow-hidden rounded-full bg-[var(--border-dim)]">
            <div
              key={factIndex}
              className="h-full rounded-full bg-[var(--accent)] opacity-50"
              style={{
                animation: `fact-progress ${factDuration / 1000}s linear`,
              }}
            />
          </div>
        </div>
      </div>

      {/* Footer — hint + cancel */}
      <div className="relative z-10 flex h-12 shrink-0 items-center justify-between border-t border-[var(--border-dim)] px-6">
        <p
          className="text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)]"
          style={{ fontFamily: "var(--font-mono)" }}
        >
          Fanning out across Tor network · Extracting entities · Building relationship graph
        </p>
        {onCancelRequest && (
          <button
            onClick={onCancelRequest}
            disabled={cancelling}
            className="flex items-center gap-2 rounded border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider text-red-400 transition-all hover:border-red-500/60 hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {cancelling ? "Cancelling…" : "Cancel investigation"}
          </button>
        )}
      </div>

      <style>{`
        /* ── Radar / sonar rings ─────────────────────────────── */
        .radar-container {
          position: relative;
          width: 120px;
          height: 120px;
          margin: 0 auto;
        }

        .radar-dot {
          position: absolute;
          top: 50%;
          left: 50%;
          width: 8px;
          height: 8px;
          background: #3B82F6;
          border-radius: 50%;
          transform: translate(-50%, -50%);
          box-shadow: 0 0 12px #3B82F6;
          z-index: 2;
        }

        .radar-ring {
          position: absolute;
          top: 50%;
          left: 50%;
          border: 1px solid rgba(155, 159, 238, 0.6);
          border-radius: 50%;
          transform: translate(-50%, -50%);
          animation: radar-pulse 2s ease-out infinite;
        }

        .radar-ring:nth-child(1) {
          animation-delay: 0s;
          width: 40px;
          height: 40px;
        }
        .radar-ring:nth-child(2) {
          animation-delay: 0.5s;
          width: 80px;
          height: 80px;
        }
        .radar-ring:nth-child(3) {
          animation-delay: 1s;
          width: 120px;
          height: 120px;
        }

        @keyframes radar-pulse {
          0%   { opacity: 0.8; transform: translate(-50%, -50%) scale(0.3); }
          100% { opacity: 0;   transform: translate(-50%, -50%) scale(1); }
        }

        /* ── Step dots ───────────────────────────────────────── */
        .step-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: var(--accent);
          animation: pulse-glow 1.5s ease-in-out infinite alternate;
        }

        .step-dot-done {
          width: 16px;
          height: 16px;
          border-radius: 50%;
          background: var(--success-dim);
          border: 1.5px solid var(--success);
          color: var(--success);
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 9px;
          font-weight: 700;
        }

        .step-dot-upcoming {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          border: 1.5px solid rgba(255,255,255,0.18);
          background: transparent;
        }

        @keyframes pulse-glow {
          from { opacity: 0.3; box-shadow: 0 0 4px 1px rgba(88,166,255,0.3); }
          to   { opacity: 1;   box-shadow: 0 0 10px 3px rgba(88,166,255,0.7); }
        }

        /* ── Fact progress bar ───────────────────────────────── */
        @keyframes fact-progress {
          from { width: 0% }
          to   { width: 100% }
        }
      `}</style>
    </div>
  );
}
