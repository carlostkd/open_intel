import Link from "next/link";

const ENTITY_TYPES = [
  { name: "Threat Actor", color: "#e05c5c", desc: "Handles, aliases, operator identities" },
  { name: "Wallet", color: "#9B9FEE", desc: "BTC/ETH/XMR addresses (auto blockchain lookup)" },
  { name: "Malware", color: "#d08770", desc: "Malware families, RATs, ransomware strains" },
  { name: "Forum", color: "#79b8ff", desc: "Dark web forum and marketplace names" },
  { name: "C2 Server", color: "#b392f0", desc: "Command & control infrastructure" },
  { name: "CVE", color: "#f0e68c", desc: "Vulnerability identifiers" },
  { name: "Onion URL", color: "#9ecbff", desc: ".onion addresses discovered during scraping" },
  { name: "Email", color: "#c9a35a", desc: "Email addresses extracted from content" },
  { name: "PGP Key", color: "#73d397", desc: "PGP fingerprints (used for actor correlation)" },
  { name: "Paste URL", color: "#56b6c2", desc: "Paste site URLs containing leaked data" },
];

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-[var(--bg-void)]">
      <div className="max-w-[720px] mx-auto px-6 py-12">
        <Link
          href="/"
          className="inline-block text-[13px] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors mb-8"
        >
          ← Back
        </Link>

        <h1 className="text-[28px] font-semibold text-[var(--text-primary)] mb-12">
          voidaccess / docs
        </h1>

        <section className="mb-10">
          <h2 className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] mb-4">
            Getting Started
          </h2>
          <p className="text-[15px] leading-[1.7] text-[var(--text-secondary)]">
            VoidAccess is a dark web OSINT platform. Submit an investigation query and the platform will:
          </p>
          <ol className="list-decimal list-inside text-[15px] leading-[1.7] text-[var(--text-secondary)] mt-3 space-y-2">
            <li>Search 18 dark web search engines simultaneously</li>
            <li>Scrape and extract entities from results</li>
            <li>Build a relationship graph</li>
            <li>Analyze for OPSEC failures and behavioral patterns</li>
          </ol>
        </section>

        <section className="mb-10">
          <h2 className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] mb-4">
            Writing Good Queries
          </h2>
          <p className="text-[15px] leading-[1.7] text-[var(--text-secondary)] mb-4">
            Effective queries are specific and targeted:
          </p>
          <div className="space-y-2">
            <code className="block bg-[var(--bg-raised)] text-[var(--accent)] text-[13px] px-3 py-2 rounded">
              LockBit ransomware bitcoin payment 2024
            </code>
            <code className="block bg-[var(--bg-raised)] text-[var(--accent)] text-[13px] px-3 py-2 rounded">
              CVE-2024-1234 exploit kit sale dark web
            </code>
            <code className="block bg-[var(--bg-raised)] text-[var(--accent)] text-[13px] px-3 py-2 rounded">
              threat actor handle forum credential dump
            </code>
          </div>
          <p className="text-[15px] leading-[1.7] text-[var(--text-secondary)] mt-4">
            Avoid overly broad queries like <span className="text-[var(--text-muted)]">hacking</span> or <span className="text-[var(--text-muted)]">dark web</span>.
          </p>
        </section>

        <section className="mb-10">
          <h2 className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] mb-4">
            Entity Types
          </h2>
          <div className="space-y-3">
            {ENTITY_TYPES.map((type) => (
              <div key={type.name} className="flex items-start gap-3">
                <span
                  className="w-2.5 h-2.5 rounded-full mt-1.5 shrink-0"
                  style={{ backgroundColor: type.color }}
                />
                <div>
                  <span className="text-[15px] text-[var(--text-primary)]">{type.name}</span>
                  <span className="text-[14px] text-[var(--text-muted)]"> — {type.desc}</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-10">
          <h2 className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] mb-4">
            Investigation Modes
          </h2>
          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <span className="text-[14px] font-semibold text-[var(--text-primary)] w-20 shrink-0">Standard</span>
              <span className="text-[14px] text-[var(--text-secondary)]">Search, scrape, extract, graph (5-12 min)</span>
            </div>
            <div className="flex items-start gap-3">
              <span className="text-[14px] font-semibold text-[var(--text-primary)] w-20 shrink-0">Full Intel</span>
              <span className="text-[14px] text-[var(--text-secondary)]">Adds recursive .onion crawler (15-45 min)</span>
            </div>
          </div>
        </section>

        <section className="mb-10">
          <h2 className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] mb-4">
            Graph Controls
          </h2>
          <ul className="text-[14px] text-[var(--text-secondary)] space-y-2">
            <li>• <span className="text-[var(--text-primary)]">Strong edges only</span> — hides weak cross-page links (recommended)</li>
            <li>• <span className="text-[var(--text-primary)]">Filter by type</span> — click entity type chips to isolate</li>
            <li>• <span className="text-[var(--text-primary)]">Click node</span> — opens entity detail panel</li>
            <li>• <span className="text-[var(--text-primary)]">Click entity name</span> — opens full profile page</li>
          </ul>
        </section>

        <section className="mb-10">
          <h2 className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] mb-4">
            Analysis Features
          </h2>
          <div className="space-y-4">
            <div>
              <h3 className="text-[15px] font-semibold text-[var(--text-primary)] mb-1">Temporal Analysis</h3>
              <p className="text-[14px] text-[var(--text-secondary)]">
                Activity patterns, anomaly detection, silence breaks. Found on investigation results page.
              </p>
            </div>
            <div>
              <h3 className="text-[15px] font-semibold text-[var(--text-primary)] mb-1">OPSEC Assessment</h3>
              <p className="text-[14px] text-[var(--text-secondary)]">
                Timezone leaks, language switches, PGP reuse detection. Found on entity profile (threat actors).
              </p>
            </div>
            <div>
              <h3 className="text-[15px] font-semibold text-[var(--text-primary)] mb-1">Stylometry</h3>
              <p className="text-[14px] text-[var(--text-secondary)]">
                Writing style fingerprinting for actor attribution. Found on entity profile (threat actors).
                Matches above 75% suggest possible same actor.
              </p>
            </div>
          </div>
        </section>

        <section className="mb-10">
          <h2 className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] mb-4">
            Exports
          </h2>
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-[var(--bg-raised)] px-4 py-3 rounded">
              <span className="text-[14px] font-semibold text-[var(--text-primary)]">STIX 2.1</span>
              <p className="text-[12px] text-[var(--text-muted)]">For SIEM/SOAR integration</p>
            </div>
            <div className="bg-[var(--bg-raised)] px-4 py-3 rounded">
              <span className="text-[14px] font-semibold text-[var(--text-primary)]">MISP</span>
              <p className="text-[12px] text-[var(--text-muted)]">For threat sharing platforms</p>
            </div>
            <div className="bg-[var(--bg-raised)] px-4 py-3 rounded">
              <span className="text-[14px] font-semibold text-[var(--text-primary)]">Sigma</span>
              <p className="text-[12px] text-[var(--text-muted)]">Detection rules from IOCs</p>
            </div>
            <div className="bg-[var(--bg-raised)] px-4 py-3 rounded">
              <span className="text-[14px] font-semibold text-[var(--text-primary)]">JSON</span>
              <p className="text-[12px] text-[var(--text-muted)]">Raw entity and relationship data</p>
            </div>
          </div>
        </section>

        <section className="mb-10">
          <h2 className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] mb-4">
            Monitoring
          </h2>
          <p className="text-[14px] text-[var(--text-secondary)]">
            Create keyword or URL watches. Alerts fire when content changes. Supports webhook, Telegram, and email delivery.
          </p>
        </section>

        <section className="mb-10">
          <h2 className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] mb-4">
            API Access
          </h2>
          <p className="text-[14px] text-[var(--text-secondary)] mb-3">
            All endpoints require Bearer token authentication.
          </p>
          <p className="text-[14px] text-[var(--text-secondary)] mb-3">
            Get token: <code className="bg-[var(--bg-raised)] text-[var(--accent)] text-[13px] px-2 py-0.5 rounded">POST /auth/login</code>
          </p>
          <p className="text-[14px] text-[var(--text-secondary)]">
            Full API: <a href="http://localhost:8000/docs" className="text-[var(--accent)] hover:underline">http://localhost:8000/docs</a> (FastAPI auto-docs)
          </p>
        </section>

        <section className="mb-10">
          <h2 className="font-mono text-[11px] uppercase tracking-widest text-[var(--text-muted)] mb-4">
            First Login
          </h2>
          <p className="text-[14px] text-[var(--text-secondary)]">
            Admin credentials are set during the initial deployment via <code className="bg-[var(--bg-raised)] text-[var(--accent)] text-[13px] px-2 py-0.5 rounded">bash setup.sh</code>.
          </p>
          <p className="text-[13px] text-[var(--text-muted)] mt-2">
            If you did not use the setup script, the default account will require a password reset before first use.
          </p>
        </section>


      </div>
    </div>
  );
}