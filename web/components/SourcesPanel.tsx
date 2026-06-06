"use client";

const SOURCE_LABELS: Record<string, string> = {
  tor_search: "Tor Search",
  otx: "AlienVault OTX",
  malwarebazaar: "MalwareBazaar",
  threatfox: "ThreatFox",
  urlhaus: "URLhaus",
  ransomware_live: "ransomware.live",
  cisa: "CISA KEV",
  shodan: "Shodan InternetDB",
  virustotal: "VirusTotal",
  securitytrails: "SecurityTrails",
  github: "GitHub",
  gitlab: "GitLab",
  paste_sites: "Paste Sites",
  rss_feeds: "RSS Feeds",
  circl_pdns: "CIRCL pDNS",
};

// Canonical display order
const SOURCE_ORDER = [
  "tor_search",
  "otx",
  "malwarebazaar",
  "threatfox",
  "urlhaus",
  "ransomware_live",
  "cisa",
  "shodan",
  "virustotal",
  "securitytrails",
  "circl_pdns",
  "github",
  "gitlab",
  "paste_sites",
  "rss_feeds",
];

type DotColor = "green" | "gray" | "yellow" | "red";

function getDotColor(status: string): DotColor {
  if (!status || status.startsWith("skipped") || status === "pending") return "gray";
  if (status === "error") return "red";
  if (status.includes("_0_")) return "yellow";
  if (status.startsWith("ok")) return "green";
  return "gray";
}

function getResultCount(status: string): string | null {
  const m = status.match(/ok_(\d+)_/);
  return m ? m[1] : null;
}

function getTooltip(key: string, status: string): string {
  const label = SOURCE_LABELS[key] ?? key;
  if (!status || status === "pending") return `${label}: pending`;
  if (status === "skipped_no_key") return `${label}: skipped — no API key configured`;
  if (status === "skipped_disabled") return `${label}: disabled via env var`;
  if (status === "skipped_not_implemented") return `${label}: key present but not yet wired`;
  if (status === "error") return `${label}: failed with error`;
  const count = getResultCount(status);
  if (count === "0") return `${label}: ran, no results`;
  if (count !== null) {
    const unit = status.includes("_pages") ? "pages" : status.includes("_enrichments") ? "enrichments" : "results";
    return `${label}: ${count} ${unit}`;
  }
  return `${label}: ok`;
}

const DOT_CLASSES: Record<DotColor, string> = {
  green: "bg-green-500 shadow-[0_0_6px_rgba(74,222,128,0.6)]",
  gray: "bg-[var(--text-muted)] opacity-50",
  yellow: "bg-yellow-400",
  red: "bg-red-500",
};

const LEGEND = [
  { color: "green" as DotColor, label: "Results" },
  { color: "yellow" as DotColor, label: "No results" },
  { color: "gray" as DotColor, label: "Skipped" },
  { color: "red" as DotColor, label: "Error" },
];

interface Props {
  sourcesUsed: Record<string, string>;
}

export function SourcesPanel({ sourcesUsed }: Props) {
  if (!sourcesUsed || Object.keys(sourcesUsed).length === 0) {
    return (
      <p className="text-[12px] text-[var(--text-muted)]">
        Source data not available for this investigation.
      </p>
    );
  }

  // All known keys in order, then any extras not in SOURCE_ORDER
  const allKeys = [
    ...SOURCE_ORDER.filter(k => k in sourcesUsed),
    ...Object.keys(sourcesUsed).filter(k => !SOURCE_ORDER.includes(k)),
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-6">
        <h3 className="text-[11px] font-bold uppercase tracking-widest text-[var(--text-secondary)]">
          Intelligence Sources
        </h3>
        <div className="flex items-center gap-4">
          {LEGEND.map(({ color, label }) => (
            <span key={color} className="flex items-center gap-1.5">
              <span className={`h-2 w-2 rounded-full shrink-0 ${DOT_CLASSES[color]}`} />
              <span className="text-[10px] text-[var(--text-muted)]">{label}</span>
            </span>
          ))}
        </div>
      </div>

      <div className="flex flex-wrap gap-x-5 gap-y-3">
        {allKeys.map(key => {
          const status = sourcesUsed[key] ?? "";
          const color = getDotColor(status);
          const label = SOURCE_LABELS[key] ?? key;
          const tip = getTooltip(key, status);
          const count = getResultCount(status);

          return (
            <div
              key={key}
              title={tip}
              className="flex items-center gap-2 cursor-default select-none"
            >
              <span className={`h-2 w-2 rounded-full shrink-0 ${DOT_CLASSES[color]}`} />
              <span className="text-[12px] text-[var(--text-primary)]">{label}</span>
              {count !== null && count !== "0" && (
                <span className="text-[10px] font-mono text-[var(--text-muted)]">
                  ({count})
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
