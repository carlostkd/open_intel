"use client";

import { useMemo, useState } from "react";
import {
  CATEGORY_META,
  EntityCategoryKey,
  InvestigationEntity,
} from "@/lib/types/investigation";
import { getMitreUrl, getCveUrl } from "@/lib/utils/entityLinks";
import { getEntityTypeConfig } from "@/lib/utils/entityTypes";

interface Props {
  entities: InvestigationEntity[];
  selectedIds: Set<string>;
  onToggle: (id: string, next: boolean) => void;
  onEntityActivate: (e: InvestigationEntity) => void;
  loading: boolean;
  investigationParamId: string;
  minConfidence?: number;
  onMinConfidenceChange?: (value: number) => void;
}

const CONFIDENCE_OPTIONS = [
  { label: "All confidence levels", value: 0 },
  { label: ">= 0.95 (verified)", value: 0.95 },
  { label: ">= 0.85 (high)", value: 0.85 },
  { label: ">= 0.75 (medium)", value: 0.75 },
  { label: ">= 0.50 (low)", value: 0.5 },
];

const FRESHNESS_OPTIONS = [
  { label: "All freshness", value: "" },
  { label: "Fresh only", value: "fresh" },
  { label: "Exclude expired", value: "expired" },
];

const SOURCE_TOOLTIPS: Record<string, string> = {
  OTX: "AlienVault Open Threat Exchange",
  ThreatFox: "Abuse.ch ThreatFox IOC database",
  MalwareBazaar: "Abuse.ch MalwareBazaar",
  URLhaus: "Abuse.ch URLhaus",
  Shodan: "Shodan Internet-wide scan data",
  VirusTotal: "VirusTotal malware database",
  CISA_KEV: "CISA Known Exploited Vulnerabilities",
  MITRE_ATTACK: "MITRE ATT&CK framework",
  dark_web_scrape: "Extracted from dark web pages",
  paste_site: "Found in a public paste site (clearnet)",
  Pastebin: "Found in a Pastebin paste",
  dpaste: "Found in a dpaste paste",
  "paste.ee": "Found in a paste.ee paste",
  Rentry: "Found in a Rentry paste",
  GitHub: "Extracted from a GitHub repository",
  github: "Extracted from a GitHub repository",
  GitLab: "Extracted from a GitLab repository",
  gitlab: "Extracted from a GitLab repository",
  rss_feed: "Found in a threat intelligence news article",
  "Krebs on Security": "Found in a Krebs on Security article",
  BleepingComputer: "Found in a BleepingComputer article",
  "The Record by Recorded Future": "Found in The Record article",
  "Cisco Talos Intelligence": "Found in a Talos Intelligence report",
  "Mandiant Blog": "Found in a Mandiant threat report",
  "CrowdStrike Blog": "Found in a CrowdStrike intelligence report",
  "Palo Alto Unit 42": "Found in a Unit 42 threat report",
  "US-CERT Alerts": "Referenced in a US-CERT advisory",
  "CISA News": "Referenced in a CISA advisory",
  "Microsoft Security Blog": "Found in a Microsoft Security report",
};

const PASTE_SOURCE_NAMES = new Set([
  "paste_site",
  "Pastebin",
  "dpaste",
  "paste.ee",
  "Rentry",
]);

const GITHUB_SOURCE_NAMES = new Set(["GitHub", "github"]);

const GITLAB_SOURCE_NAMES = new Set(["GitLab", "gitlab"]);

const RSS_SOURCE_NAMES = new Set([
  "rss_feed",
  "Krebs on Security",
  "BleepingComputer",
  "The Record by Recorded Future",
  "Dark Reading",
  "SecurityWeek",
  "Threatpost",
  "SANS Internet Storm Center",
  "Malwarebytes Labs",
  "Cisco Talos Intelligence",
  "Sophos News",
  "Mandiant Blog",
  "CrowdStrike Blog",
  "Secureworks CTU",
  "US-CERT Alerts",
  "CISA News",
  "FBI Cyber Division News",
  "Recorded Future Intelligence",
  "Palo Alto Unit 42",
  "Microsoft Security Blog",
  "Google Project Zero",
]);

function hasPasteSource(sources?: string[]): boolean {
  if (!sources) return false;
  return sources.some((s) => PASTE_SOURCE_NAMES.has(s));
}

function hasGithubSource(sources?: string[]): boolean {
  if (!sources) return false;
  return sources.some((s) => GITHUB_SOURCE_NAMES.has(s));
}

function hasGitlabSource(sources?: string[]): boolean {
  if (!sources) return false;
  return sources.some((s) => GITLAB_SOURCE_NAMES.has(s));
}

function hasRssFeedSource(sources?: string[]): boolean {
  if (!sources) return false;
  return sources.some((s) => RSS_SOURCE_NAMES.has(s));
}

function getRssSourceLabel(sources?: string[]): string {
  if (!sources) return "News";
  const named = sources.find(
    (s) => RSS_SOURCE_NAMES.has(s) && s !== "rss_feed"
  );
  return named ?? "News";
}

function isWaybackArchived(sources?: string[]): boolean {
  return sources?.includes("wayback_archived") ?? false;
}

function isUrlscanMalicious(sources?: string[]): boolean {
  return sources?.includes("urlscan_malicious") ?? false;
}

function hasCTHistory(sources?: string[]): boolean {
  return sources?.includes("has_ct_history") ?? false;
}

function getSubdomainCount(sources?: string[]): number {
  if (!sources) return 0;
  for (const s of sources) {
    if (s.startsWith("subdomain_count_")) {
      const n = parseInt(s.replace("subdomain_count_", ""), 10);
      return isNaN(n) ? 0 : n;
    }
  }
  return 0;
}

function isLikelyTakenDown(sources?: string[]): boolean {
  return sources?.includes("likely_taken_down") ?? false;
}

function isHashMalicious(sources?: string[]): boolean {
  return sources?.includes("hybrid_analysis_malicious") ?? false;
}

function isHashSuspicious(sources?: string[]): boolean {
  return (
    (sources?.includes("hybrid_analysis_suspicious") ?? false) &&
    !isHashMalicious(sources)
  );
}

function isHashClean(sources?: string[]): boolean {
  return (
    (sources?.includes("hybrid_analysis_clean") ?? false) &&
    !isHashMalicious(sources) &&
    !isHashSuspicious(sources)
  );
}

function getMalwareFamilyFromSources(sources?: string[]): string {
  if (!sources) return "";
  for (const s of sources) {
    if (s.startsWith("malware_family_")) {
      return s.replace("malware_family_", "").replace(/_/g, " ");
    }
  }
  return "";
}

function getAvDetectionData(
  sources?: string[]
): { n: number; total: number } | null {
  if (!sources) return null;
  for (const s of sources) {
    const m = s.match(/^av_detections_(\d+)_of_(\d+)$/);
    if (m) return { n: parseInt(m[1], 10), total: parseInt(m[2], 10) };
  }
  return null;
}

function isHashEntity(entityType?: string): boolean {
  return (
    entityType === "FILE_HASH_MD5" ||
    entityType === "FILE_HASH_SHA1" ||
    entityType === "FILE_HASH_SHA256"
  );
}

function isEmailEntity(entityType?: string): boolean {
  return entityType === "EMAIL_ADDRESS";
}

function isHibpBreached(sources?: string[]): boolean {
  return sources?.includes("hibp_breached") ?? false;
}

function getHibpBreachCount(sources?: string[]): number {
  if (!sources) return 0;
  for (const s of sources) {
    if (s.startsWith("hibp_breach_count_")) {
      const n = parseInt(s.replace("hibp_breach_count_", ""), 10);
      return isNaN(n) ? 0 : n;
    }
  }
  return 0;
}

function isHibpPasswordExposed(sources?: string[]): boolean {
  return sources?.includes("hibp_password_exposed") ?? false;
}

function isDisposableEmail(sources?: string[]): boolean {
  return sources?.includes("disposable_email") ?? false;
}

function isEmailrepMalicious(sources?: string[]): boolean {
  return sources?.includes("emailrep_malicious") ?? false;
}

function isCredentialsLeaked(sources?: string[]): boolean {
  return sources?.includes("credentials_leaked") ?? false;
}

function isConfirmedC2(sources?: string[]): boolean {
  return sources?.includes("confirmed_c2") ?? false;
}

function getC2Family(sources?: string[]): string {
  if (!sources) return "";
  for (const s of sources) {
    if (s.startsWith("confirmed_c2_") && s !== "confirmed_c2") {
      return s.replace("confirmed_c2_", "").replace(/_/g, " ");
    }
  }
  return "";
}

function isAbuseConfirmed(sources?: string[]): boolean {
  return sources?.includes("abuse_confirmed") ?? false;
}

function getFreshnessColor(tag?: string): string {
  const colors: Record<string, string> = {
    fresh: "bg-green-500",
    aging: "bg-yellow-500",
    stale: "bg-orange-500",
    expired: "bg-red-500",
    unknown: "bg-gray-500",
  };
  return colors[tag || "unknown"] || "bg-gray-500";
}

export function EntitySidebar({
  entities,
  selectedIds,
  onToggle,
  onEntityActivate,
  loading,
  minConfidence = 0.75,
  onMinConfidenceChange,
}: Props) {
  const [search, setSearch] = useState("");
  const [freshnessFilter, setFreshnessFilter] = useState("");

  const filtered = useMemo(() => {
    const s = search.toLowerCase().trim();
    let result = entities;
    if (s) {
      result = result.filter(
        (e) =>
          e.value.toLowerCase().includes(s) ||
          (e.category as string).toLowerCase().includes(s)
      );
    }
    if (freshnessFilter === "fresh") {
      result = result.filter((e) => e.freshness_tag === "fresh");
    } else if (freshnessFilter === "expired") {
      result = result.filter((e) => e.freshness_tag !== "expired");
    }
    return result;
  }, [entities, search, freshnessFilter]);

  const grouped = useMemo(() => {
    const map: Partial<Record<EntityCategoryKey, InvestigationEntity[]>> = {};
    filtered.forEach((e) => {
      const cat = e.category as EntityCategoryKey;
      if (!map[cat]) map[cat] = [];
      map[cat]!.push(e);
    });
    return Object.entries(map).sort((a, b) => b[1].length - a[1].length) as [
      EntityCategoryKey,
      InvestigationEntity[],
    ][];
  }, [filtered]);

  return (
    <div className="flex h-full flex-col font-sans">
      {/* Search Header */}
      <div className="p-4 border-b border-[var(--border-dim)] bg-[var(--bg-surface)] space-y-3">
        <div className="relative group">
          <svg
            className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-muted)] group-focus-within:text-[var(--accent)] transition-colors"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
          <input
            type="text"
            placeholder="Search investigation..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--bg-void)] py-1.5 pl-9 pr-3 text-[12px] text-[var(--text-primary)] outline-none transition-all placeholder:text-[var(--text-muted)] focus:border-[var(--accent-border)] focus:ring-1 focus:ring-[var(--accent-dim)]"
          />
        </div>
        <select
          value={minConfidence}
          onChange={(e) => onMinConfidenceChange?.(parseFloat(e.target.value))}
          className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--bg-void)] py-1.5 px-2 text-[11px] text-[var(--text-secondary)] outline-none transition-all focus:border-[var(--accent-border)] cursor-pointer"
        >
          {CONFIDENCE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <select
          value={freshnessFilter}
          onChange={(e) => setFreshnessFilter(e.target.value)}
          className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--bg-void)] py-1.5 px-2 text-[11px] text-[var(--text-secondary)] outline-none transition-all focus:border-[var(--accent-border)] cursor-pointer"
        >
          {FRESHNESS_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <div className="text-[10px] font-mono text-[var(--text-muted)] text-center">
          {filtered.length} entities at this confidence level
        </div>
      </div>

      {/* Entity Lists */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden p-2 custom-scrollbar bg-[var(--bg-surface)]">
        {loading && grouped.length === 0 ? (
          <div className="flex flex-col gap-3 p-4">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-16 w-full animate-pulse rounded bg-[var(--bg-raised)]" />
            ))}
          </div>
        ) : grouped.length === 0 ? (
          <div className="flex h-32 flex-col items-center justify-center text-center p-4">
            <span className="text-[18px] text-[var(--text-muted)] opacity-20">◆</span>
            <p className="mt-2 text-[11px] font-medium text-[var(--text-muted)] uppercase tracking-widest">
              No matching intelligence
            </p>
          </div>
        ) : (
          <div className="space-y-6">
            {grouped.map(([cat, items]) => {
              const meta = CATEGORY_META[cat] || CATEGORY_META.OTHER;
              return (
                <section key={cat} className="space-y-1">
                  <header className="sticky top-0 z-10 flex items-center justify-between bg-[var(--bg-surface)] px-2 py-1">
                    <div className="flex items-center gap-2">
                      <div
                        className="h-3 w-1 rounded-full"
                        style={{ backgroundColor: meta.color }}
                      />
                      <span className="text-[10px] font-bold uppercase tracking-[0.08em] text-[var(--text-secondary)]">
                        {meta.label}
                      </span>
                    </div>
                    <span className="font-mono text-[9px] text-[var(--text-muted)]">
                      {items.length}
                    </span>
                  </header>

                  <div className="space-y-0.5">
                    {items.map((e) => {
                      const selected = selectedIds.has(e.id);
                      const typeConfig = getEntityTypeConfig(e.entity_type);
                      const isMitresTech = e.entity_type === "MITRE_TECHNIQUE";
                      const isCve = e.entity_type === "CVE";
                      const isOnion = e.entity_type === "ONION_URL";

                      const renderValue = () => {
                        if (isMitresTech) {
                          return (
                            <a
                              href={getMitreUrl(e.value)}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="truncate font-mono text-[12px] font-semibold tracking-tighter text-[var(--accent)] hover:underline"
                              onClick={(ev) => ev.stopPropagation()}
                            >
                              {e.value}
                              <svg className="ml-1 inline h-2.5 w-2.5" viewBox="0 0 16 16" fill="none">
                                <path d="M12 2h4v4M14 2L8 8M6 14H2v-4M2 14l6-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                              </svg>
                            </a>
                          );
                        }
                        if (isCve) {
                          return (
                            <a
                              href={getCveUrl(e.value)}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="truncate font-mono text-[12px] font-semibold tracking-tighter text-[var(--accent)] hover:underline"
                              onClick={(ev) => ev.stopPropagation()}
                            >
                              {e.value}
                              <svg className="ml-1 inline h-2.5 w-2.5" viewBox="0 0 16 16" fill="none">
                                <path d="M12 2h4v4M14 2L8 8M6 14H2v-4M2 14l6-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                              </svg>
                            </a>
                          );
                        }
                        return (
                          <span className={`truncate font-mono text-[12px] font-semibold tracking-tighter ${
                            selected ? "text-[var(--accent)]" : "text-[var(--text-primary)]"
                          }`}>
                            {e.value}
                          </span>
                        );
                      };

                      return (
                        <div
                          key={e.id}
                          className={`group relative flex cursor-pointer items-center justify-between rounded-md border py-2 px-3 transition-all ${
                            selected
                              ? "border-[var(--accent-border)] bg-[var(--accent-dim)]"
                              : "border-transparent hover:bg-[var(--bg-raised)] hover:border-[var(--border-dim)]"
                          }`}
                          onClick={() => onEntityActivate(e)}
                        >
                          <div className="flex min-w-0 flex-col gap-0.5">
                            <div className="flex items-center gap-2">
                              {renderValue()}
                              <span
                                className="shrink-0 rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider"
                                style={{
                                  backgroundColor: typeConfig.color,
                                  color: typeConfig.textColor,
                                }}
                              >
                                {typeConfig.label}
                              </span>
                              {(e.source_count ?? 1) > 1 && (
                                <span
                                  className={`shrink-0 rounded px-1.5 py-0.5 text-[9px] font-bold ${
                                    (e.source_count ?? 1) >= 4
                                      ? "bg-green-600 text-white"
                                      : "bg-blue-600 text-white"
                                  }`}
                                >
                                  {(e.source_count ?? 1) >= 4 ? "✓ " : ""}{(e.source_count ?? 1)} sources
                                </span>
                              )}
                              {hasPasteSource(e.corroborating_sources) && (
                                <span
                                  title={SOURCE_TOOLTIPS.paste_site}
                                  className="shrink-0 rounded bg-amber-700 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  📋 Paste
                                </span>
                              )}
                              {hasGithubSource(e.corroborating_sources) && (
                                <span
                                  title={SOURCE_TOOLTIPS.GitHub}
                                  className="shrink-0 rounded bg-indigo-700 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  🐙 GitHub
                                </span>
                              )}
                              {hasGitlabSource(e.corroborating_sources) && (
                                <span
                                  title={SOURCE_TOOLTIPS.GitLab}
                                  className="shrink-0 rounded bg-orange-700 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  🦊 GitLab
                                </span>
                              )}
                              {hasRssFeedSource(e.corroborating_sources) && (
                                <span
                                  title={
                                    SOURCE_TOOLTIPS[
                                      getRssSourceLabel(e.corroborating_sources)
                                    ] ?? SOURCE_TOOLTIPS.rss_feed
                                  }
                                  className="shrink-0 rounded bg-teal-700 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  📰 News
                                </span>
                              )}
                              {isConfirmedC2(e.corroborating_sources) && (
                                <span
                                  title={
                                    getC2Family(e.corroborating_sources)
                                      ? `Confirmed C2 · ${getC2Family(e.corroborating_sources)}`
                                      : "Confirmed command-and-control server"
                                  }
                                  className="shrink-0 rounded bg-red-700 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  C2{getC2Family(e.corroborating_sources) ? ` · ${getC2Family(e.corroborating_sources)}` : ""}
                                </span>
                              )}
                              {isAbuseConfirmed(e.corroborating_sources) && (
                                <span
                                  title="Community-reported IP abuse (AbuseIPDB)"
                                  className="shrink-0 rounded bg-orange-600 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  Reported
                                </span>
                              )}
                              {isWaybackArchived(e.corroborating_sources) && (
                                <span
                                  title="Historical snapshots found in Wayback Machine"
                                  className="shrink-0 rounded bg-purple-700 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  Archived
                                </span>
                              )}
                              {isUrlscanMalicious(e.corroborating_sources) && (
                                <span
                                  title="Flagged malicious by URLScan.io"
                                  className="shrink-0 rounded bg-red-600 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  Malicious
                                </span>
                              )}
                              {hasCTHistory(e.corroborating_sources) && (
                                <span
                                  title={`${getSubdomainCount(e.corroborating_sources)} subdomains found in certificate transparency logs`}
                                  className="shrink-0 rounded bg-blue-700 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  CT Logs {getSubdomainCount(e.corroborating_sources) > 0 ? `·${getSubdomainCount(e.corroborating_sources)}` : ""}
                                </span>
                              )}
                              {isLikelyTakenDown(e.corroborating_sources) && (
                                <span
                                  title="Domain appears to have been taken down"
                                  className="shrink-0 rounded bg-amber-600 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  Taken Down
                                </span>
                              )}
                              {isHashEntity(e.entity_type) && isHashMalicious(e.corroborating_sources) && (
                                <span
                                  title={
                                    getMalwareFamilyFromSources(e.corroborating_sources)
                                      ? `Confirmed malware · ${getMalwareFamilyFromSources(e.corroborating_sources)}`
                                      : "Confirmed malicious by sandbox analysis"
                                  }
                                  className="shrink-0 rounded bg-red-700 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  Malware{getMalwareFamilyFromSources(e.corroborating_sources) ? ` · ${getMalwareFamilyFromSources(e.corroborating_sources)}` : ""}
                                </span>
                              )}
                              {isHashEntity(e.entity_type) && isHashSuspicious(e.corroborating_sources) && (
                                <span
                                  title="Flagged suspicious — not confirmed malicious"
                                  className="shrink-0 rounded bg-orange-600 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  Suspicious
                                </span>
                              )}
                              {isHashEntity(e.entity_type) && isHashClean(e.corroborating_sources) && (
                                <span
                                  title="No detections across checked sources"
                                  className="shrink-0 rounded bg-gray-600 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  Clean
                                </span>
                              )}
                              {isHashEntity(e.entity_type) && (() => {
                                const av = getAvDetectionData(e.corroborating_sources);
                                if (!av) return null;
                                return (
                                  <span
                                    title={`Detected by ${av.n} of ${av.total} AV vendors`}
                                    className="shrink-0 rounded bg-blue-700 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                  >
                                    {av.n}/{av.total} AV
                                  </span>
                                );
                              })()}
                              {isEmailEntity(e.entity_type) && isHibpBreached(e.corroborating_sources) && (
                                <span
                                  title={(() => {
                                    const n = getHibpBreachCount(e.corroborating_sources);
                                    return n > 0 ? `Found in ${n} known data breach${n === 1 ? "" : "es"} (HaveIBeenPwned)` : "Found in known data breaches (HaveIBeenPwned)";
                                  })()}
                                  className="shrink-0 rounded bg-red-700 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  Breached{getHibpBreachCount(e.corroborating_sources) > 0 ? ` ·${getHibpBreachCount(e.corroborating_sources)}` : ""}
                                </span>
                              )}
                              {isEmailEntity(e.entity_type) && isHibpPasswordExposed(e.corroborating_sources) && (
                                <span
                                  title="Password hash or plaintext exposed in breach data"
                                  className="shrink-0 rounded bg-red-900 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  Pwd Exposed
                                </span>
                              )}
                              {isEmailEntity(e.entity_type) && isDisposableEmail(e.corroborating_sources) && (
                                <span
                                  title="Temporary/disposable email address"
                                  className="shrink-0 rounded bg-gray-600 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  Disposable
                                </span>
                              )}
                              {isEmailEntity(e.entity_type) && isEmailrepMalicious(e.corroborating_sources) && (
                                <span
                                  title="Associated with malicious activity per EmailRep"
                                  className="shrink-0 rounded bg-orange-600 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  Malicious
                                </span>
                              )}
                              {isEmailEntity(e.entity_type) && isCredentialsLeaked(e.corroborating_sources) && (
                                <span
                                  title="Credentials found in stealer logs"
                                  className="shrink-0 rounded bg-purple-700 px-1.5 py-0.5 text-[9px] font-bold text-white"
                                >
                                  Leaked Creds
                                </span>
                              )}
                            </div>
                            <div className="flex items-center gap-2">
                              {e.freshness_label && (
                                <span className="flex items-center gap-1">
                                  <span className={`h-1.5 w-1.5 rounded-full ${getFreshnessColor(e.freshness_tag)}`} />
                                  <span className="text-[10px] text-[var(--text-muted)]">
                                    {e.freshness_label}
                                  </span>
                                </span>
                              )}
                              {(e.corroborating_sources?.length ?? 0) > 1 && (
                                <span className="text-[9px] text-[var(--text-muted)] truncate">
                                  {e.corroborating_sources?.join(" · ")}
                                </span>
                              )}
                            </div>
                            {e.context?.[0] && (
                              <span className="truncate text-[10px] text-[var(--text-muted)] leading-tight opacity-70">
                                {e.context[0]}
                              </span>
                            )}
                          </div>

                          <button
                            onClick={(ev) => {
                              ev.stopPropagation();
                              onToggle(e.id, !selected);
                            }}
                            className={`flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors ${
                              selected
                                ? "border-[var(--accent)] bg-[var(--accent)] text-[var(--text-inverse)]"
                                : "border-[var(--border-subtle)] opacity-0 group-hover:opacity-100 hover:border-[var(--accent)]"
                            }`}
                          >
                            {selected && (
                              <svg viewBox="0 0 16 16" fill="white" className="h-2.5 w-2.5">
                                <path d="M13.5 4.5l-7.5 7.5-3.5-3.5" stroke="white" strokeWidth="2" fill="none" />
                              </svg>
                            )}
                          </button>
                        </div>
                      );
                    })}
                  </div>
                </section>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

