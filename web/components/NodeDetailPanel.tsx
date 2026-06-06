"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import type Graph from "graphology";
import { getMitreUrl, getCveUrl } from "@/lib/utils/entityLinks";
import { formatRelativeTime } from "@/lib/utils/formatRelativeTime";

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface SelectedNodeData {
  id: string;
  label?: string;
  vaCategory?: string;
  color?: string;
  origColor?: string;
  // From GraphNodeJSON / raw attrs
  raw?: {
    id: string;
    type: string;
    confidence?: number;
    first_seen?: string | null;
    last_seen?: string | null;
    source_urls?: string[];
    metadata?: Record<string, unknown>;
  };
  // Extra enriched attrs possibly on graph node
  freshness_tag?: string;
  freshness_label?: string;
  freshness_color?: string;
  source_count?: number;
  corroborating_sources?: string[];
  context_snippet?: string;
  context?: string;
  // degree computed externally
  degree?: number;
}

interface EnrichedEntityData {
  id: string;
  entity_type: string;
  value: string;
  canonical_value?: string | null;
  confidence: number;
  context?: string | null;
  context_snippet?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  source_count?: number;
  corroborating_sources?: string[];
  freshness_tag?: string;
  freshness_label?: string;
  freshness_color?: string;
  metadata?: Record<string, unknown>;
}

interface NodeDetailPanelProps {
  node: SelectedNodeData | null;
  graph?: Graph | null;
  searchQuery?: string;
  onClose: () => void;
  onIsolateNeighbors: (nodeId: string) => void;
}

// ─── Graph topology helpers ────────────────────────────────────────────────────

function findHubNode(graph: Graph): string | null {
  const nodes = graph.nodes();
  if (!nodes.length) return null;
  return nodes.reduce(
    (best, n) => graph.degree(n) > graph.degree(best) ? n : best,
    nodes[0]
  );
}

function findClusterHub(nodeId: string, graph: Graph): { id: string; label: string } | null {
  const neighbors = graph.neighbors(nodeId);
  if (!neighbors.length) return null;
  const hub = neighbors.reduce(
    (best, n) => graph.degree(n) > graph.degree(best) ? n : best,
    neighbors[0]
  );
  return { id: hub, label: (graph.getNodeAttribute(hub, "label") as string) || hub };
}

function findClusterMembers(nodeId: string, graph: Graph, limit = 3): string[] {
  const neighbors = new Set(graph.neighbors(nodeId));
  const coOccurrence: Record<string, number> = {};
  neighbors.forEach(neighbor => {
    graph.neighbors(neighbor).forEach(n => {
      if (n !== nodeId && !neighbors.has(n)) {
        coOccurrence[n] = (coOccurrence[n] || 0) + 1;
      }
    });
  });
  return Object.entries(coOccurrence)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([id]) => (graph.getNodeAttribute(id, "label") as string) || id);
}

function findPathToHub(fromId: string, graph: Graph, maxDepth = 4): string[] {
  const hubNode = findHubNode(graph);
  if (!hubNode) return [];
  if (fromId === hubNode) return [fromId];

  const visited = new Set<string>([fromId]);
  const queue: string[][] = [[fromId]];

  while (queue.length > 0) {
    const path = queue.shift()!;
    const current = path[path.length - 1];
    if (path.length > maxDepth) continue;
    for (const neighbor of graph.neighbors(current)) {
      if (visited.has(neighbor)) continue;
      visited.add(neighbor);
      const newPath = [...path, neighbor];
      if (neighbor === hubNode) return newPath;
      queue.push(newPath);
    }
  }
  return [];
}

// ─── Helper: Paste-site source tooltips ─────────────────────────────────────────

const PASTE_SOURCE_TOOLTIPS: Record<string, string> = {
  paste_site: "Found in a public paste site (clearnet)",
  Pastebin: "Found in a Pastebin paste",
  dpaste: "Found in a dpaste paste",
  "paste.ee": "Found in a paste.ee paste",
  Rentry: "Found in a Rentry paste",
};

const PASTE_SOURCE_NAMES = new Set(Object.keys(PASTE_SOURCE_TOOLTIPS));

const GITHUB_SOURCE_TOOLTIPS: Record<string, string> = {
  GitHub: "Extracted from a GitHub repository",
  github: "Extracted from a GitHub repository",
};

const GITHUB_SOURCE_NAMES = new Set(Object.keys(GITHUB_SOURCE_TOOLTIPS));

const GITLAB_SOURCE_TOOLTIPS: Record<string, string> = {
  GitLab: "Extracted from a GitLab repository",
  gitlab: "Extracted from a GitLab repository",
};

const GITLAB_SOURCE_NAMES = new Set(Object.keys(GITLAB_SOURCE_TOOLTIPS));

const RSS_SOURCE_TOOLTIPS: Record<string, string> = {
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
  "Dark Reading": "Found in a Dark Reading article",
  SecurityWeek: "Found in a SecurityWeek article",
  Threatpost: "Found in a Threatpost article",
  "SANS Internet Storm Center": "Found in a SANS ISC diary",
  "Malwarebytes Labs": "Found in a Malwarebytes Labs report",
  "Sophos News": "Found in a Sophos News article",
  "Secureworks CTU": "Found in a Secureworks CTU report",
  "FBI Cyber Division News": "Referenced in an FBI press release",
  "Recorded Future Intelligence": "Found in a Recorded Future report",
  "Google Project Zero": "Found in a Google Project Zero post",
};

const RSS_SOURCE_NAMES = new Set(Object.keys(RSS_SOURCE_TOOLTIPS));

function getPasteSources(sources?: string[]): string[] {
  if (!sources) return [];
  return sources.filter((s) => PASTE_SOURCE_NAMES.has(s));
}

function getGithubSources(sources?: string[]): string[] {
  if (!sources) return [];
  return sources.filter((s) => GITHUB_SOURCE_NAMES.has(s));
}

function getGitlabSources(sources?: string[]): string[] {
  if (!sources) return [];
  return sources.filter((s) => GITLAB_SOURCE_NAMES.has(s));
}

function getRssFeedSources(sources?: string[]): string[] {
  if (!sources) return [];
  return sources.filter((s) => RSS_SOURCE_NAMES.has(s));
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

// ─── Helper: Category label ────────────────────────────────────────────────────

const CAT_LABELS: Record<string, string> = {
  THREAT_ACTOR: "Threat Actor",
  WALLET:       "Wallet",
  MALWARE:      "Malware",
  FORUM:        "Forum",
  C2_SERVER:    "C2 Server",
  CVE:          "CVE",
  PASTE_URL:    "Paste URL",
  ONION_URL:    "Onion URL",
  EMAIL:        "Email",
  PGP_KEY:      "PGP Key",
  OTHER:        "Other",
};

// ─── Freshness indicator ────────────────────────────────────────────────────────

function FreshnessIndicator({ tag, label }: { tag?: string; label?: string }) {
  const dot = tag === "fresh"   ? "🟢"
            : tag === "recent"  ? "🟡"
            : tag === "aged"    ? "🟠"
            : tag === "stale"   ? "🔴"
            : "⚪";
  const text = label ?? (tag ? tag.charAt(0).toUpperCase() + tag.slice(1) : "Unknown");
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
      <span>{dot}</span>
      <span style={{ color: "rgba(255,255,255,0.75)", fontSize: 12 }}>{text}</span>
    </span>
  );
}

// ─── Confidence bar ────────────────────────────────────────────────────────────

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = value >= 0.8 ? "#4ade80" : value >= 0.6 ? "#facc15" : "#f87171";
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
      <span
        style={{
          display: "inline-block",
          width: 80,
          height: 6,
          borderRadius: 3,
          background: "rgba(255,255,255,0.08)",
          position: "relative",
          overflow: "hidden",
        }}
      >
        <span
          style={{
            display: "block",
            height: "100%",
            width: `${pct}%`,
            background: color,
            borderRadius: 3,
            transition: "width 0.4s ease",
          }}
        />
      </span>
      <span style={{ fontFamily: "'JetBrains Mono', 'IBM Plex Mono', monospace", fontSize: 11, color: "rgba(255,255,255,0.7)" }}>
        {value.toFixed(2)}
      </span>
    </span>
  );
}

// ─── Main panel component ──────────────────────────────────────────────────────

export function NodeDetailPanel({ node, graph, searchQuery: _searchQuery, onClose, onIsolateNeighbors }: NodeDetailPanelProps) {
  const [enriched, setEnriched] = useState<EnrichedEntityData | null>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const visible = node !== null;

  // Cluster topology computations
  const clusterHub = useMemo(() => {
    if (!node || !graph) return null;
    try { return findClusterHub(node.id, graph); } catch { return null; }
  }, [node?.id, graph]);

  const clusterMembers = useMemo(() => {
    if (!node || !graph) return [];
    try { return findClusterMembers(node.id, graph); } catch { return []; }
  }, [node?.id, graph]);

  const connectionPath = useMemo(() => {
    if (!node || !graph) return [];
    try { return findPathToHub(node.id, graph); } catch { return []; }
  }, [node?.id, graph]);

  // Reset enriched data when node changes
  useEffect(() => {
    if (!node) { setEnriched(null); setFetchError(null); return; }
    setEnriched(null);
    setFetchError(null);

    // Try to fetch full entity data from API
    const entityId = node.id;
    setLoading(true);
    const apiBase = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
    fetch(`${apiBase}/api/entities/${encodeURIComponent(entityId)}`, {
      credentials: "include",
    })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<EnrichedEntityData>;
      })
      .then((d) => { setEnriched(d); setFetchError(null); })
      .catch((err) => { setFetchError(String(err)); })
      .finally(() => setLoading(false));
  }, [node?.id]);

  const handleCopy = useCallback(() => {
    if (!node) return;
    // Use canonical value from enriched if available, otherwise node id
    const val = enriched?.canonical_value ?? enriched?.value ?? node.id;
    navigator.clipboard.writeText(val).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {/* ok */});
  }, [node, enriched]);

  // Merge attrs: prefer enriched API data, fall back to graph node attrs
  const entityType = enriched?.entity_type ?? node?.raw?.type ?? node?.vaCategory ?? "OTHER";
  const catLabel   = CAT_LABELS[node?.vaCategory ?? "OTHER"] ?? "Other";
  const dotColor   = node?.origColor ?? node?.color ?? "#4a5260";
  const displayVal = enriched?.canonical_value ?? enriched?.value ?? node?.id ?? "";
  const confidence = enriched?.confidence ?? node?.raw?.confidence ?? 0;
  const freshnessTag   = enriched?.freshness_tag   ?? node?.freshness_tag;
  const freshnessLabel = enriched?.freshness_label ?? node?.freshness_label;
  const sourceCount    = enriched?.source_count    ?? node?.source_count;
  const sources        = enriched?.corroborating_sources ?? node?.corroborating_sources ?? [];
  const contextText    = enriched?.context_snippet ?? enriched?.context ?? node?.context_snippet ?? node?.context;
  const firstSeen      = enriched?.first_seen ?? node?.raw?.first_seen;
  const lastSeen       = enriched?.last_seen  ?? node?.raw?.last_seen;

  // Enrichment links
  const isMitre  = entityType === "MITRE_TECHNIQUE";
  const isCve    = entityType === "CVE" || entityType === "CVE_NUMBER";
  const isIp     = entityType === "IP_ADDRESS";
  const shodanUrl = isIp ? `https://www.shodan.io/host/${encodeURIComponent(displayVal)}` : null;
  const mitreUrl  = isMitre ? getMitreUrl(displayVal) : null;
  const cveUrl    = isCve   ? getCveUrl(displayVal) : null;

  const panelStyle: React.CSSProperties = {
    position: "absolute",
    left: 0,
    top: 0,
    bottom: 0,
    width: 320,
    zIndex: 50,
    display: "flex",
    flexDirection: "column",
    background: "rgba(8, 11, 17, 0.97)",
    borderRight: "1px solid rgba(155, 159, 238, 0.18)",
    backdropFilter: "blur(16px)",
    transform: visible ? "translateX(0)" : "translateX(-100%)",
    transition: "transform 0.28s cubic-bezier(0.4, 0, 0.2, 1)",
    overflow: "hidden",
    pointerEvents: visible ? "auto" : "none",
  };

  const sectionStyle: React.CSSProperties = {
    padding: "10px 16px",
    borderBottom: "1px solid rgba(255,255,255,0.06)",
  };

  const sectionTitleStyle: React.CSSProperties = {
    fontFamily: "'JetBrains Mono', 'IBM Plex Mono', monospace",
    fontSize: 9,
    letterSpacing: "0.14em",
    textTransform: "uppercase",
    color: "rgba(255,255,255,0.35)",
    marginBottom: 8,
  };

  const rowStyle: React.CSSProperties = {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 6,
  };

  const labelStyle: React.CSSProperties = {
    fontFamily: "'Inter', sans-serif",
    fontSize: 11,
    color: "rgba(255,255,255,0.45)",
  };

  const valueStyle: React.CSSProperties = {
    fontFamily: "'Inter', sans-serif",
    fontSize: 12,
    color: "rgba(255,255,255,0.82)",
  };

  return (
    <div style={panelStyle} aria-hidden={!visible}>
      {/* Header — Back button */}
      <div
        style={{
          padding: "12px 16px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          borderBottom: "1px solid rgba(255,255,255,0.07)",
          flexShrink: 0,
        }}
      >
        <button
          onClick={onClose}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            background: "transparent",
            border: "none",
            cursor: "pointer",
            fontFamily: "'IBM Plex Mono', monospace",
            fontSize: 10,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: "rgba(255,255,255,0.45)",
            padding: "2px 0",
            transition: "color 0.15s",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.color = "rgba(255,255,255,0.85)")}
          onMouseLeave={(e) => (e.currentTarget.style.color = "rgba(255,255,255,0.45)")}
        >
          ← Back to list
        </button>
        {loading && (
          <div
            style={{
              width: 12,
              height: 12,
              borderRadius: "50%",
              border: "2px solid rgba(88,166,255,0.3)",
              borderTopColor: "#9B9FEE",
              animation: "spin 0.8s linear infinite",
            }}
          />
        )}
      </div>

      {/* Scrollable content */}
      <div style={{ flex: 1, overflowY: "auto", overflowX: "hidden" }}>

        {/* Identity section */}
        <div style={{ padding: "16px 16px 12px" }}>
          {/* Type badge */}
          <div style={{ marginBottom: 10 }}>
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                padding: "2px 8px",
                borderRadius: 4,
                background: `${dotColor}20`,
                border: `1px solid ${dotColor}55`,
              }}
            >
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: dotColor, display: "inline-block" }} />
              <span
                style={{
                  fontFamily: "'JetBrains Mono', 'IBM Plex Mono', monospace",
                  fontSize: 9,
                  letterSpacing: "0.12em",
                  textTransform: "uppercase",
                  color: dotColor,
                }}
              >
                {catLabel}
              </span>
            </span>
          </div>

          {/* Value (full canonical) */}
          <div
            style={{
              fontFamily: "'JetBrains Mono', 'IBM Plex Mono', monospace",
              fontSize: 12,
              color: "rgba(255,255,255,0.9)",
              wordBreak: "break-all",
              lineHeight: 1.5,
              marginBottom: 10,
              padding: "8px 10px",
              background: "rgba(255,255,255,0.04)",
              borderRadius: 5,
              border: "1px solid rgba(255,255,255,0.07)",
              maxHeight: 90,
              overflowY: "auto",
            }}
          >
            {displayVal || node?.id}
          </div>

          {/* Copy button */}
          <button
            onClick={handleCopy}
            style={{
              width: "100%",
              padding: "5px 0",
              borderRadius: 4,
              border: "1px solid rgba(255,255,255,0.12)",
              background: copied ? "rgba(74,222,128,0.12)" : "rgba(255,255,255,0.04)",
              cursor: "pointer",
              fontFamily: "'IBM Plex Mono', monospace",
              fontSize: 10,
              letterSpacing: "0.08em",
              color: copied ? "#4ade80" : "rgba(255,255,255,0.55)",
              transition: "all 0.2s",
            }}
          >
            {copied ? "✓ Copied" : "Copy value"}
          </button>
        </div>

        {/* Intelligence section */}
        <div style={sectionStyle}>
          <div style={sectionTitleStyle}>Intelligence</div>

          {confidence > 0 && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Confidence</span>
              <ConfidenceBar value={confidence} />
            </div>
          )}

          {(freshnessTag || freshnessLabel) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Freshness</span>
              <FreshnessIndicator tag={freshnessTag} label={freshnessLabel} />
            </div>
          )}

          {(sourceCount !== undefined || sources.length > 0) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Sources</span>
              <span style={valueStyle}>
                {sourceCount ?? sources.length}
                {sources.length > 0 && (
                  <span style={{ color: "rgba(255,255,255,0.4)", marginLeft: 6 }}>
                    ({sources.slice(0, 3).join(" · ")})
                  </span>
                )}
              </span>
            </div>
          )}

          {getPasteSources(sources).length > 0 && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Paste site</span>
              <span
                title={
                  PASTE_SOURCE_TOOLTIPS[getPasteSources(sources)[0]] ??
                  PASTE_SOURCE_TOOLTIPS.paste_site
                }
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(217,119,6,0.12)",
                  border: "1px solid rgba(217,119,6,0.4)",
                  color: "#fbbf24",
                  fontSize: 11,
                }}
              >
                <span aria-hidden="true">📋</span>
                {getPasteSources(sources).join(" · ")}
              </span>
            </div>
          )}

          {getGithubSources(sources).length > 0 && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>GitHub</span>
              <span
                title={
                  GITHUB_SOURCE_TOOLTIPS[getGithubSources(sources)[0]] ??
                  GITHUB_SOURCE_TOOLTIPS.GitHub
                }
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(99,102,241,0.12)",
                  border: "1px solid rgba(99,102,241,0.4)",
                  color: "#a5b4fc",
                  fontSize: 11,
                }}
              >
                <span aria-hidden="true">🐙</span>
                GitHub
              </span>
            </div>
          )}

          {getGitlabSources(sources).length > 0 && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>GitLab</span>
              <span
                title={
                  GITLAB_SOURCE_TOOLTIPS[getGitlabSources(sources)[0]] ??
                  GITLAB_SOURCE_TOOLTIPS.GitLab
                }
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(234,88,12,0.12)",
                  border: "1px solid rgba(234,88,12,0.4)",
                  color: "#fb923c",
                  fontSize: 11,
                }}
              >
                <span aria-hidden="true">🦊</span>
                GitLab
              </span>
            </div>
          )}

          {getRssFeedSources(sources).length > 0 && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>News</span>
              <span
                title={
                  RSS_SOURCE_TOOLTIPS[getRssFeedSources(sources)[0]] ??
                  RSS_SOURCE_TOOLTIPS.rss_feed
                }
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(20,184,166,0.12)",
                  border: "1px solid rgba(20,184,166,0.4)",
                  color: "#5eead4",
                  fontSize: 11,
                  maxWidth: 170,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                <span aria-hidden="true">📰</span>
                {getRssFeedSources(sources)
                  .find((s) => s !== "rss_feed") ?? "News"}
              </span>
            </div>
          )}

          {isConfirmedC2(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Threat</span>
              <span
                title={
                  getC2Family(sources)
                    ? `Confirmed C2 · ${getC2Family(sources)}`
                    : "Confirmed command-and-control server (Feodo Tracker / C2IntelFeeds)"
                }
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(185,28,28,0.18)",
                  border: "1px solid rgba(239,68,68,0.5)",
                  color: "#fca5a5",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                C2{getC2Family(sources) ? ` · ${getC2Family(sources)}` : ""}
              </span>
            </div>
          )}

          {isAbuseConfirmed(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Abuse</span>
              <span
                title="Community-reported IP abuse (AbuseIPDB)"
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(194,65,12,0.18)",
                  border: "1px solid rgba(249,115,22,0.5)",
                  color: "#fdba74",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                Reported
              </span>
            </div>
          )}

          {isWaybackArchived(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Archive</span>
              <span
                title="Historical snapshots found in Wayback Machine"
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(126,34,206,0.18)",
                  border: "1px solid rgba(168,85,247,0.5)",
                  color: "#d8b4fe",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                Archived
              </span>
            </div>
          )}

          {isUrlscanMalicious(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>URLScan</span>
              <span
                title="Flagged malicious by URLScan.io"
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(185,28,28,0.18)",
                  border: "1px solid rgba(239,68,68,0.5)",
                  color: "#fca5a5",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                Malicious
              </span>
            </div>
          )}

          {hasCTHistory(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>CT Logs</span>
              <span
                title={`${getSubdomainCount(sources)} subdomains found in certificate transparency logs`}
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(29,78,216,0.18)",
                  border: "1px solid rgba(96,165,250,0.5)",
                  color: "#93c5fd",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                {getSubdomainCount(sources) > 0
                  ? `${getSubdomainCount(sources)} subdomains`
                  : "CT history"}
              </span>
            </div>
          )}

          {isLikelyTakenDown(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Status</span>
              <span
                title="Domain appears to have been taken down"
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(180,83,9,0.18)",
                  border: "1px solid rgba(251,191,36,0.5)",
                  color: "#fde68a",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                Taken Down
              </span>
            </div>
          )}

          {isHashMalicious(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Verdict</span>
              <span
                title={
                  getMalwareFamilyFromSources(sources)
                    ? `Confirmed malware · ${getMalwareFamilyFromSources(sources)}`
                    : "Confirmed malicious by sandbox analysis"
                }
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(185,28,28,0.18)",
                  border: "1px solid rgba(239,68,68,0.5)",
                  color: "#fca5a5",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                Malware{getMalwareFamilyFromSources(sources) ? ` · ${getMalwareFamilyFromSources(sources)}` : ""}
              </span>
            </div>
          )}

          {isHashSuspicious(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Verdict</span>
              <span
                title="Flagged suspicious — not confirmed malicious"
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(194,65,12,0.18)",
                  border: "1px solid rgba(249,115,22,0.5)",
                  color: "#fdba74",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                Suspicious
              </span>
            </div>
          )}

          {isHashClean(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Verdict</span>
              <span
                title="No detections across checked sources"
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(75,85,99,0.18)",
                  border: "1px solid rgba(156,163,175,0.4)",
                  color: "#d1d5db",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                Clean
              </span>
            </div>
          )}

          {(() => {
            const av = getAvDetectionData(sources);
            if (!av) return null;
            return (
              <div style={{ ...rowStyle, marginBottom: 8 }}>
                <span style={labelStyle}>AV Detection</span>
                <span
                  title={`Detected by ${av.n} of ${av.total} AV vendors`}
                  style={{
                    ...valueStyle,
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                    padding: "2px 8px",
                    borderRadius: 4,
                    background: "rgba(29,78,216,0.18)",
                    border: "1px solid rgba(96,165,250,0.5)",
                    color: "#93c5fd",
                    fontSize: 11,
                    fontWeight: 700,
                  }}
                >
                  {av.n}/{av.total} AV
                </span>
              </div>
            );
          })()}

          {isHibpBreached(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Breach</span>
              <span
                title={(() => {
                  const n = getHibpBreachCount(sources);
                  return n > 0
                    ? `Found in ${n} known data breach${n === 1 ? "" : "es"} (HaveIBeenPwned)`
                    : "Found in known data breaches (HaveIBeenPwned)";
                })()}
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(185,28,28,0.18)",
                  border: "1px solid rgba(239,68,68,0.5)",
                  color: "#fca5a5",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                Breached{getHibpBreachCount(sources) > 0 ? ` · ${getHibpBreachCount(sources)}` : ""}
              </span>
            </div>
          )}

          {isHibpPasswordExposed(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Exposure</span>
              <span
                title="Password hash or plaintext exposed in breach data"
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(127,7,7,0.25)",
                  border: "1px solid rgba(239,68,68,0.6)",
                  color: "#fca5a5",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                Password Exposed
              </span>
            </div>
          )}

          {isDisposableEmail(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Email</span>
              <span
                title="Temporary/disposable email address"
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(75,85,99,0.18)",
                  border: "1px solid rgba(156,163,175,0.4)",
                  color: "#d1d5db",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                Disposable
              </span>
            </div>
          )}

          {isEmailrepMalicious(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>EmailRep</span>
              <span
                title="Associated with malicious activity per EmailRep"
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(194,65,12,0.18)",
                  border: "1px solid rgba(249,115,22,0.5)",
                  color: "#fdba74",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                Malicious
              </span>
            </div>
          )}

          {isCredentialsLeaked(sources) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Stealer</span>
              <span
                title="Credentials found in stealer logs"
                style={{
                  ...valueStyle,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "2px 8px",
                  borderRadius: 4,
                  background: "rgba(126,34,206,0.18)",
                  border: "1px solid rgba(168,85,247,0.5)",
                  color: "#d8b4fe",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                Leaked Creds
              </span>
            </div>
          )}

          {firstSeen && (
            <div style={{ ...rowStyle, marginBottom: 6 }}>
              <span style={labelStyle}>First seen</span>
              <span style={valueStyle}>{formatRelativeTime(firstSeen)}</span>
            </div>
          )}

          {lastSeen && (
            <div style={{ ...rowStyle, marginBottom: 0 }}>
              <span style={labelStyle}>Last seen</span>
              <span style={valueStyle}>{formatRelativeTime(lastSeen)}</span>
            </div>
          )}
        </div>

        {/* Context section */}
        {contextText && (
          <div style={sectionStyle}>
            <div style={sectionTitleStyle}>Context</div>
            <div
              style={{
                fontFamily: "'Inter', sans-serif",
                fontSize: 11,
                color: "rgba(255,255,255,0.6)",
                lineHeight: 1.6,
                fontStyle: "italic",
                padding: "8px 10px",
                background: "rgba(255,255,255,0.03)",
                borderRadius: 4,
                border: "1px solid rgba(255,255,255,0.06)",
                maxHeight: 100,
                overflowY: "auto",
              }}
            >
              "{contextText}"
            </div>
          </div>
        )}

        {/* Connections section */}
        {node && (
          <div style={sectionStyle}>
            <div style={sectionTitleStyle}>Connections</div>
            <div style={{ ...rowStyle, flexDirection: "column", alignItems: "flex-start", gap: 8 }}>
              {node.degree !== undefined && node.degree > 0 && (
                <span style={{ ...valueStyle, fontSize: 11 }}>
                  Connected to <strong style={{ color: "rgba(255,255,255,0.9)" }}>{node.degree}</strong> other{" "}
                  {node.degree === 1 ? "entity" : "entities"}
                </span>
              )}
              <button
                onClick={() => { onIsolateNeighbors(node.id); onClose(); }}
                style={{
                  padding: "5px 10px",
                  borderRadius: 4,
                  border: "1px solid rgba(88,166,255,0.3)",
                  background: "rgba(88,166,255,0.07)",
                  cursor: "pointer",
                  fontFamily: "'IBM Plex Mono', monospace",
                  fontSize: 10,
                  letterSpacing: "0.07em",
                  color: "rgba(88,166,255,0.9)",
                  transition: "all 0.15s",
                  whiteSpace: "nowrap",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "rgba(88,166,255,0.14)";
                  e.currentTarget.style.borderColor = "rgba(88,166,255,0.6)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "rgba(88,166,255,0.07)";
                  e.currentTarget.style.borderColor = "rgba(88,166,255,0.3)";
                }}
              >
                View neighbors only
              </button>
            </div>
          </div>
        )}

        {/* Cluster context section */}
        {node && graph && (clusterHub || clusterMembers.length > 0) && (
          <div className="panel-section">
            <div className="section-title">Cluster Context</div>
            {clusterHub && (
              <div className="context-row">
                <span className="context-label">Main topic</span>
                <span className="context-value mono">{clusterHub.label}</span>
              </div>
            )}
            {clusterMembers.length > 0 && (
              <div className="context-row">
                <span className="context-label">Related</span>
                <span className="context-value" style={{ fontSize: 11 }}>{clusterMembers.join(" · ")}</span>
              </div>
            )}
            <div className="context-row">
              <span className="context-label">Connections</span>
              <span className="context-value">{graph.degree(node.id)} direct links</span>
            </div>
          </div>
        )}

        {/* Connection path section */}
        {node && connectionPath.length > 1 && (
          <div className="panel-section">
            <div className="section-title">Connection Path</div>
            <div className="path-display">
              {connectionPath.map((nid, i) => {
                const lbl = graph
                  ? ((graph.getNodeAttribute(nid, "label") as string) || nid)
                  : nid;
                const isFirst = i === 0;
                const isLast  = i === connectionPath.length - 1;
                const truncated = lbl.length > 20 ? lbl.slice(0, 20) + "…" : lbl;
                return (
                  <div key={nid} className="path-step">
                    <span className={`path-node${isFirst ? " path-current" : ""}${isLast ? " path-hub" : ""}`}>
                      {truncated}
                    </span>
                    {!isLast && <span className="path-arrow">→</span>}
                  </div>
                );
              })}
            </div>
            <div className="path-note">Shortest path to investigation hub</div>
          </div>
        )}

        {/* Enrichment section */}
        {(isMitre || isCve || isIp) && (
          <div style={sectionStyle}>
            <div style={sectionTitleStyle}>Enrichment</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {isMitre && mitreUrl && (
                <a
                  href={mitreUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                    fontFamily: "'IBM Plex Mono', monospace",
                    fontSize: 11,
                    color: "#f0a050",
                    textDecoration: "none",
                    padding: "4px 8px",
                    borderRadius: 4,
                    border: "1px solid rgba(240,160,80,0.25)",
                    background: "rgba(240,160,80,0.06)",
                    transition: "all 0.15s",
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(240,160,80,0.12)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(240,160,80,0.06)"; }}
                >
                  → View on ATT&CK
                </a>
              )}
              {isCve && cveUrl && (
                <a
                  href={cveUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                    fontFamily: "'IBM Plex Mono', monospace",
                    fontSize: 11,
                    color: "#e5c07b",
                    textDecoration: "none",
                    padding: "4px 8px",
                    borderRadius: 4,
                    border: "1px solid rgba(229,192,123,0.25)",
                    background: "rgba(229,192,123,0.06)",
                    transition: "all 0.15s",
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(229,192,123,0.12)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(229,192,123,0.06)"; }}
                >
                  → View on NVD
                </a>
              )}
              {isIp && shodanUrl && (
                <a
                  href={shodanUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                    fontFamily: "'IBM Plex Mono', monospace",
                    fontSize: 11,
                    color: "#56b6c2",
                    textDecoration: "none",
                    padding: "4px 8px",
                    borderRadius: 4,
                    border: "1px solid rgba(86,182,194,0.25)",
                    background: "rgba(86,182,194,0.06)",
                    transition: "all 0.15s",
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(86,182,194,0.12)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(86,182,194,0.06)"; }}
                >
                  → View on Shodan
                </a>
              )}
            </div>
          </div>
        )}

        {/* API error notice */}
        {fetchError && (
          <div style={{ padding: "8px 16px" }}>
            <span
              style={{
                fontFamily: "'IBM Plex Mono', monospace",
                fontSize: 9,
                color: "rgba(248,113,113,0.6)",
              }}
            >
              Note: Could not load full entity data
            </span>
          </div>
        )}

        {/* Bottom padding */}
        <div style={{ height: 24 }} />
      </div>

      {/* Spin keyframe injected via style tag — avoids CSS file dependency */}
      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
