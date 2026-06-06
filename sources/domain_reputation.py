"""
sources/domain_reputation.py — Domain reputation enrichment.

Enriches extracted DOMAIN entities with infrastructure profiles from three sources:
  - crt.sh (Certificate Transparency): subdomain enumeration — free, no auth
  - URLScan.io: live scan data, malicious indicators, communicating IPs
  - Wayback Machine (Internet Archive): historical snapshots for taken-down domains

All three sources queried concurrently per domain. Results are cached.
New subdomain/IP entities are returned in the result for pipeline reporting.
Existing DOMAIN entities get confidence and tag updates written to the DB.

Public interface
----------------
async query_crt_sh(domain)                         → list[dict]
async query_urlscan(domain)                        → dict
async query_wayback(domain)                        → dict
async check_domain_reputation(domain, confidence)  → dict
async enrich_domain_entities(extraction_results, investigation_id) → (results, stats)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

MAX_DOMAINS = 30
MAX_SUBDOMAINS_PER_DOMAIN = 20
MAX_IPS_PER_DOMAIN = 5

CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5"
URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
WAYBACK_CDX_URL = (
    "http://web.archive.org/cdx/search/cdx"
    "?url={domain}&output=json&limit=5&fl=timestamp,statuscode,mimetype"
)

# In-memory per-domain caches (module-level singletons, keyed by domain)
_crt_cache: dict[str, dict] = {}
_urlscan_cache: dict[str, dict] = {}
_wayback_cache: dict[str, dict] = {}

CRT_CACHE_TTL = 86400.0      # 24 h
URLSCAN_CACHE_TTL = 21600.0  # 6 h
WAYBACK_CACHE_TTL = 86400.0  # 24 h

_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
)

_PRIVATE_SUFFIXES = (".local", ".internal", ".test", ".example", ".invalid", ".localhost")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_onion(domain: str) -> bool:
    return domain.lower().strip().endswith(".onion")


def _is_private_domain(domain: str) -> bool:
    d = domain.lower().strip()
    if d == "localhost":
        return True
    return any(d.endswith(s) for s in _PRIVATE_SUFFIXES)


def _is_valid_domain(value: str) -> bool:
    if not value or len(value) < 4 or "." not in value:
        return False
    if value.endswith(".onion"):
        return False
    return bool(_DOMAIN_RE.match(value))


def _parse_wayback_timestamp(ts: str) -> str | None:
    """Convert 14-char Wayback timestamp (YYYYMMDDHHmmss) to ISO date (YYYY-MM-DD)."""
    try:
        ts = ts.strip()
        if len(ts) >= 8:
            return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        return None
    except Exception:
        return None


def _is_established_domain(first_seen: str | None) -> bool:
    """True if first Wayback snapshot is older than 5 years."""
    if not first_seen:
        return False
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(first_seen)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days > 1825
    except Exception:
        return False


def _is_newly_observed(first_seen: str | None) -> bool:
    """True if first Wayback snapshot is younger than 90 days."""
    if not first_seen:
        return False
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(first_seen)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days < 90
    except Exception:
        return False


# ---------------------------------------------------------------------------
# crt.sh — Certificate Transparency
# ---------------------------------------------------------------------------

async def query_crt_sh(domain: str) -> list[dict]:
    """
    Query crt.sh for subdomains found in certificate transparency logs.

    Returns list of dicts with keys: name, first_seen, last_seen, issuer.
    Wildcards (*.example.com) and the parent domain itself are filtered out.
    Results capped at MAX_SUBDOMAINS_PER_DOMAIN. Cached for 24 h.
    """
    cached = _crt_cache.get(domain)
    if cached and (time.time() - cached["loaded_at"]) < CRT_CACHE_TTL:
        return cached["subdomains"]

    url = CRT_SH_URL.format(domain=domain)
    try:
        timeout = aiohttp.ClientTimeout(connect=10, sock_read=120)
        headers = {"User-Agent": "Open_Intel-OSINT/1.1 (security research)"}
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    logger.debug("domain_reputation: crt.sh %s → HTTP %s", domain, resp.status)
                    return []
                data = await resp.json(content_type=None)
    except Exception as exc:
        logger.debug("domain_reputation: crt.sh failed for %s: %s", domain, exc)
        return []

    seen: set[str] = set()
    results: list[dict] = []
    for entry in data or []:
        raw = (entry.get("name_value") or "").strip().lower()
        # name_value may contain newline-separated entries
        for name in raw.split("\n"):
            name = name.strip()
            if not name:
                continue
            if name.startswith("*"):
                continue
            if name == domain:
                continue
            if not name.endswith(f".{domain}"):
                continue
            if not _is_valid_domain(name):
                continue
            if name in seen:
                continue
            seen.add(name)
            results.append({
                "name": name,
                "first_seen": entry.get("not_before", ""),
                "last_seen": entry.get("not_after", ""),
                "issuer": entry.get("issuer_name", ""),
            })
            if len(results) >= MAX_SUBDOMAINS_PER_DOMAIN:
                break
        if len(results) >= MAX_SUBDOMAINS_PER_DOMAIN:
            break

    _crt_cache[domain] = {"subdomains": results, "loaded_at": time.time()}
    logger.debug("domain_reputation: crt.sh %s → %d subdomains", domain, len(results))
    return results


# ---------------------------------------------------------------------------
# URLScan.io
# ---------------------------------------------------------------------------

async def query_urlscan(domain: str) -> dict[str, Any]:
    """
    Query URLScan.io search API for the most recent scans of a domain.

    Returns dict: malicious, tags, categories, ips, technologies, screenshot_url.
    Uses URLSCAN_API_KEY env var if present (higher rate limits).
    Cached for 6 h.
    """
    cached = _urlscan_cache.get(domain)
    if cached and (time.time() - cached["loaded_at"]) < URLSCAN_CACHE_TTL:
        return cached["result"]

    empty: dict[str, Any] = {
        "malicious": False,
        "tags": [],
        "categories": [],
        "ips": [],
        "technologies": [],
        "screenshot_url": None,
    }

    api_key = (os.getenv("URLSCAN_API_KEY") or "").strip()
    headers: dict[str, str] = {"User-Agent": "Open_Intel-OSINT/1.1 (security research)"}
    if api_key:
        headers["API-Key"] = api_key

    url = URLSCAN_SEARCH_URL.format(domain=domain)
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    logger.debug("domain_reputation: URLScan %s → HTTP %s", domain, resp.status)
                    _urlscan_cache[domain] = {"result": empty, "loaded_at": time.time()}
                    return empty
                data = await resp.json()
    except Exception as exc:
        logger.debug("domain_reputation: URLScan failed for %s: %s", domain, exc)
        return empty

    scan_list = data.get("results") or []
    if not scan_list:
        _urlscan_cache[domain] = {"result": empty, "loaded_at": time.time()}
        return empty

    malicious = False
    all_tags: list[str] = []
    all_categories: list[str] = []
    seen_ips: list[str] = []
    all_tech: list[str] = []
    screenshot_url: str | None = None

    for scan in scan_list[:5]:
        verdicts = scan.get("verdicts", {})
        overall = verdicts.get("overall", {})
        if overall.get("malicious"):
            malicious = True
        all_tags.extend(overall.get("tags") or [])
        all_categories.extend(overall.get("categories") or [])

        for ip in (scan.get("lists") or {}).get("ips") or []:
            if isinstance(ip, str) and ip not in seen_ips:
                seen_ips.append(ip)
            if len(seen_ips) >= MAX_IPS_PER_DOMAIN:
                break

        wappa = (scan.get("meta") or {}).get("processors", {}).get("wappa", {})
        for tech in wappa.get("data") or []:
            name = tech.get("app") or tech.get("name") or ""
            if name and name not in all_tech:
                all_tech.append(name)

        if screenshot_url is None:
            screenshot_url = (scan.get("task") or {}).get("screenshotURL")

    result: dict[str, Any] = {
        "malicious": malicious,
        "tags": list(dict.fromkeys(all_tags))[:10],
        "categories": list(dict.fromkeys(all_categories))[:5],
        "ips": seen_ips[:MAX_IPS_PER_DOMAIN],
        "technologies": all_tech[:10],
        "screenshot_url": screenshot_url,
    }

    _urlscan_cache[domain] = {"result": result, "loaded_at": time.time()}
    logger.debug(
        "domain_reputation: URLScan %s → malicious=%s, %d IPs",
        domain, malicious, len(result["ips"]),
    )
    return result


async def _submit_urlscan(domain: str, api_key: str) -> None:
    """Submit a new public scan to URLScan.io — only when URLSCAN_SUBMIT=true."""
    if (os.getenv("URLSCAN_SUBMIT") or "false").lower().strip() != "true":
        return
    if not api_key:
        return
    try:
        payload = {"url": f"https://{domain}", "visibility": "public"}
        headers = {"API-Key": api_key, "Content-Type": "application/json"}
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(URLSCAN_SUBMIT_URL, json=payload, headers=headers) as resp:
                if resp.status in (200, 201):
                    logger.debug("domain_reputation: URLScan scan submitted for %s", domain)
                else:
                    logger.debug(
                        "domain_reputation: URLScan submit %s → HTTP %s", domain, resp.status
                    )
    except Exception as exc:
        logger.debug("domain_reputation: URLScan submit failed for %s: %s", domain, exc)


# ---------------------------------------------------------------------------
# Wayback Machine
# ---------------------------------------------------------------------------

async def query_wayback(domain: str) -> dict[str, Any]:
    """
    Query the Wayback Machine CDX API for historical snapshots of a domain.

    Returns dict: exists, first_seen, last_seen, snapshot_url, likely_taken_down.
    A domain shows "likely_taken_down" when earlier snapshots returned 2xx
    and the most recent snapshot returned a 4xx status.
    Cached for 24 h.
    """
    cached = _wayback_cache.get(domain)
    if cached and (time.time() - cached["loaded_at"]) < WAYBACK_CACHE_TTL:
        return cached["result"]

    empty: dict[str, Any] = {
        "exists": False,
        "first_seen": None,
        "last_seen": None,
        "snapshot_url": None,
        "likely_taken_down": False,
    }

    url = WAYBACK_CDX_URL.format(domain=domain)
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        headers = {"User-Agent": "Open_Intel-OSINT/1.1 (security research)"}
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    logger.debug("domain_reputation: Wayback %s → HTTP %s", domain, resp.status)
                    _wayback_cache[domain] = {"result": empty, "loaded_at": time.time()}
                    return empty
                rows = await resp.json(content_type=None)
    except Exception as exc:
        logger.debug("domain_reputation: Wayback failed for %s: %s", domain, exc)
        return empty

    # CDX returns list-of-lists; first row is the header
    if not rows or len(rows) <= 1:
        _wayback_cache[domain] = {"result": empty, "loaded_at": time.time()}
        return empty

    data_rows = rows[1:]
    timestamps: list[str] = []
    status_codes: list[str] = []
    for row in data_rows:
        if isinstance(row, list) and len(row) >= 2:
            timestamps.append(str(row[0]))
            status_codes.append(str(row[1]))

    if not timestamps:
        _wayback_cache[domain] = {"result": empty, "loaded_at": time.time()}
        return empty

    timestamps_sorted = sorted(timestamps)
    first_seen = _parse_wayback_timestamp(timestamps_sorted[0])
    last_seen = _parse_wayback_timestamp(timestamps_sorted[-1])
    snapshot_url = f"https://web.archive.org/web/{timestamps_sorted[-1]}/{domain}"

    has_200 = any(sc.startswith("2") for sc in status_codes)
    last_status = status_codes[-1] if status_codes else ""
    likely_taken_down = has_200 and last_status.startswith("4")

    result: dict[str, Any] = {
        "exists": True,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "snapshot_url": snapshot_url,
        "likely_taken_down": likely_taken_down,
    }

    _wayback_cache[domain] = {"result": result, "loaded_at": time.time()}
    logger.debug(
        "domain_reputation: Wayback %s → archived, taken_down=%s", domain, likely_taken_down
    )
    return result


# ---------------------------------------------------------------------------
# Core enrichment check
# ---------------------------------------------------------------------------

async def check_domain_reputation(
    domain: str,
    base_confidence: float = 1.0,
) -> dict[str, Any]:
    """
    Run all three enrichment sources for a single domain concurrently.

    Returns:
        domain, crt_subdomains, urlscan_malicious, urlscan_tags, urlscan_ips,
        wayback_exists, wayback_first_seen, wayback_last_seen, likely_taken_down,
        new_entities, tags, confidence_delta
    """
    result: dict[str, Any] = {
        "domain": domain,
        "crt_subdomains": [],
        "urlscan_malicious": False,
        "urlscan_tags": [],
        "urlscan_ips": [],
        "wayback_exists": False,
        "wayback_first_seen": None,
        "wayback_last_seen": None,
        "likely_taken_down": False,
        "new_entities": [],
        "tags": [],
        "confidence_delta": 0.0,
    }

    if _is_onion(domain) or _is_private_domain(domain):
        return result

    crt_data, urlscan_data, wayback_data = await asyncio.gather(
        query_crt_sh(domain),
        query_urlscan(domain),
        query_wayback(domain),
        return_exceptions=True,
    )

    # --- crt.sh ---
    if isinstance(crt_data, list) and crt_data:
        result["crt_subdomains"] = crt_data
        result["tags"].append("has_ct_history")
        n = len(crt_data)
        result["tags"].append(f"subdomain_count_{n}")
        for sub in crt_data:
            name = sub.get("name", "")
            if name:
                result["new_entities"].append({
                    "entity_type": "DOMAIN",
                    "value": name,
                    "canonical_value": name,
                    "confidence": 0.70,
                    "source": "crt_sh",
                    "extraction_method": "domain_enrichment",
                    "context_snippet": f"Subdomain of {domain} (certificate transparency logs)",
                })
    elif isinstance(crt_data, Exception):
        logger.debug("domain_reputation: crt.sh error for %s: %s", domain, crt_data)

    # --- URLScan.io ---
    if isinstance(urlscan_data, dict):
        result["urlscan_malicious"] = urlscan_data.get("malicious", False)
        result["urlscan_tags"] = urlscan_data.get("tags", [])
        result["urlscan_ips"] = urlscan_data.get("ips", [])

        if urlscan_data.get("malicious"):
            result["tags"].append("urlscan_malicious")
            result["confidence_delta"] += 0.10

        for ip in urlscan_data.get("ips", [])[:MAX_IPS_PER_DOMAIN]:
            result["new_entities"].append({
                "entity_type": "IP_ADDRESS",
                "value": ip,
                "canonical_value": ip,
                "confidence": 0.72,
                "source": "urlscan",
                "extraction_method": "domain_enrichment",
                "context_snippet": f"IP communicating with {domain} (URLScan.io)",
            })

        for tech in urlscan_data.get("technologies", []):
            slug = re.sub(r"[^a-z0-9]+", "_", tech.lower())[:40]
            result["tags"].append(f"tech_{slug}")
    elif isinstance(urlscan_data, Exception):
        logger.debug("domain_reputation: URLScan error for %s: %s", domain, urlscan_data)

    # --- Wayback Machine ---
    if isinstance(wayback_data, dict):
        result["wayback_exists"] = wayback_data.get("exists", False)
        result["wayback_first_seen"] = wayback_data.get("first_seen")
        result["wayback_last_seen"] = wayback_data.get("last_seen")
        result["likely_taken_down"] = wayback_data.get("likely_taken_down", False)

        if wayback_data.get("exists"):
            result["tags"].append("wayback_archived")
            first_seen = wayback_data.get("first_seen")
            if wayback_data.get("likely_taken_down"):
                result["tags"].append("likely_taken_down")
            if _is_established_domain(first_seen):
                result["tags"].append("established_domain")
            elif _is_newly_observed(first_seen):
                result["tags"].append("newly_observed_domain")
    elif isinstance(wayback_data, Exception):
        logger.debug("domain_reputation: Wayback error for %s: %s", domain, wayback_data)

    return result


# ---------------------------------------------------------------------------
# DB helpers (sync — called via asyncio.to_thread)
# ---------------------------------------------------------------------------

def _update_domain_entities_in_db(
    updates: list[tuple[str, float, list[str]]],
) -> None:
    """Update confidence and corroborating_sources for enriched DOMAIN entities."""
    if not os.getenv("DATABASE_URL") or not updates:
        return
    try:
        from db.session import get_session
        from db.models import Entity

        with get_session() as session:
            for domain_val, confidence, tags in updates:
                db_entity = session.query(Entity).filter(
                    Entity.entity_type == "DOMAIN",
                    Entity.value == domain_val,
                ).first()
                if db_entity is None:
                    continue
                if confidence > (db_entity.confidence or 0.0):
                    db_entity.confidence = confidence
                if tags:
                    existing: list = json.loads(db_entity.corroborating_sources or "[]")
                    for tag in tags:
                        if tag not in existing:
                            existing.append(tag)
                    db_entity.corroborating_sources = json.dumps(existing)
            session.commit()
    except Exception as exc:
        logger.warning("domain_reputation: DB update failed: %s", exc)


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------

async def enrich_domain_entities(
    extraction_results: list,
    investigation_id: Any,
) -> tuple[list, dict]:
    """
    Post-extraction domain reputation enrichment step.

    Collects DOMAIN entities from *extraction_results*, skipping ONION_URL and
    private/internal domains. Queries crt.sh, URLScan.io, and Wayback Machine
    concurrently per domain (capped at MAX_DOMAINS).

    Updates confidence and tags for existing DOMAIN entities in the DB.
    New entities (subdomains, communicating IPs) are returned in stats for logging.

    Returns (extraction_results, stats_dict).
    """
    seen: dict[str, float] = {}
    for exr in extraction_results:
        for entity in getattr(exr, "entities", []):
            if getattr(entity, "entity_type", "") != "DOMAIN":
                continue
            domain = entity.value
            if _is_onion(domain) or _is_private_domain(domain):
                continue
            if domain not in seen:
                seen[domain] = getattr(entity, "confidence", 1.0)

    unique_domains = list(seen.keys())
    if not unique_domains:
        return extraction_results, {"domain_reputation": "ok_0_domains"}

    if len(unique_domains) > MAX_DOMAINS:
        logger.info(
            "domain_reputation: capping to %d of %d unique domains",
            MAX_DOMAINS, len(unique_domains),
        )
        unique_domains = unique_domains[:MAX_DOMAINS]

    logger.info("domain_reputation: enriching %d unique domain(s)", len(unique_domains))

    rep_list = await asyncio.gather(
        *[check_domain_reputation(d, base_confidence=seen[d]) for d in unique_domains],
        return_exceptions=True,
    )

    db_updates: list[tuple[str, float, list[str]]] = []
    all_new_entities: list[dict] = []
    stats = {
        "domains_checked": len(unique_domains),
        "ct_records": 0,
        "urlscan_malicious": 0,
        "wayback_archived": 0,
        "new_entities_discovered": 0,
    }

    for domain, rep in zip(unique_domains, rep_list):
        if isinstance(rep, Exception):
            logger.debug("domain_reputation: check raised for %s: %s", domain, rep)
            continue

        base_conf = seen[domain]
        new_conf = min(base_conf + rep["confidence_delta"], 1.0)
        tags = rep.get("tags", [])

        stats["ct_records"] += len(rep.get("crt_subdomains", []))
        if rep.get("urlscan_malicious"):
            stats["urlscan_malicious"] += 1
        if rep.get("wayback_exists"):
            stats["wayback_archived"] += 1

        new_entities = rep.get("new_entities", [])
        all_new_entities.extend(new_entities)
        stats["new_entities_discovered"] += len(new_entities)

        if tags or rep["confidence_delta"] > 0:
            db_updates.append((domain, new_conf, tags))

    if db_updates:
        await asyncio.to_thread(_update_domain_entities_in_db, db_updates)

    checked = stats["domains_checked"]
    status = (
        f"ok_{checked}_domains"
        f"_{stats['ct_records']}_ct"
        f"_{stats['urlscan_malicious']}_malicious"
        f"_{stats['wayback_archived']}_archived"
    )

    if all_new_entities:
        logger.info(
            "domain_reputation: %d new entities discovered (subdomains + IPs)",
            len(all_new_entities),
        )

    logger.info(
        "domain_reputation: done — %d domains, %d CT records, %d malicious, %d archived",
        checked,
        stats["ct_records"],
        stats["urlscan_malicious"],
        stats["wayback_archived"],
    )

    return extraction_results, {"domain_reputation": status, **stats}
