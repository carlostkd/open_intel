"""
Threat intelligence enrichment — OTX (AlienVault) and abuse.ch (MalwareBazaar,
ThreatFox, URLhaus).

Returns page-shaped dicts compatible with ``extract_entities_from_pages`` (``url``,
``text`` / ``content``, plus ``link``, ``status``, ``source`` for traceability).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


def is_onion_url(url: str) -> bool:
    """Return True if *url* points to a .onion hidden service."""
    if not url:
        return False
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return host.endswith(".onion")
    except Exception:
        return False
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

# All HTTP calls use at most 30s client timeout (enforced per request).


_ABUSECH_WARNED = False


def _abusech_headers() -> dict[str, str]:
    key = (os.environ.get("ABUSECH_API_KEY") or "").strip()
    return {"Auth-Key": key} if key else {}


def _abusech_enabled() -> bool:
    """abuse.ch APIs (MalwareBazaar/ThreatFox/URLhaus) require an Auth-Key
    since 2024. Return False (and log once) when the key is missing so we
    skip the request entirely instead of spamming HTTP 401."""
    global _ABUSECH_WARNED
    if (os.environ.get("ABUSECH_API_KEY") or "").strip():
        return True
    if not _ABUSECH_WARNED:
        logger.info(
            "abuse.ch enrichment skipped — set ABUSECH_API_KEY "
            "(free at https://auth.abuse.ch) to enable MalwareBazaar/ThreatFox/URLhaus."
        )
        _ABUSECH_WARNED = True
    return False


def is_onion_url(url: str) -> bool:
    """
    Return True if *url* looks like a Tor hidden service URL (.onion).
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url.strip())
        host = (parsed.hostname or "").lower()
        return host.endswith(".onion")
    except Exception:
        return ".onion" in url.lower()


async def fetch_otx_pulses(query: str, api_key: str, limit: int = 20) -> list[dict]:
    """
    Search OTX for threat pulses related to the query.

    Returns list of dicts with pulse metadata and optional ``indicators``.
    """
    if not (api_key or "").strip():
        logger.debug("OTX skipped — no API key configured")
        return []

    headers = {"X-OTX-API-KEY": api_key.strip()}
    results: list[dict] = []

    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            url = f"{OTX_BASE_URL}/search/pulses"
            params = {"q": query, "limit": limit, "page": 1}

            async with session.get(url, params=params) as resp:
                if resp.status != 200:
                    logger.warning("OTX pulse search returned HTTP %s", resp.status)
                    return []

                data = await resp.json()
                pulses = data.get("results", [])
                logger.info("OTX: %d results", len(pulses))

                for pulse in pulses:
                    mf = pulse.get("malware_families") or []
                    if mf and isinstance(mf[0], str):
                        malware_families_fmt: list[Any] = mf
                    else:
                        malware_families_fmt = mf

                    result = {
                        "source": "otx_pulse",
                        "pulse_id": pulse.get("id"),
                        "title": pulse.get("name", ""),
                        "description": pulse.get("description", ""),
                        "tags": pulse.get("tags", []),
                        "created": pulse.get("created"),
                        "modified": pulse.get("modified"),
                        "tlp": pulse.get("tlp", "white"),
                        "indicator_count": pulse.get("indicator_count", 0),
                        "malware_families": malware_families_fmt,
                        "attack_ids": [
                            a.get("display_name")
                            for a in (pulse.get("attack_ids") or [])
                            if isinstance(a, dict)
                        ],
                        "indicators": [],
                    }
                    results.append(result)

                for pulse_result in results[:5]:
                    indicators = await fetch_otx_pulse_indicators(
                        str(pulse_result["pulse_id"]), api_key, session
                    )
                    pulse_result["indicators"] = indicators

    except asyncio.TimeoutError:
        logger.warning("OTX: Request timed out")
    except aiohttp.ClientError as e:
        logger.warning("OTX: Client error: %s", e)
    except Exception as e:
        logger.warning("OTX: Error fetching pulses: %s", e)

    return results


async def fetch_otx_pulse_indicators(
    pulse_id: str, api_key: str, session: aiohttp.ClientSession
) -> list[dict]:
    """Fetch IOCs for a pulse."""
    try:
        url = f"{OTX_BASE_URL}/pulses/{pulse_id}/indicators"
        headers = {"X-OTX-API-KEY": api_key}

        async with session.get(url, headers=headers) as resp:
            if resp.status != 200:
                return []

            data = await resp.json()
            indicators = data.get("results", [])

            return [
                {
                    "type": ind.get("type"),
                    "value": ind.get("indicator"),
                    "description": ind.get("description", ""),
                    "created": ind.get("created"),
                }
                for ind in indicators
                if ind.get("indicator")
            ]

    except Exception as e:
        logger.debug("OTX: Error fetching indicators for pulse %s: %s", pulse_id, e)
        return []


def otx_pulse_to_page(pulse: dict) -> dict:
    """Convert an OTX pulse to page-shaped dict for the entity extractor."""
    lines: list[str] = []

    if pulse.get("title"):
        lines.append(f"Threat Report: {pulse['title']}")

    if pulse.get("description"):
        lines.append(f"\nDescription: {pulse['description']}")

    if pulse.get("tags"):
        lines.append(f"\nTags: {', '.join(pulse['tags'])}")

    mf = pulse.get("malware_families") or []
    if mf:
        families: list[str] = []
        for m in mf:
            if isinstance(m, dict):
                families.append(m.get("display_name") or m.get("name") or "")
            elif isinstance(m, str):
                families.append(m)
        families = [f for f in families if f]
        if families:
            lines.append(f"\nMalware Families: {', '.join(families)}")

    if pulse.get("attack_ids"):
        lines.append(f"\nMITRE ATT&CK: {', '.join(pulse['attack_ids'])}")

    indicators = pulse.get("indicators", [])
    if indicators:
        lines.append("\nIndicators of Compromise:")
        for ind in indicators:
            ind_type = ind.get("type", "")
            ind_value = ind.get("value", "")
            ind_desc = ind.get("description", "")
            if ind_value:
                extra = f" ({ind_desc})" if ind_desc else ""
                lines.append(f"  {ind_type}: {ind_value}{extra}")

    content = "\n".join(lines)
    pid = pulse.get("pulse_id") or ""
    link = f"https://otx.alienvault.com/pulse/{pid}"

    return {
        "link": link,
        "url": link,
        "content": content,
        "text": content,
        "status": 200,
        "source": "alienvault_otx",
        "title": pulse.get("title", "OTX Threat Report"),
        "via": "otx_api",
    }


async def fetch_malwarebazaar(query: str, limit: int = 20) -> list[dict]:
    """Query MalwareBazaar by tag then by signature."""
    if not _abusech_enabled():
        return []
    results: list[dict] = []
    q = (query or "").strip()
    if not q:
        # Fetch most recent samples (last 100)
        try:
            headers = _abusech_headers()
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                payload = {"query": "get_recent", "selector": "time"}
                async with session.post(MALWAREBAZAAR_URL, data=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("query_status") == "ok":
                            samples = data.get("data") or []
                            for sample in samples:
                                results.append({
                                    "source": "malwarebazaar",
                                    "sha256": sample.get("sha256_hash"),
                                    "signature": sample.get("signature"),
                                    "malware_family": sample.get("signature", ""),
                                    "tags": sample.get("tags", []),
                                    "first_seen": sample.get("first_seen"),
                                })
                            return results
        except Exception as e:
            logger.warning("MalwareBazaar recent fetch failed: %s", e)
            return []
        return []

    headers = _abusech_headers()
    timeout = aiohttp.ClientTimeout(total=30)

    def _map_sample(sample: dict) -> dict:
        return {
            "source": "malwarebazaar",
            "sha256": sample.get("sha256_hash"),
            "md5": sample.get("md5_hash"),
            "file_name": sample.get("file_name"),
            "file_type": sample.get("file_type"),
            "signature": sample.get("signature"),
            "tags": sample.get("tags", []),
            "malware_family": sample.get("signature", ""),
            "first_seen": sample.get("first_seen"),
            "last_seen": sample.get("last_seen"),
            "reporter": sample.get("reporter", ""),
            "comment": sample.get("comment", ""),
        }

    try:
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            tag_payload = {"query": "get_taginfo", "tag": q, "limit": limit}
            async with session.post(MALWAREBAZAAR_URL, data=tag_payload) as resp:
                if resp.status != 200:
                    logger.warning("MalwareBazaar: HTTP %s (tag)", resp.status)
                else:
                    data = await resp.json()
                    if data.get("query_status") == "no_api_key":
                        logger.warning(
                            "MalwareBazaar: no_api_key — set ABUSECH_API_KEY for abuse.ch APIs"
                        )
                        return []
                    if data.get("query_status") == "ok":
                        samples = data.get("data") or []
                        logger.info("MalwareBazaar: %d samples (tag)", len(samples))
                        for sample in samples:
                            results.append(_map_sample(sample))
                        if results:
                            return results

            sig_payload = {"query": "get_siginfo", "signature": q, "limit": limit}
            async with session.post(MALWAREBAZAAR_URL, data=sig_payload) as resp:
                if resp.status != 200:
                    logger.warning("MalwareBazaar: HTTP %s (signature)", resp.status)
                    return []
                data = await resp.json()
                if data.get("query_status") != "ok":
                    return []
                samples = data.get("data") or []
                logger.info("MalwareBazaar: %d samples (signature)", len(samples))
                for sample in samples:
                    results.append(_map_sample(sample))

    except asyncio.TimeoutError:
        logger.warning("MalwareBazaar: Request timed out")
    except aiohttp.ClientError as e:
        logger.warning("MalwareBazaar: Client error: %s", e)
    except Exception as e:
        logger.warning("MalwareBazaar: Error: %s", e)

    return results


async def fetch_threatfox(query: str, limit: int = 50) -> list[dict]:
    """Search ThreatFox IOCs by search term."""
    if not _abusech_enabled():
        return []
    results: list[dict] = []
    q = (query or "").strip()
    if not q:
        # Fetch most recent IOCs (last 24 hours)
        payload = {"query": "get_iocs", "days": 1}
        try:
            headers = _abusech_headers()
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                async with session.post(THREATFOX_URL, json=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("query_status") == "ok":
                            iocs = data.get("data") or []
                            for ioc in iocs[:limit]:
                                conf = ioc.get("confidence_level")
                                conf_f = float(conf) / 100.0 if conf is not None else 0.0
                                results.append({
                                    "source": "threatfox",
                                    "ioc_type": ioc.get("ioc_type"),
                                    "ioc_value": ioc.get("ioc"),
                                    "malware": ioc.get("malware_printable"),
                                    "confidence": conf_f,
                                    "tags": ioc.get("tags", []),
                                })
                            return results
        except Exception as e:
            logger.warning("ThreatFox recent fetch failed: %s", e)
            return []
        return []

    headers = _abusech_headers()
    timeout = aiohttp.ClientTimeout(total=30)
    payload = {"query": "search_ioc", "search_term": q}

    try:
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            async with session.post(THREATFOX_URL, json=payload) as resp:
                if resp.status != 200:
                    logger.warning("ThreatFox: HTTP %s", resp.status)
                    return []

                data = await resp.json()
                if data.get("query_status") == "no_api_key":
                    logger.warning(
                        "ThreatFox: no_api_key — set ABUSECH_API_KEY for abuse.ch APIs"
                    )
                    return []
                if data.get("query_status") != "ok":
                    return []

                iocs = data.get("data") or []
                logger.info("ThreatFox: %d results", len(iocs))

                for ioc in iocs[:limit]:
                    conf = ioc.get("confidence_level")
                    conf_f = float(conf) / 100.0 if conf is not None else 0.0
                    results.append(
                        {
                            "source": "threatfox",
                            "ioc_type": ioc.get("ioc_type"),
                            "ioc_value": ioc.get("ioc"),
                            "malware": ioc.get("malware"),
                            "malware_printable": ioc.get("malware_printable"),
                            "confidence": conf_f,
                            "first_seen": ioc.get("first_seen"),
                            "last_seen": ioc.get("last_seen"),
                            "tags": ioc.get("tags", []),
                            "comment": ioc.get("comment", ""),
                            "reporter": ioc.get("reporter", ""),
                        }
                    )

    except asyncio.TimeoutError:
        logger.warning("ThreatFox: Request timed out")
    except aiohttp.ClientError as e:
        logger.warning("ThreatFox: Client error: %s", e)
    except Exception as e:
        logger.warning("ThreatFox: Error: %s", e)

    return results


async def fetch_urlhaus(query: str, limit: int = 20) -> list[dict]:
    """Search URLhaus by tag."""
    if not _abusech_enabled():
        return []
    results: list[dict] = []
    q = (query or "").strip()
    if not q:
        return []

    headers = _abusech_headers()
    timeout = aiohttp.ClientTimeout(total=30)
    payload = {"tag": q}

    try:
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            async with session.post(f"{URLHAUS_URL}tag/", data=payload) as resp:
                if resp.status != 200:
                    logger.warning("URLhaus: HTTP %s", resp.status)
                    return []

                data = await resp.json()
                if data.get("query_status") == "no_api_key":
                    logger.warning(
                        "URLhaus: no_api_key — set ABUSECH_API_KEY for abuse.ch APIs"
                    )
                    return []
                if data.get("query_status") != "ok":
                    return []

                urls = (data.get("urls") or [])[:limit]
                logger.info("URLhaus: %d results", len(urls))

                for url_entry in urls:
                    results.append(
                        {
                            "source": "urlhaus",
                            "url": url_entry.get("url"),
                            "url_status": url_entry.get("url_status"),
                            "tags": url_entry.get("tags", []),
                            "threat": url_entry.get("threat"),
                            "date_added": url_entry.get("date_added"),
                            "reporter": url_entry.get("reporter", ""),
                        }
                    )

    except asyncio.TimeoutError:
        logger.warning("URLhaus: Request timed out")
    except aiohttp.ClientError as e:
        logger.warning("URLhaus: Client error: %s", e)
    except Exception as e:
        logger.warning("URLhaus: Error: %s", e)

    return results


def abusech_to_pages(
    malwarebazaar_results: list[dict],
    threatfox_results: list[dict],
    urlhaus_results: list[dict],
) -> list[dict]:
    """Group Abuse.ch results into page-shaped dicts."""
    pages: list[dict] = []

    if malwarebazaar_results:
        lines = ["MalwareBazaar Threat Intelligence Report\n"]
        for sample in malwarebazaar_results[:20]:
            lines.append(f"Malware Family: {sample.get('malware_family', 'Unknown')}")
            if sample.get("sha256"):
                lines.append(f"SHA256: {sample['sha256']}")
            if sample.get("tags"):
                lines.append(f"Tags: {', '.join(sample['tags'])}")
            if sample.get("reporter"):
                lines.append(f"Reporter: {sample['reporter']}")
            if sample.get("first_seen"):
                lines.append(f"First seen: {sample['first_seen']}")
            lines.append("")

        content = "\n".join(lines)
        link = "https://bazaar.abuse.ch/browse/"
        pages.append(
            {
                "link": link,
                "url": link,
                "content": content,
                "text": content,
                "status": 200,
                "source": "malwarebazaar",
                "via": "abusech_api",
            }
        )

    if threatfox_results:
        lines = ["ThreatFox IOC Intelligence Report\n"]
        for ioc in threatfox_results[:30]:
            lines.append(f"IOC Type: {ioc.get('ioc_type', 'Unknown')}")
            lines.append(f"IOC Value: {ioc.get('ioc_value', '')}")
            if ioc.get("malware_printable"):
                lines.append(f"Malware: {ioc['malware_printable']}")
            if ioc.get("confidence"):
                lines.append(f"Confidence: {ioc['confidence']:.0%}")
            if ioc.get("tags"):
                lines.append(f"Tags: {', '.join(ioc['tags'])}")
            lines.append("")

        content = "\n".join(lines)
        link = "https://threatfox.abuse.ch/"
        pages.append(
            {
                "link": link,
                "url": link,
                "content": content,
                "text": content,
                "status": 200,
                "source": "threatfox",
                "via": "abusech_api",
            }
        )

    if urlhaus_results:
        lines = ["URLhaus Malicious URL Intelligence Report\n"]
        for url_entry in urlhaus_results[:20]:
            lines.append(f"URL: {url_entry.get('url', '')}")
            lines.append(f"Threat: {url_entry.get('threat', 'Unknown')}")
            if url_entry.get("tags"):
                lines.append(f"Tags: {', '.join(url_entry['tags'])}")
            lines.append("")

        content = "\n".join(lines)
        link = "https://urlhaus.abuse.ch/"
        pages.append(
            {
                "link": link,
                "url": link,
                "content": content,
                "text": content,
                "status": 200,
                "source": "urlhaus",
                "via": "abusech_api",
            }
        )

    return pages


_RANSOMWARE_LIVE_BASE = "https://api.ransomware.live/v2"
_RANSOMWARE_LIVE_HEADERS = {"User-Agent": "Open_Intel-OSINT/1.0", "Accept": "application/json"}


def _rl_extract_onion_urls(group: dict) -> list[str]:
    """Extract .onion leak-site URLs from a group dict (available sites first)."""
    locations = group.get("locations") or []
    if not isinstance(locations, list):
        return []
    # available=True sites first, then the rest
    locations = sorted(locations, key=lambda l: not l.get("available", False))
    urls: list[str] = []
    for loc in locations:
        fqdn = (loc.get("fqdn") or "").strip()
        if fqdn and ".onion" in fqdn:
            urls.append(fqdn if fqdn.startswith("http") else f"http://{fqdn}")
    return urls


async def fetch_ransomware_live(query: str) -> list[dict]:
    """
    Search ransomware.live for threat group profiles, leak-site .onion addresses,
    and recent victim claim URLs.

    Produces three kinds of intelligence:
    1. Group profile + TTPs (text for entity extraction)
    2. Leak-site .onion addresses (scrape seeds — bypass search engine discovery)
    3. Individual victim claim URLs (specific .onion post pages to scrape)

    Free public API — no key required.
    """
    q = (query or "").strip().lower()
    if not q:
        return []

    results: list[dict] = []
    timeout = aiohttp.ClientTimeout(total=25)

    try:
        async with aiohttp.ClientSession(headers=_RANSOMWARE_LIVE_HEADERS, timeout=timeout) as session:
            # ── 1. Match groups from the full group index ──────────────────────
            async with session.get(f"{_RANSOMWARE_LIVE_BASE}/groups") as resp:
                if resp.status != 200:
                    logger.warning("ransomware.live /groups HTTP %s", resp.status)
                    return []
                all_groups = await resp.json(content_type=None)

            matched_summary: list[dict] = []
            for g in (all_groups if isinstance(all_groups, list) else []):
                name = (g.get("name") or "").lower()
                if q in name:
                    matched_summary.append(g)

            if not matched_summary:
                logger.info("ransomware.live: no groups matched %r", query)
                return []

            logger.info("ransomware.live: %d groups matched %r", len(matched_summary), query)

            # ── 2. Fetch full group detail for each match (has ttps, tools, locations) ──
            async def _fetch_group_detail(gname: str) -> Optional[dict]:
                try:
                    async with session.get(f"{_RANSOMWARE_LIVE_BASE}/group/{gname}") as r:
                        if r.status == 200:
                            text = await r.text()
                            if text.strip()[:1] in "[{":
                                return await r.json(content_type=None) if False else \
                                       __import__("json").loads(text)
                except Exception:
                    pass
                return None

            detail_tasks = [_fetch_group_detail(g.get("name", "")) for g in matched_summary[:5]]
            details = await asyncio.gather(*detail_tasks, return_exceptions=True)

            group_map: dict[str, dict] = {}
            for g, detail in zip(matched_summary[:5], details):
                gname = g.get("name", "")
                if isinstance(detail, dict):
                    group_map[gname] = {**g, **detail}
                else:
                    group_map[gname] = g

            # ── 3. Pull recent victims and filter by matched groups ────────────
            recent_victims: list[dict] = []
            matched_names = {g.get("name", "").lower() for g in matched_summary}
            for endpoint in ("/v2/recentvictims", "/v2/recentcyberattacks"):
                try:
                    async with session.get(f"https://api.ransomware.live{endpoint}") as r:
                        if r.status == 200:
                            text = await r.text()
                            if text.strip()[:1] == "[":
                                raw: list = __import__("json").loads(text)
                                for v in raw:
                                    if (v.get("group") or "").lower() in matched_names:
                                        recent_victims.append(v)
                except Exception:
                    pass

            logger.info("ransomware.live: %d recent victims for matched groups", len(recent_victims))

            # ── 4. Assemble results ───────────────────────────────────────────
            for gname, gdata in group_map.items():
                onion_urls = _rl_extract_onion_urls(gdata)

                # Collect victims for this specific group
                group_victims = [
                    v for v in recent_victims
                    if (v.get("group") or "").lower() == gname.lower()
                ]

                # Claim URLs are individual victim post pages on the leak site
                claim_urls = [
                    v.get("claim_url") for v in group_victims
                    if v.get("claim_url") and ".onion" in (v.get("claim_url") or "")
                ]

                results.append({
                    "group":        gname,
                    "description":  gdata.get("description") or "",
                    "onion_urls":   onion_urls,
                    "claim_urls":   claim_urls[:30],
                    "victims":      group_victims[:50],
                    "ttps":         gdata.get("ttps") or [],
                    "tools":        gdata.get("tools") or [],
                    "victim_count": gdata.get("_victim_count", 0),
                })

    except asyncio.TimeoutError:
        logger.warning("ransomware.live: request timed out")
    except aiohttp.ClientError as exc:
        logger.warning("ransomware.live: client error: %s", exc)
    except Exception as exc:
        logger.warning("ransomware.live: unexpected error: %s", exc)

    return results


def ransomwarelive_to_pages(groups: list[dict]) -> list[dict]:
    """Convert ransomware.live group data into page-shaped dicts.

    Produces two kinds of pages:
    1. A rich text summary page (for entity extraction)
    2. One stub page per discovered .onion URL (so the scraper will visit them)
    """
    pages: list[dict] = []

    for gd in groups:
        gname = gd.get("group", "Unknown")
        lines: list[str] = [f"Ransomware Group Intelligence Report: {gname}"]

        if gd.get("description"):
            lines.append(f"\nDescription: {gd['description']}")

        onion_urls = gd.get("onion_urls", [])
        if onion_urls:
            lines.append(f"\nLeak Site URLs: {', '.join(onion_urls)}")

        victims = gd.get("victims", [])
        if victims:
            lines.append(f"\nKnown Victims ({len(victims)} total):")
            for v in victims[:40]:
                title  = v.get("victim") or v.get("post_title") or v.get("website") or ""
                domain = v.get("domain") or v.get("website") or ""
                date   = v.get("attackdate") or v.get("published") or v.get("date") or ""
                country = v.get("country") or ""
                activity = v.get("activity") or ""
                victim_line = f"  - {title}"
                if domain and domain != title:
                    victim_line += f" ({domain})"
                if country:
                    victim_line += f" [{country}]"
                if date:
                    victim_line += f" {date}"
                if activity:
                    victim_line += f" — {activity}"
                lines.append(victim_line)

        claim_urls = gd.get("claim_urls", [])

        content = "\n".join(lines)
        base_link = f"https://www.ransomware.live/group/{gname}"

        pages.append({
            "link":    base_link,
            "url":     base_link,
            "content": content,
            "text":    content,
            "status":  200,
            "source":  "ransomware_live",
            "title":   f"ransomware.live — {gname}",
            "via":     "ransomware_live_api",
        })

        # Stub pages for each .onion leak site so the scraper will visit them
        for onion_url in onion_urls:
            if onion_url and ".onion" in onion_url:
                stub = f"{gname} ransomware group leak site: {onion_url}"
                pages.append({
                    "link":    onion_url,
                    "url":     onion_url,
                    "content": stub,
                    "text":    stub,
                    "status":  200,
                    "source":  "ransomware_live",
                    "title":   f"{gname} leak site",
                    "via":     "ransomware_live_onion_seed",
                    "_scrape_seed": True,
                })

        # Stub pages for individual victim claim URLs (specific post pages on leak sites)
        for claim_url in claim_urls[:20]:
            if claim_url and ".onion" in claim_url:
                stub = f"{gname} ransomware victim post: {claim_url}"
                pages.append({
                    "link":    claim_url,
                    "url":     claim_url,
                    "content": stub,
                    "text":    stub,
                    "status":  200,
                    "source":  "ransomware_live",
                    "title":   f"{gname} victim claim",
                    "via":     "ransomware_live_claim_seed",
                    "_scrape_seed": True,
                })

    return pages


async def _enrich_new_sources(query: str, entities: list[dict]) -> list[dict]:
    """
    Run the 4 new enrichment sources concurrently and return page-shaped dicts.

    Sources:
    - CISA KEV + advisories   (cisa.py)
    - Shodan InternetDB       (shodan.py)
    - VirusTotal              (virustotal.py)
    - Historical intel        (historical_intel.py)
    """
    from sources.cisa import enrich_cisa
    from sources.shodan import enrich_shodan
    from sources.virustotal import enrich_virustotal
    from sources.historical_intel import enrich_historical

    async def _gather():
        return await asyncio.gather(
            enrich_cisa(query, entities),
            enrich_shodan(entities),
            enrich_virustotal(entities),
            return_exceptions=True,
        )

    cisa_results, shodan_results, vt_results = [], [], []
    try:
        packed = await asyncio.wait_for(_gather(), timeout=55.0)
    except asyncio.TimeoutError:
        logger.warning("_enrich_new_sources: deadline exceeded")
        return []

    cisa_results, shodan_results, vt_results = packed

    if isinstance(cisa_results, Exception):
        logger.warning("CISA enrichment failed: %s", cisa_results)
        cisa_results = []
    if isinstance(shodan_results, Exception):
        logger.warning("Shodan enrichment failed: %s", shodan_results)
        shodan_results = []
    if isinstance(vt_results, Exception):
        logger.warning("VirusTotal enrichment failed: %s", vt_results)
        vt_results = []

    pages: list[dict] = []

    if cisa_results:
        pages.extend(_cisa_results_to_pages(cisa_results, query))
    if shodan_results:
        pages.extend(_shodan_results_to_pages(shodan_results))
    if vt_results:
        pages.extend(_vt_results_to_pages(vt_results))

    if cisa_results or shodan_results or vt_results:
        unenriched = _group_unenriched_entities(entities, cisa_results, shodan_results, vt_results)
        if unenriched:
            hist_pages = await enrich_historical(unenriched)
            pages.extend(_historical_results_to_pages(hist_pages))

    # Entity-based MITRE overlay: fires when the caller passes pre-extracted entities
    # that contain actors but zero CVE/MITRE_TECHNIQUE results.
    _actor_types = {"THREAT_ACTOR", "RANSOMWARE_GROUP", "MALWARE_FAMILY"}
    _cve_mitre_types = {"CVE", "MITRE_TECHNIQUE"}
    _actor_ents = [
        e for e in entities
        if (e.get("type") or e.get("entity_type", "")) in _actor_types
    ]
    _has_cve_or_mitre = any(
        (e.get("type") or e.get("entity_type", "")) in _cve_mitre_types
        for e in entities
    )
    if _actor_ents and not _has_cve_or_mitre:
        from sources.historical_intel import get_techniques_for_actor
        for _actor_ent in _actor_ents:
            _actor_name = (
                _actor_ent.get("value")
                or _actor_ent.get("canonical_value")
                or _actor_ent.get("entity_value", "")
            )
            if not _actor_name:
                continue
            try:
                _techniques = await get_techniques_for_actor(_actor_name)
            except Exception as _exc:
                logger.warning("MITRE overlay: failed for '%s': %s", _actor_name, _exc)
                _techniques = []
            if not _techniques:
                continue
            logger.info(f"MITRE overlay: added {len(_techniques)} techniques for actor '{_actor_name}'")
            _oc = (
                f"MITRE ATT&CK Overlay: Techniques associated with {_actor_name} "
                f"(source: mitre_attack_overlay)\n" + "\n".join(_techniques)
            )
            pages.append({
                "link": "https://attack.mitre.org/",
                "url": "https://attack.mitre.org/",
                "content": _oc,
                "text": _oc,
                "status": 200,
                "source": "mitre_attack_overlay",
                "via": "mitre_overlay",
            })

    return pages


def _cisa_results_to_pages(results: list[dict], query: str) -> list[dict]:
    pages: list[dict] = []
    kev_entries = [r for r in results if r.get("source") == "cisa_kev"]
    adv_entries = [r for r in results if r.get("source") == "cisa_advisory"]

    if kev_entries:
        lines = ["CISA Known Exploited Vulnerabilities (KEV) Catalog\n"]
        for r in kev_entries:
            lines.append(f"CVE: {r.get('entity_value', '')}")
            if r.get("vendor_project"):
                lines.append(f"  Vendor/Project: {r['vendor_project']}")
            if r.get("product"):
                lines.append(f"  Product: {r['product']}")
            if r.get("vulnerability_name"):
                lines.append(f"  Vulnerability: {r['vulnerability_name']}")
            if r.get("date_added"):
                lines.append(f"  Date Added to KEV: {r['date_added']}")
            if r.get("short_description"):
                lines.append(f"  Description: {r['short_description']}")
            lines.append("")
        pages.append({
            "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "content": "\n".join(lines),
            "text": "\n".join(lines),
            "status": 200,
            "source": "cisa_kev",
            "via": "cisa_feed",
        })

    if adv_entries:
        lines = ["CISA Cybersecurity Advisories\n"]
        for r in adv_entries:
            lines.append(f"Title: {r.get('advisory_title', '')}")
            if r.get("advisory_url"):
                lines.append(f"  URL: {r['advisory_url']}")
            if r.get("advisory_date"):
                lines.append(f"  Date: {r['advisory_date']}")
            lines.append("")
        pages.append({
            "link": "https://www.cisa.gov/cybersecurity-advisories",
            "url": "https://www.cisa.gov/cybersecurity-advisories",
            "content": "\n".join(lines),
            "text": "\n".join(lines),
            "status": 200,
            "source": "cisa_advisory",
            "via": "cisa_feed",
        })

    return pages


def _shodan_results_to_pages(results: list[dict]) -> list[dict]:
    pages: list[dict] = []
    for r in results:
        lines = [f"Shodan InternetDB: {r.get('entity_value', '')}\n"]
        if r.get("open_ports"):
            lines.append(f"Open Ports: {', '.join(str(p) for p in r['open_ports'])}")
        if r.get("hostnames"):
            lines.append(f"Hostnames: {', '.join(r['hostnames'])}")
        if r.get("tags"):
            lines.append(f"Tags: {', '.join(r['tags'])}")
        if r.get("vulns"):
            lines.append(f"Vulnerabilities: {', '.join(r['vulns'])}")
        if r.get("correlated_cves"):
            lines.append(f"Correlated CVEs (also extracted): {', '.join(r['correlated_cves'])}")
        if r.get("high_confidence_c2"):
            lines.append("** HIGH CONFIDENCE C2 **")
        pages.append({
            "link": f"https://internetdb.shodan.io/{r.get('entity_value', '')}",
            "url": f"https://internetdb.shodan.io/{r.get('entity_value', '')}",
            "content": "\n".join(lines),
            "text": "\n".join(lines),
            "status": 200,
            "source": "shodan_internetdb",
            "via": "shodan_api",
        })
    return pages


def _vt_results_to_pages(results: list[dict]) -> list[dict]:
    pages: list[dict] = []
    for r in results:
        lines = [f"VirusTotal: {r.get('entity_value', '')}\n"]
        lines.append(f"Detection: {r.get('malicious_count', 0)}/{r.get('total_engines', 0)} ({r.get('detection_ratio', 0):.0%})")
        if r.get("suggested_threat_label"):
            lines.append(f"Threat Label: {r['suggested_threat_label']}")
        if r.get("first_seen"):
            lines.append(f"First Seen: {r['first_seen']}")
        if r.get("last_seen"):
            lines.append(f"Last Seen: {r['last_seen']}")
        if r.get("confirmed_malicious"):
            lines.append("** CONFIRMED MALICIOUS **")
        pages.append({
            "link": f"https://www.virustotal.com/gui/file/{r.get('entity_value', '')}",
            "url": f"https://www.virustotal.com/gui/file/{r.get('entity_value', '')}",
            "content": "\n".join(lines),
            "text": "\n".join(lines),
            "status": 200,
            "source": "virustotal",
            "via": "virustotal_api",
        })
    return pages


def _group_unenriched_entities(
    entities: list[dict],
    cisa_results: list[dict],
    shodan_results: list[dict],
    vt_results: list[dict],
) -> dict[str, list[dict]]:
    """
    Determine which THREAT_ACTOR / RANSOMWARE_GROUP / MALWARE_FAMILY entities
    received zero enrichment results from CISA, Shodan, and VT.
    Returns a dict mapping entity type -> list of entities with no enrichment.
    """
    fallback_types = {"THREAT_ACTOR", "RANSOMWARE_GROUP", "MALWARE_FAMILY"}
    ent_by_type: dict[str, list[dict]] = {t: [] for t in fallback_types}

    for e in entities:
        et = e.get("type") or e.get("entity_type", "")
        if et in fallback_types:
            ent_by_type[et].append(e)

    enriched_values: set[str] = set()
    for r in cisa_results:
        ev = r.get("entity_value", "")
        if ev:
            enriched_values.add(ev.lower())
    for r in shodan_results:
        ev = r.get("entity_value", "")
        if ev:
            enriched_values.add(ev.lower())
    for r in vt_results:
        ev = r.get("entity_value", "")
        if ev:
            enriched_values.add(ev.lower())

    result: dict[str, list[dict]] = {}
    for et, ent_list in ent_by_type.items():
        unenriched = [
            ent for ent in ent_list
            if (ent.get("value") or ent.get("entity_value", "")).lower() not in enriched_values
        ]
        if unenriched:
            result[et] = unenriched

    return result


def _historical_results_to_pages(results: list[dict]) -> list[dict]:
    pages: list[dict] = []
    for r in results:
        src = r.get("source", "")
        lines = [f"Historical Intel: {r.get('entity_value', '')}\n"]
        if src == "mitre_attack":
            lines.append(f"MITRE ATT&CK ID: {r.get('mitre_id', '')}")
            lines.append(f"Name: {r.get('mitre_name', '')}")
            if r.get("aliases"):
                lines.append(f"Aliases: {', '.join(r['aliases'])}")
            if r.get("techniques"):
                lines.append(f"Techniques: {', '.join(r['techniques'])}")
            if r.get("description"):
                lines.append(f"Description: {r['description']}")
            pages.append({
                "link": f"https://attack.mitre.org/groups/{r.get('mitre_id', '')}",
                "url": f"https://attack.mitre.org/groups/{r.get('mitre_id', '')}",
                "content": "\n".join(lines),
                "text": "\n".join(lines),
                "status": 200,
                "source": "mitre_attack",
                "via": "mitre_cti",
            })
        elif src == "fbi_doj_press":
            lines.append(f"Title: {r.get('press_title', '')}")
            lines.append(f"Date: {r.get('press_date', '')}")
            pages.append({
                "link": r.get("press_url", ""),
                "url": r.get("press_url", ""),
                "content": "\n".join(lines),
                "text": "\n".join(lines),
                "status": 200,
                "source": "fbi_doj_press",
                "via": "fbi_rss",
            })
        elif src == "cisa_advisory_historical":
            lines.append(f"Title: {r.get('advisory_title', '')}")
            lines.append(f"URL: {r.get('advisory_url', '')}")
            lines.append(f"Date: {r.get('advisory_date', '')}")
            pages.append({
                "link": r.get("advisory_url", ""),
                "url": r.get("advisory_url", ""),
                "content": "\n".join(lines),
                "text": "\n".join(lines),
                "status": 200,
                "source": "cisa_advisory",
                "via": "cisa_feed",
            })
    return pages


async def run_dns_enrichment(extracted_entities: list[dict]) -> dict:
    """
    Run DNS/WHOIS enrichment on extracted IP and domain entities.
    Returns ip_enrichments, domain_enrichments, new_entities, infrastructure_clusters.
    """
    try:
        from sources.dns_enrichment import enrich_with_dns
        return await enrich_with_dns(extracted_entities)
    except Exception as e:
        logger.error("DNS enrichment error: %s", e)
        return {
            "ip_enrichments": {},
            "domain_enrichments": {},
            "new_entities": [],
            "infrastructure_clusters": [],
        }


async def enrich_investigation(
    query: str,
    otx_api_key: Optional[str] = None,
    entities: Optional[list[dict]] = None,
) -> list[dict]:
    """
    Run all threat intel sources in parallel; return page dicts for extraction.

    Sources:
    - OTX (AlienVault)      — requires OTX_API_KEY
    - MalwareBazaar          — free (ABUSECH_API_KEY improves rate limits)
    - ThreatFox              — free
    - URLhaus                — free
    - ransomware.live        — free, no key required
    - CISA KEV + advisories  — free, no key required (clearnet)
    - Shodan InternetDB      — free, no key required (clearnet)
    - VirusTotal             — requires VT_API_KEY (clearnet)

    Completes within ~60s (enforced via ``asyncio.wait_for``).
    """
    logger.info("Starting threat intel enrichment for: %s", query)

    _entities = entities if entities is not None else []

    async def _gather():
        return await asyncio.gather(
            fetch_otx_pulses(query, otx_api_key or "", limit=20),
            fetch_malwarebazaar(query, limit=20),
            fetch_threatfox(query, limit=50),
            fetch_urlhaus(query, limit=20),
            fetch_ransomware_live(query),
            _enrich_new_sources(query, _entities),
            return_exceptions=True,
        )

    try:
        packed = await asyncio.wait_for(_gather(), timeout=59.0)
    except asyncio.TimeoutError:
        logger.warning("Enrichment: deadline exceeded (59s), returning empty")
        return []

    otx_pulses, mb_results, tf_results, uh_results, rl_groups, new_pages = packed

    if isinstance(otx_pulses, Exception):
        logger.warning("OTX failed: %s", otx_pulses)
        otx_pulses = []
    if isinstance(mb_results, Exception):
        logger.warning("MalwareBazaar failed: %s", mb_results)
        mb_results = []
    if isinstance(tf_results, Exception):
        logger.warning("ThreatFox failed: %s", tf_results)
        tf_results = []
    if isinstance(uh_results, Exception):
        logger.warning("URLhaus failed: %s", uh_results)
        uh_results = []
    if isinstance(rl_groups, Exception):
        logger.warning("ransomware.live failed: %s", rl_groups)
        rl_groups = []
    if isinstance(new_pages, Exception):
        logger.warning("New enrichment sources failed: %s", new_pages)
        new_pages = []

    pages: list[dict] = []

    for pulse in otx_pulses:
        page = otx_pulse_to_page(pulse)
        if page.get("content"):
            pages.append(page)

    pages.extend(abusech_to_pages(mb_results, tf_results, uh_results))
    pages.extend(ransomwarelive_to_pages(rl_groups))
    pages.extend(new_pages or [])

    # Page-scan MITRE overlay: extract actor names from ransomware.live / OTX results
    # and inject T-codes when no MITRE techniques appear in any enrichment page.
    # This fires without a pre-extracted entity list, covering the current pipeline.
    _overlay_actor_names: list[str] = []
    for _g in (rl_groups if isinstance(rl_groups, list) else []):
        _gname = _g.get("group", "")
        if _gname and _gname not in _overlay_actor_names:
            _overlay_actor_names.append(_gname)
    for _pulse in (otx_pulses if isinstance(otx_pulses, list) else []):
        for _mf in (_pulse.get("malware_families") or []):
            _mfname = _mf if isinstance(_mf, str) else (_mf.get("display_name") or _mf.get("name", ""))
            if _mfname and _mfname not in _overlay_actor_names:
                _overlay_actor_names.append(_mfname)

    if _overlay_actor_names:
        _t_pattern = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
        _t_found = any(
            _t_pattern.search(p.get("content", "") or p.get("text", ""))
            for p in pages
        )
        if not _t_found:
            from sources.historical_intel import get_techniques_for_actor

            OVERLAY_TIMEOUT = 20

            _q_lower = query.lower()
            _capped = _overlay_actor_names[:10]
            _prioritized = sorted(
                _capped,
                key=lambda a: 0 if a.lower() in _q_lower else 1,
            )

            async def _run_overlay():
                _results = []
                for _aname in _prioritized:
                    try:
                        _techs = await get_techniques_for_actor(_aname)
                    except Exception as _oexc:
                        logger.warning("MITRE overlay: failed for '%s': %s", _aname, _oexc)
                        _techs = []
                    if not _techs:
                        continue
                    logger.info(f"MITRE overlay: added {len(_techs)} techniques for actor '{_aname}'")
                    _ocontent = (
                        f"MITRE ATT&CK Overlay: Techniques associated with {_aname} "
                        f"(source: mitre_attack_overlay)\n" + "\n".join(_techs)
                    )
                    _results.append({
                        "link": "https://attack.mitre.org/",
                        "url": "https://attack.mitre.org/",
                        "content": _ocontent,
                        "text": _ocontent,
                        "status": 200,
                        "source": "mitre_attack_overlay",
                        "via": "mitre_overlay",
                    })
                return _results

            try:
                _overlay_pages = await asyncio.wait_for(
                    _run_overlay(),
                    timeout=OVERLAY_TIMEOUT,
                )
                pages.extend(_overlay_pages)
            except asyncio.TimeoutError:
                logger.warning(
                    "MITRE overlay timed out after %ds — skipping",
                    OVERLAY_TIMEOUT,
                )

    total_onion_seeds = sum(1 for p in pages if p.get("_scrape_seed"))
    logger.info(
        "Enrichment complete: %s OTX pulses, %s MalwareBazaar, "
        "%s ThreatFox IOCs, %s URLhaus, %s ransomware.live groups "
        "(%s .onion seeds) → %s enrichment pages total",
        len(otx_pulses), len(mb_results), len(tf_results),
        len(uh_results), len(rl_groups), total_onion_seeds, len(pages),
    )

    return pages
