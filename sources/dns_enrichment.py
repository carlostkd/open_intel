"""
WHOIS/passive DNS enrichment using CIRCL pDNS, CIRCL pSSL, and RDAP.

Enriches extracted IP and domain entities with DNS history, WHOIS data,
and infrastructure overlap detection. Free, no auth required for CIRCL/RDAP.
"""

import asyncio
import aiohttp
import ipaddress
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

CIRCL_PDNS_URL = "https://www.circl.lu/pdns/query"
CIRCL_PSSL_URL = "https://www.circl.lu/v2pssl/query"

RDAP_IP_URL = "https://rdap.arin.net/registry/ip/{ip}"
RDAP_DOMAIN_URL = "https://rdap.org/domain/{domain}"

CIRCL_TIMEOUT = 15
WHOIS_TIMEOUT = 10

MAX_IPS_TO_ENRICH = 20
MAX_DOMAINS_TO_ENRICH = 20

MAX_RELATED_PER_ENTITY = 5

CIRCL_DELAY = 0.5


class DNSEnrichment:
    """
    Enriches IP and domain entities with passive DNS history, WHOIS data,
    and infrastructure overlap detection.

    Uses CIRCL passive DNS (free, no auth).
    Optional: SecurityTrails (free tier, key needed).
    """

    def __init__(self):
        self._session: Optional[aiohttp.ClientSession] = None
        self._st_key = os.getenv("SECURITYTRAILS_API_KEY", "").strip()

    async def __aenter__(self):
        headers = {
            "User-Agent": "Open_Intel-OSINT/1.1 (security research)",
            "Accept": "application/json",
        }
        self._session = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=20),
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def enrich_entities(self, entities: list[dict]) -> dict:
        """
        Main entry point. Takes a list of extracted entities, enriches IPs
        and domains with DNS/WHOIS data.

        Returns:
        {
            "ip_enrichments": {ip: {...}},
            "domain_enrichments": {domain: {...}},
            "new_entities": [...],
            "infrastructure_clusters": [...],
        }
        """
        ips = []
        domains = []

        for entity in entities:
            etype = entity.get("entity_type", "")
            value = entity.get("canonical_value", "") or entity.get("value", "")

            if not value:
                continue

            if etype == "IP_ADDRESS":
                if self._is_valid_public_ip(value):
                    ips.append(value)
            elif etype == "DOMAIN":
                domains.append(value)

        ips = list(set(ips))[:MAX_IPS_TO_ENRICH]
        domains = list(set(domains))[:MAX_DOMAINS_TO_ENRICH]

        if not ips and not domains:
            return {
                "ip_enrichments": {},
                "domain_enrichments": {},
                "new_entities": [],
                "infrastructure_clusters": [],
            }

        logger.info(
            "DNS enrichment: %d IPs, %d domains", len(ips), len(domains)
        )

        sem = asyncio.Semaphore(3)

        ip_tasks = [self._enrich_ip(ip, sem) for ip in ips]
        domain_tasks = [self._enrich_domain(domain, sem) for domain in domains]

        ip_results = await asyncio.gather(*ip_tasks, return_exceptions=True)
        domain_results = await asyncio.gather(*domain_tasks, return_exceptions=True)

        ip_enrichments = {}
        domain_enrichments = {}
        new_entities = []

        for ip, result in zip(ips, ip_results):
            if isinstance(result, dict):
                ip_enrichments[ip] = result
                new_entities.extend(result.get("new_entities", []))

        for domain, result in zip(domains, domain_results):
            if isinstance(result, dict):
                domain_enrichments[domain] = result
                new_entities.extend(result.get("new_entities", []))

        seen: set[str] = set()
        unique_new = []
        for e in new_entities:
            key = f"{e['type']}:{e['value']}"
            if key not in seen:
                seen.add(key)
                unique_new.append(e)

        clusters = self._detect_infrastructure_clusters(ip_enrichments, domain_enrichments)

        logger.info(
            "DNS enrichment complete: %d new entities, %d clusters found",
            len(unique_new),
            len(clusters),
        )

        return {
            "ip_enrichments": ip_enrichments,
            "domain_enrichments": domain_enrichments,
            "new_entities": unique_new,
            "infrastructure_clusters": clusters,
        }

    async def _enrich_ip(self, ip: str, sem: asyncio.Semaphore) -> dict:
        async with sem:
            result: dict = {
                "ip": ip,
                "passive_dns": [],
                "whois": {},
                "ssl_certs": [],
                "new_entities": [],
                "tags": [],
            }

            pdns, whois, ssl = await asyncio.gather(
                self._circl_pdns_ip(ip),
                self._rdap_ip(ip),
                self._circl_pssl_ip(ip),
                return_exceptions=True,
            )

            await asyncio.sleep(CIRCL_DELAY)

            if isinstance(pdns, list):
                result["passive_dns"] = pdns
                for record in pdns[:MAX_RELATED_PER_ENTITY]:
                    rrname = record.get("rrname", "").rstrip(".")
                    if rrname and self._is_valid_domain(rrname):
                        result["new_entities"].append({
                            "type": "DOMAIN",
                            "value": rrname,
                            "source": "circl_pdns",
                            "context": f"Resolved to {ip} (passive DNS)",
                            "confidence": 0.75,
                        })
                if pdns:
                    result["tags"].append("has_pdns_history")

            if isinstance(whois, dict):
                result["whois"] = whois
                org = whois.get("org", "").lower()
                country = whois.get("country", "")
                C2_HOSTERS = [
                    "choopa", "vultr", "digitalocean", "linode",
                    "frantech", "m247", "serverius", "combahton",
                    "servermania", "sharktech",
                ]
                for hoster in C2_HOSTERS:
                    if hoster in org:
                        result["tags"].append(f"c2_hoster_{hoster}")
                if country in ("RU", "CN", "KP", "IR"):
                    result["tags"].append(f"country_{country.lower()}")

            if isinstance(ssl, list):
                result["ssl_certs"] = ssl
                for cert in ssl[:MAX_RELATED_PER_ENTITY]:
                    cn = cert.get("cn", "")
                    if cn and self._is_valid_domain(cn):
                        result["new_entities"].append({
                            "type": "DOMAIN",
                            "value": cn,
                            "source": "circl_pssl",
                            "context": f"SSL certificate on {ip}",
                            "confidence": 0.80,
                        })
                if ssl:
                    result["tags"].append("has_ssl_history")

            return result

    async def _enrich_domain(self, domain: str, sem: asyncio.Semaphore) -> dict:
        async with sem:
            result: dict = {
                "domain": domain,
                "passive_dns": [],
                "whois": {},
                "new_entities": [],
                "tags": [],
            }

            pdns, whois = await asyncio.gather(
                self._circl_pdns_domain(domain),
                self._rdap_domain(domain),
                return_exceptions=True,
            )

            await asyncio.sleep(CIRCL_DELAY)

            if isinstance(pdns, list):
                result["passive_dns"] = pdns
                seen_ips: set[str] = set()
                for record in pdns:
                    rdata = record.get("rdata", "")
                    if self._is_valid_public_ip(rdata) and rdata not in seen_ips:
                        seen_ips.add(rdata)
                        result["new_entities"].append({
                            "type": "IP_ADDRESS",
                            "value": rdata,
                            "source": "circl_pdns",
                            "context": f"{domain} resolved to this IP (passive DNS)",
                            "confidence": 0.80,
                        })
                    if len(result["new_entities"]) >= MAX_RELATED_PER_ENTITY:
                        break
                if pdns:
                    result["tags"].append("has_pdns_history")

            if isinstance(whois, dict):
                result["whois"] = whois
                reg_date = whois.get("registered", "")
                if reg_date:
                    result["tags"].append(f"registered_{reg_date[:7]}")

                registrant = whois.get("registrant", "").lower()
                PRIVACY_SERVICES = [
                    "whoisguard", "privacyprotect", "perfect privacy",
                    "domainsbyproxy", "withheld for privacy",
                ]
                for svc in PRIVACY_SERVICES:
                    if svc in registrant:
                        result["tags"].append("privacy_protected")
                        break

                if reg_date:
                    try:
                        from dateutil.parser import parse as parse_date

                        reg_dt = parse_date(reg_date)
                        now = datetime.now(timezone.utc)
                        if reg_dt.tzinfo is None:
                            reg_dt = reg_dt.replace(tzinfo=timezone.utc)
                        age_days = (now - reg_dt).days
                        if age_days < 30:
                            result["tags"].append("recently_registered")
                        elif age_days < 90:
                            result["tags"].append("new_domain")
                    except Exception:
                        pass

            return result

    async def _circl_pdns_ip(self, ip: str) -> list:
        if not self._session:
            return []
        try:
            async with self._session.get(
                f"{CIRCL_PDNS_URL}/{ip}",
                timeout=aiohttp.ClientTimeout(total=CIRCL_TIMEOUT),
            ) as resp:
                if resp.status != 200:
                    return []
                text = await resp.text()
                records = []
                for line in text.strip().split("\n"):
                    if line.strip():
                        try:
                            records.append(json.loads(line))
                        except Exception:
                            pass
                return records[:20]
        except Exception as e:
            logger.debug("CIRCL PDNS IP error %s: %s", ip, e)
            return []

    async def _circl_pdns_domain(self, domain: str) -> list:
        if not self._session:
            return []
        try:
            async with self._session.get(
                f"{CIRCL_PDNS_URL}/{domain}",
                timeout=aiohttp.ClientTimeout(total=CIRCL_TIMEOUT),
            ) as resp:
                if resp.status != 200:
                    return []
                text = await resp.text()
                records = []
                for line in text.strip().split("\n"):
                    if line.strip():
                        try:
                            records.append(json.loads(line))
                        except Exception:
                            pass
                return records[:20]
        except Exception as e:
            logger.debug("CIRCL PDNS domain error %s: %s", domain, e)
            return []

    async def _circl_pssl_ip(self, ip: str) -> list:
        if not self._session:
            return []
        try:
            async with self._session.get(
                f"{CIRCL_PSSL_URL}/{ip}",
                timeout=aiohttp.ClientTimeout(total=CIRCL_TIMEOUT),
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                certs = []
                for sha1, cert_data in list(data.items())[:10]:
                    subjects = cert_data.get("subjects", {})
                    cn = subjects.get("cn", [])
                    if isinstance(cn, list):
                        cn = cn[0] if cn else ""
                    certs.append({"sha1": sha1, "cn": cn, "subject": subjects})
                return certs
        except Exception as e:
            logger.debug("CIRCL PSSL error %s: %s", ip, e)
            return []

    async def _rdap_ip(self, ip: str) -> dict:
        if not self._session:
            return {}
        try:
            async with self._session.get(
                RDAP_IP_URL.format(ip=ip),
                timeout=aiohttp.ClientTimeout(total=WHOIS_TIMEOUT),
            ) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()

            result: dict = {}

            for entity in data.get("entities", []):
                vcards = entity.get("vcardArray", [None, []])
                if isinstance(vcards, list) and len(vcards) > 1:
                    for vcard in vcards[1]:
                        if isinstance(vcard, list) and len(vcard) >= 4:
                            if vcard[0] == "fn":
                                result["org"] = vcard[3]
                                break

            result["country"] = data.get("country", "")

            cidrs = data.get("cidr0_cidrs", [])
            if cidrs:
                cidr = cidrs[0]
                result["cidr"] = (
                    f"{cidr.get('v4prefix', '')}/{cidr.get('length', '')}"
                )

            handle = data.get("handle", "")
            if handle.startswith("NET-"):
                result["network"] = handle
            result["raw_handle"] = handle

            return result
        except Exception as e:
            logger.debug("RDAP IP error %s: %s", ip, e)
            return {}

    async def _rdap_domain(self, domain: str) -> dict:
        if not self._session:
            return {}
        try:
            async with self._session.get(
                RDAP_DOMAIN_URL.format(domain=domain),
                timeout=aiohttp.ClientTimeout(total=WHOIS_TIMEOUT),
            ) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()

            result: dict = {}

            for event in data.get("events", []):
                action = event.get("eventAction", "")
                date = event.get("eventDate", "")
                if action == "registration":
                    result["registered"] = date
                elif action == "expiration":
                    result["expires"] = date
                elif action == "last changed":
                    result["updated"] = date

            result["nameservers"] = [
                ns.get("ldhName", "").lower()
                for ns in data.get("nameservers", [])
            ]

            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                vcards = entity.get("vcardArray", [None, []])
                if not (isinstance(vcards, list) and len(vcards) > 1):
                    continue
                for vcard in vcards[1]:
                    if not (isinstance(vcard, list) and len(vcard) >= 4):
                        continue
                    if vcard[0] == "fn":
                        if "registrar" in roles:
                            result["registrar"] = vcard[3]
                        if "registrant" in roles:
                            result["registrant"] = vcard[3]
                        break

            result["status"] = data.get("status", [])
            return result
        except Exception as e:
            logger.debug("RDAP domain error %s: %s", domain, e)
            return {}

    def _detect_infrastructure_clusters(
        self,
        ip_enrichments: dict,
        domain_enrichments: dict,
    ) -> list[dict]:
        """Find shared IP and shared nameserver clusters across investigated entities."""
        clusters = []

        ip_to_domains: dict[str, set] = {}
        for ip, data in ip_enrichments.items():
            domains: set[str] = set()
            for record in data.get("passive_dns", []):
                rrname = record.get("rrname", "").rstrip(".")
                if rrname:
                    domains.add(rrname)
            ip_to_domains[ip] = domains

        for ip, domains in ip_to_domains.items():
            investigated = [d for d in domains if d in domain_enrichments]
            if len(investigated) >= 2:
                clusters.append({
                    "type": "shared_ip",
                    "ip": ip,
                    "domains": investigated,
                    "description": (
                        f"IP {ip} hosts multiple investigated domains: "
                        f"{', '.join(investigated)}"
                    ),
                })

        ns_to_domains: dict[str, list] = {}
        for domain, data in domain_enrichments.items():
            for ns in data.get("whois", {}).get("nameservers", []):
                if ns not in ns_to_domains:
                    ns_to_domains[ns] = []
                ns_to_domains[ns].append(domain)

        for ns, domains in ns_to_domains.items():
            if len(domains) >= 2:
                clusters.append({
                    "type": "shared_nameserver",
                    "nameserver": ns,
                    "domains": domains,
                    "description": (
                        f"Domains sharing nameserver {ns}: "
                        f"{', '.join(domains)}"
                    ),
                })

        return clusters

    def _is_valid_public_ip(self, value: str) -> bool:
        if not value:
            return False
        try:
            ip = ipaddress.ip_address(value.strip())
            return (
                not ip.is_private
                and not ip.is_loopback
                and not ip.is_multicast
                and not ip.is_reserved
                and ip.version == 4
            )
        except ValueError:
            return False

    def _is_valid_domain(self, value: str) -> bool:
        if not value or len(value) < 4:
            return False
        if "." not in value:
            return False
        if value.endswith(".onion"):
            return False
        pattern = re.compile(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
        )
        return bool(pattern.match(value))


async def enrich_with_dns(entities: list[dict]) -> dict:
    """
    Main entry point for DNS/WHOIS enrichment.
    Takes extracted entities, returns enrichment results including new entities.
    """
    enabled = os.getenv("DNS_ENRICHMENT_ENABLED", "true").lower() == "true"

    if not enabled:
        logger.info("DNS enrichment disabled")
        return {
            "ip_enrichments": {},
            "domain_enrichments": {},
            "new_entities": [],
            "infrastructure_clusters": [],
        }

    if not entities:
        return {
            "ip_enrichments": {},
            "domain_enrichments": {},
            "new_entities": [],
            "infrastructure_clusters": [],
        }

    async with DNSEnrichment() as enricher:
        return await enricher.enrich_entities(entities)
