"""
Import seed data into Open_Intel database on first run.
Called from docker-entrypoint.sh if DB is empty.
"""

import gzip
import json
import logging
import sys
import uuid
from datetime import datetime, timezone

from db.session import get_session
from db.models import Investigation, Entity, Page
from extractor.normalizer import canonicalize_entity_value
from db.queries import upsert_entity_canonical

logger = logging.getLogger(__name__)
SEED_FILE = "/data/seed_data.json.gz"
SEED_FLAG_QUERY = "SELECT COUNT(*) FROM investigations WHERE is_seed = TRUE"

def get_or_create_seed_context(session, name: str) -> tuple[Investigation, uuid.UUID]:
    """Create a special seed investigation, source, and page for the seed data."""
    # 1. Investigation
    inv = Investigation(
        query=f"__seed__{name}__",
        run_id=uuid.uuid4(),
        status="completed",
        summary=f"Historical seed data from {name}",
        is_seed=True,
    )
    session.add(inv)
    session.flush()
    
    # 2. Source
    from db.models import Source, SourceType, SourceStatus
    source_addr = f"seed.{name}.internal"
    source = session.query(Source).filter_by(onion_address=source_addr).first()
    if not source:
        source = Source(
            onion_address=source_addr,
            source_type=SourceType.SEED,
            status=SourceStatus.ACTIVE,
        )
        session.add(source)
        session.flush()
        
    # 3. Page
    from db.models import Page
    page_url = f"open_intel://seed/{name}"
    page = session.query(Page).filter_by(url=page_url).first()
    if not page:
        page = Page(
            url=page_url,
            source_id=source.id,
            cleaned_text=f"Seed data from {name}",
        )
        session.add(page)
        session.flush()
        
    return inv, page.id


def is_already_seeded(session) -> bool:
    """Check if seed data has already been imported using DB records."""
    try:
        from sqlalchemy import text
        result = session.execute(
            text("SELECT COUNT(*) FROM investigations WHERE query LIKE '__seed__%'")
        ).scalar()
        return (result or 0) > 0
    except Exception as e:
        logger.error(f"Error checking seed status: {e}")
        return False




def import_ransomware_victims(session, victims: list[dict]) -> int:
    """
    Import ransomware victims as threat actor + victim org entity pairs.
    """
    if not victims:
        return 0
        
    inv, page_id = get_or_create_seed_context(session, "ransomware_live")
    count = 0
    
    for victim in victims:
        group = victim.get("threat_actor", "").strip()
        victim_name = victim.get("victim_name", "").strip()
        
        if group and len(group) >= 2:
            upsert_entity_canonical(
                session=session,
                investigation_id=inv.id,
                entity_type="THREAT_ACTOR",
                entity_value=group,
                confidence=0.95,
                source_page_id=page_id,
                context_snippet=f"Ransomware group. Victims: {victim_name}",
            )
            count += 1
        
        if victim_name and len(victim_name) >= 2:
            upsert_entity_canonical(
                session=session,
                investigation_id=inv.id,
                entity_type="THREAT_ACTOR",
                entity_value=victim_name,
                confidence=0.90,
                source_page_id=page_id,
                context_snippet=f"Ransomware victim of {group}. Sector: {victim.get('sector','')}",
            )
            count += 1
    
    session.commit()
    logger.warning(f"Imported {count} entities from Ransomware.live ({len(victims)} victims)")
    return count


def import_threatfox_iocs(session, iocs: list[dict]) -> int:
    """Import ThreatFox IOCs as typed entities."""
    if not iocs:
        return 0
        
    inv, page_id = get_or_create_seed_context(session, "threatfox")
    count = 0
    
    # Map ThreatFox IOC types to Open_Intel entity types
    TYPE_MAP = {
        "ip:port": "IP",
        "domain": "ONION_URL",
        "url": "PASTE_URL",
        "md5_hash": "MALWARE",
        "sha256_hash": "MALWARE",
        "sha1_hash": "MALWARE",
        "btc_address": "WALLET",
        "xmr_address": "WALLET",
    }
    
    for ioc in iocs:
        ioc_type = (ioc.get("ioc_type") or "").lower()
        entity_type = TYPE_MAP.get(ioc_type)
        value = ioc.get("value", "").strip()
        
        if not entity_type or not value:
            continue
        
        upsert_entity_canonical(
            session=session,
            investigation_id=inv.id,
            entity_type=entity_type,
            entity_value=value,
            confidence=ioc.get("confidence", 0.75),
            source_page_id=page_id,
            context_snippet=f"ThreatFox IOC. Malware: {ioc.get('malware','')}. Tags: {', '.join(ioc.get('tags',[]))}",
        )
        count += 1
    
    session.commit()
    logger.warning(f"Imported {count} entities from ThreatFox ({len(iocs)} IOCs)")
    return count


def import_malwarebazaar(session, samples: list[dict]) -> int:
    """Import MalwareBazaar malware families as MALWARE entities."""
    if not samples:
        return 0
        
    inv, page_id = get_or_create_seed_context(session, "malwarebazaar")
    families_seen = set()
    count = 0
    
    for sample in samples:
        family = sample.get("malware_family", "").strip()
        if family and family not in families_seen and len(family) >= 2:
            families_seen.add(family)
            upsert_entity_canonical(
                session=session,
                investigation_id=inv.id,
                entity_type="MALWARE",
                entity_value=family,
                confidence=0.95,
                source_page_id=page_id,
                context_snippet=f"MalwareBazaar. Tags: {', '.join(sample.get('tags',[]))}",
            )
            count += 1
    
    session.commit()
    logger.warning(f"Imported {count} malware families from MalwareBazaar ({len(samples)} samples)")
    return count


def import_urlhaus_urls(session, urls: list[dict]) -> int:
    """Import URLhaus malicious URLs as PASTE_URL/ONION_URL entities."""
    if not urls:
        return 0
        
    inv, page_id = get_or_create_seed_context(session, "urlhaus")
    count = 0
    
    for u in urls:
        url_val = u.get("url", "").strip()
        if not url_val:
            continue
            
        entity_type = "ONION_URL" if ".onion" in url_val.lower() else "PASTE_URL"
        
        upsert_entity_canonical(
            session=session,
            investigation_id=inv.id,
            entity_type=entity_type,
            entity_value=url_val,
            confidence=0.80,
            source_page_id=page_id,
            context_snippet=f"URLhaus. Threat: {u.get('threat','unknown')}. Tags: {', '.join(u.get('tags',[]))}",
        )
        count += 1
    
    session.commit()
    logger.warning(f"Imported {count} entities from URLhaus ({len(urls)} URLs)")
    return count


def import_otx_pulses(session, pulses: list[dict]) -> int:
    """Import OTX subscribed pulse titles and malware family strings."""
    if not pulses:
        return 0

    inv, page_id = get_or_create_seed_context(session, "otx")
    count = 0

    for p in pulses:
        name = (p.get("pulse_name") or "").strip()
        if name and len(name) >= 3:
            upsert_entity_canonical(
                session=session,
                investigation_id=inv.id,
                entity_type="THREAT_ACTOR",
                entity_value=name[:500],
                confidence=0.85,
                source_page_id=page_id,
                context_snippet=f"OTX pulse. {(p.get('description') or '')[:1500]}",
            )
            count += 1

        mfs = p.get("malware_families") or []
        if not isinstance(mfs, list):
            continue
        for mf in mfs:
            if isinstance(mf, dict):
                s = (mf.get("name") or mf.get("display_name") or "").strip()
            else:
                s = str(mf).strip()
            if len(s) >= 2:
                upsert_entity_canonical(
                    session=session,
                    investigation_id=inv.id,
                    entity_type="MALWARE_FAMILY",
                    entity_value=s[:500],
                    confidence=0.82,
                    source_page_id=page_id,
                    context_snippet=f"Malware family from OTX pulse: {name[:200] if name else 'unknown'}",
                )
                count += 1

    session.commit()
    logger.warning(f"Imported {count} entities from OTX ({len(pulses)} pulses)")
    return count


def import_misp_galaxy(session, entries: list[dict]) -> int:
    """Import MISP galaxy threat actors and malware families."""
    if not entries:
        return 0

    inv, page_id = get_or_create_seed_context(session, "misp_galaxy")
    count = 0

    for entry in entries:
        name = (entry.get("name") or "").strip()
        entity_type = (entry.get("entity_type") or "THREAT_ACTOR").strip()

        if not name or len(name) < 3:
            continue

        upsert_entity_canonical(
            session=session,
            investigation_id=inv.id,
            entity_type=entity_type,
            entity_value=name,
            confidence=0.95,
            source_page_id=page_id,
            context_snippet=(
                f"MISP Galaxy entry. {entry.get('description', '')}"
                + (
                    f" Aliases: {', '.join(entry.get('aliases', []))}"
                    if entry.get("aliases")
                    else ""
                )
            )[:2000],
        )
        count += 1

        for alias in entry.get("aliases", []) or []:
            alias = str(alias).strip()
            if alias and len(alias) >= 3 and alias.lower() != name.lower():
                upsert_entity_canonical(
                    session=session,
                    investigation_id=inv.id,
                    entity_type=entity_type,
                    entity_value=alias,
                    confidence=0.90,
                    source_page_id=page_id,
                    context_snippet=f"Alias of {name}. MISP Galaxy entry.",
                )
                count += 1

    session.commit()
    logger.warning(f"Imported {count} entities from MISP Galaxy ({len(entries)} entries)")
    return count


def main():
    logging.basicConfig(level=logging.WARNING)
    
    with get_session() as session:
        if is_already_seeded(session):
            logger.warning("Seed data already imported — skipping")
            return
        
        logger.warning("=" * 50)
        logger.warning("Open_Intel: Importing historical seed data...")
        logger.warning("=" * 50)
        
        try:
            with gzip.open(SEED_FILE, "rb") as f:
                seed_data = json.loads(f.read().decode("utf-8"))
        except FileNotFoundError:
            logger.error(f"Seed file not found: {SEED_FILE}")
            logger.error("Run: python scripts/download_seed.py during Docker build")
            sys.exit(0) # Don't crash container
        except Exception as e:
            logger.error(f"Failed to load seed data: {e}")
            sys.exit(0)
        
        total = 0
        total += import_ransomware_victims(session, seed_data.get("ransomware_victims", []))
        total += import_threatfox_iocs(session, seed_data.get("threatfox_iocs", []))
        total += import_malwarebazaar(session, seed_data.get("malwarebazaar_samples", []))
        total += import_urlhaus_urls(session, seed_data.get("urlhaus_urls", []))
        total += import_otx_pulses(session, seed_data.get("otx_pulses", []))
        total += import_misp_galaxy(session, seed_data.get("misp_galaxy", []))
        
        logger.warning(f"Seed import complete: {total:,} total entities")
        logger.warning("=" * 50)


if __name__ == "__main__":
    main()
