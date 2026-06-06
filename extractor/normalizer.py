"""
extractor/normalizer.py — Entity deduplication and canonical record merging.

The same wallet address may appear in 50 pages; it gets one NormalizedEntity
per call to normalize_entities() (deduped by canonical value within that call).
merge_with_db() upserts records to the DB and returns the assigned IDs.

Public interface
----------------
normalize_entities(raw_entities, page_url, page_id) → list[NormalizedEntity]
merge_with_db(entities, investigation_id)            → list  (DB IDs / empty)
resolve_entity_type_conflicts(entities)             → list  (deduped by canonical value)
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List
import uuid

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical type priority for conflict resolution
# Lower number = higher specificity, wins in conflicts
# ---------------------------------------------------------------------------

TYPE_PRIORITY = {
    "CVE": 1,
    "MITRE_TECHNIQUE": 1,
    "FILE_HASH_SHA256": 1,
    "FILE_HASH_SHA1": 1,
    "FILE_HASH_MD5": 1,
    "IP_ADDRESS": 1,
    "ONION_URL": 1,
    "BITCOIN_ADDRESS": 2,
    "MONERO_ADDRESS": 2,
    "ETH_ADDRESS": 2,
    "RANSOMWARE_GROUP": 3,
    "THREAT_ACTOR": 3,
    "MALWARE_FAMILY": 3,
    "EMAIL_ADDRESS": 4,
    "PGP_KEY_BLOCK": 4,
    "DOMAIN": 5,
    "ORGANIZATION_NAME": 6,
    "PERSON_NAME": 6,
    "LOCATION": 7,
}
DEFAULT_PRIORITY = 99

# Tiebreak order when types have equal priority
TIEBREAK_ORDER = [
    "RANSOMWARE_GROUP",
    "THREAT_ACTOR",
    "MALWARE_FAMILY",
    "FILE_HASH_SHA256",
    "FILE_HASH_SHA1",
    "FILE_HASH_MD5",
    "CVE",
    "MITRE_TECHNIQUE",
    "IP_ADDRESS",
    "ONION_URL",
    "EMAIL_ADDRESS",
    "PGP_KEY_BLOCK",
    "BITCOIN_ADDRESS",
    "MONERO_ADDRESS",
    "ETH_ADDRESS",
    "DOMAIN",
    "ORGANIZATION_NAME",
    "PERSON_NAME",
    "LOCATION",
]


def _get_priority(entity_type: str) -> int:
    return TYPE_PRIORITY.get(entity_type, DEFAULT_PRIORITY)


def _get_tiebreak_rank(entity_type: str) -> int:
    try:
        return TIEBREAK_ORDER.index(entity_type)
    except ValueError:
        return len(TIEBREAK_ORDER)


def resolve_entity_type_conflicts(entities: list) -> list:
    """
    Resolve entity type conflicts by keeping only the most specific type
    for each unique canonical value.

    When the same value appears with multiple types:
    - Lower TYPE_PRIORITY wins (higher specificity)
    - Equal priority resolved by TIEBREAK_ORDER
    """
    value_to_entities: dict[str, list] = {}
    for entity in entities:
        key = entity.value.lower()
        if key not in value_to_entities:
            value_to_entities[key] = []
        value_to_entities[key].append(entity)

    resolved = []
    for value_lower, group in value_to_entities.items():
        if len(group) == 1:
            resolved.append(group[0])
            continue

        type_to_entity = {}
        for entity in group:
            et = entity.entity_type
            if et not in type_to_entity:
                type_to_entity[et] = entity
            else:
                existing = type_to_entity[et]
                if entity.confidence > existing.confidence:
                    type_to_entity[et] = entity

        conflicting_types = list(type_to_entity.keys())
        if len(conflicting_types) == 1:
            resolved.append(type_to_entity[conflicting_types[0]])
            continue

        def _sort_key(t):
            return (_get_priority(t), _get_tiebreak_rank(t))

        conflicting_types.sort(key=_sort_key)
        winner_type = conflicting_types[0]
        winner = type_to_entity[winner_type]

        logger.debug(
            f"Type conflict: '{winner.value}' resolved from {conflicting_types} to {winner_type}"
        )
        resolved.append(winner)

    return resolved


def _validate_hash_length(entity_type: str, value: str) -> bool:
    """Validate that a hash entity has the correct length for its type."""
    if entity_type == "FILE_HASH_MD5":
        return len(value) == 32 and re.fullmatch(r"[0-9a-fA-F]{32}", value) is not None
    elif entity_type == "FILE_HASH_SHA1":
        return len(value) == 40 and re.fullmatch(r"[0-9a-fA-F]{40}", value) is not None
    elif entity_type == "FILE_HASH_SHA256":
        return len(value) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None
    return True


def _validate_onion_url(value: str) -> bool:
    """Return True only if value is a valid .onion address."""
    value = value.lower().strip()
    if not value.endswith(".onion") and ".onion/" not in value:
        return False
    _ONION_PATTERN = re.compile(r'^(https?://)?[a-z2-7]{16,56}\.onion(/.*)?$')
    return bool(_ONION_PATTERN.match(value))


# ---------------------------------------------------------------------------
# Confidence scores by extraction source (inferred from entity_type)
# ---------------------------------------------------------------------------

_REGEX_TYPES: frozenset[str] = frozenset({
    "BITCOIN_ADDRESS",
    "ETHEREUM_ADDRESS",
    "MONERO_ADDRESS",
    "ONION_URL",
    "EMAIL_ADDRESS",
    "PGP_KEY_BLOCK",
    "CVE_NUMBER",
    "FILE_HASH_MD5",
    "FILE_HASH_SHA1",
    "FILE_HASH_SHA256",
    "IP_ADDRESS",
    "PHONE_NUMBER",
    "PASTE_URL",
    "MITRE_TECHNIQUE",
})

_NER_TYPES: frozenset[str] = frozenset({
    "THREAT_ACTOR_HANDLE",
    "MALWARE_FAMILY",
    "RANSOMWARE_GROUP",
    "ORGANIZATION_NAME",
})


def _confidence_for(entity_type: str) -> float:
    if entity_type in _REGEX_TYPES:
        return 1.0
    if entity_type in _NER_TYPES:
        return 0.85
    return 0.75


def _extraction_method_for(entity_type: str) -> str:
    if entity_type in _REGEX_TYPES:
        return "regex"
    if entity_type in _NER_TYPES:
        return "NER"
    return "LLM"


def _context_snippet(page_text: str, needle: str, max_len: int = 2000) -> str:
    """Return a window of *page_text* around *needle* for analyst / stylometry context."""
    try:
        if not page_text or not needle:
            return ""
        idx = page_text.find(needle)
        if idx < 0:
            idx = page_text.lower().find(needle.lower())
        if idx < 0:
            return ""
        half = max_len // 2
        start = max(0, idx - half)
        end = min(len(page_text), start + max_len)
        return page_text[start:end].strip()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Blocklist (NER / LLM only — regex types bypass; see normalize_entities)
# ---------------------------------------------------------------------------

ENTITY_BLOCKLIST: frozenset[str] = frozenset({
    "bitcoin", "btc", "ethereum", "eth", "monero", "xmr", "litecoin", "ltc",
    "dogecoin", "doge", "dash", "zcash", "zec", "ripple", "xrp", "usdt",
    "tether", "usdc", "bnb", "solana", "sol",
    "darknet", "dark web", "darkweb", "deep web", "tor", "onion",
    "marketplace", "market", "shop", "store", "vendor",
    "interface", "server", "client", "host", "system", "network",
    "database", "application", "service", "api", "endpoint",
    "stop", "start", "end", "new", "old", "free", "paid", "pro", "basic",
    "admin", "user", "root", "guest", "test", "demo",
    "h4ck3r", "h4cker", "hax0r", "haxor", "1337", "leet", "elite",
    "noob", "n00b", "script", "scriptkiddie", "skid",
    "vproxy", "proxychains", "nmap", "metasploit", "burpsuite",
    "cobalt", "covenant", "empire", "mimikatz", "lazagne", "pypykatz",
    "identities", "identity", "workflows", "workflow", "process",
    "processes", "services", "service", "systems", "system",
    "network", "networks", "access", "accounts", "account",
    "platform", "platforms", "solution", "solutions",
    "interface", "interfaces", "backend", "frontend",
    "resources", "resource", "project", "projects",
    "community", "communities", "member", "members",
    "moderator", "administrator", "operator", "staff", "support",
    "customer", "vendor", "buyer", "seller", "trader",
    "dropper", "loader", "stager", "payload", "beacon",
})

KNOWN_TOOLS: frozenset[str] = frozenset({
    "nmap", "metasploit", "cobaltstr", "cobaltstrike", "empire",
    "covenant", "brute", "hydra", "sqlmap", "nikto", "burp",
    "wireshark", "tcpdump", "netcat", "nc", "vproxy", "proxifier",
    "tor", "torbrowser", "onionbrowser", "i2p", "freenet",
    "kali", "parrot", "blackarch", "backtrack",
})

LEET_GENERIC = re.compile(r"^h[4a][ck]+[3e]?r?$")


ENTITY_MIN_LENGTH: dict[str, int] = {
    "THREAT_ACTOR_HANDLE": 4,
    "MALWARE_FAMILY": 3,
    "RANSOMWARE_GROUP": 4,
    "ORGANIZATION_NAME": 4,
    "BITCOIN_ADDRESS": 10,
    "ETHEREUM_ADDRESS": 10,
    "MONERO_ADDRESS": 10,
    "ONION_URL": 16,
    "EMAIL_ADDRESS": 6,
    "CVE_NUMBER": 9,
    "IP_ADDRESS": 7,
    "PGP_KEY_BLOCK": 8,
    "PASTE_URL": 10,
}


def normalize_wallet_value(value: str) -> str:
    """Normalize wallet addresses for deduplication (Ethereum compared lowercase)."""
    value = value.strip()
    if value.startswith("0x"):
        return value.lower()
    return value


def is_blocked_entity(entity_type: str, entity_value: str) -> bool:
    """
    Returns True if an entity should be filtered as noise (NER/LLM only).
    Regex-extracted entities must not use this — their patterns are precise.
    """
    value_lower = entity_value.lower().strip()

    if value_lower in ENTITY_BLOCKLIST:
        return True

    if entity_type == "THREAT_ACTOR_HANDLE":
        if value_lower in KNOWN_TOOLS:
            return True
        if LEET_GENERIC.match(value_lower):
            return True

    min_len = ENTITY_MIN_LENGTH.get(entity_type, 3)
    if len(value_lower) < min_len:
        return True

    norm_num = value_lower.replace(".", "").replace(",", "")
    if norm_num.isnumeric():
        return True

    return False


# ---------------------------------------------------------------------------
# NormalizedEntity dataclass
# ---------------------------------------------------------------------------


@dataclass
class NormalizedEntity:
    entity_type: str
    value: str
    confidence: float
    source_url: str
    page_id: Optional[uuid.UUID]
    context_snippet: str = field(default="")
    extraction_method: str = field(default="")


# ---------------------------------------------------------------------------
# Normalization rules per entity type
# ---------------------------------------------------------------------------


def _normalize_value(entity_type: str, value: str) -> str:
    """
    Return the canonical form of *value* for a given *entity_type*.
    Never raises — on any error returns the value stripped of leading/trailing
    whitespace.
    """
    try:
        if entity_type == "BITCOIN_ADDRESS":
            if value.lower().startswith("bc1"):
                return value.lower()
            return value

        if entity_type == "ETHEREUM_ADDRESS":
            return _eth_checksum(value)

        if entity_type == "EMAIL_ADDRESS":
            return value.lower()

        if entity_type == "CVE_NUMBER":
            return value.upper()

        if entity_type == "MITRE_TECHNIQUE":
            return value.upper()

        if entity_type in ("FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"):
            return value.lower()

        if entity_type == "ONION_URL":
            try:
                from crawler.utils import normalize_url
                return normalize_url(value)
            except Exception:
                parsed_lower = value.lower()
                return parsed_lower

        stripped = value.strip()
        return re.sub(r"\s+", " ", stripped)

    except Exception:
        return value.strip()


# ---------------------------------------------------------------------------
# Web3 availability check (import once at module load)
# ---------------------------------------------------------------------------

try:
    from web3 import Web3

    Web3.to_checksum_address("0x" + "0" * 40)
    WEB3_AVAILABLE = True
except Exception:
    WEB3_AVAILABLE = False


def _eth_checksum(addr: str) -> str:
    """
    Apply EIP-55 mixed-case checksum encoding to an Ethereum address.
    Falls back to lowercase if web3 is unavailable or checksum fails.
    """
    if not addr:
        return ""

    addr = addr.strip()
    if not addr.startswith("0x") or len(addr) != 42:
        return addr.lower()

    if not WEB3_AVAILABLE:
        return addr.lower()

    try:
        from web3 import Web3

        return Web3.to_checksum_address(addr)
    except ValueError:
        return addr.lower()
    except Exception:
        return addr.lower()


def canonicalize_entity_value(entity_type: str, value: str) -> str:
    """
    Produce a canonical form of an entity value for deduplication.
    The canonical form is used as the dedup key — NOT stored as the display value.
    The original casing/formatting is preserved for display.
    """
    if not value:
        return (value or "").lower().strip()

    v = value.strip()

    if entity_type in ("THREAT_ACTOR", "MALWARE", "FORUM", "THREAT_ACTOR_HANDLE", "MALWARE_FAMILY", "RANSOMWARE_GROUP"):
        v = unicodedata.normalize("NFKD", v)
        v = v.encode("ascii", "ignore").decode("ascii")
        v = v.lower()
        v = re.sub(r"[\s\-_\.]", "", v)
        v = re.sub(r"[^\w]", "", v)
        return v

    elif entity_type in ("WALLET", "BITCOIN_ADDRESS", "ETHEREUM_ADDRESS", "MONERO_ADDRESS"):
        if v.startswith("0x"):
            return v.lower()
        if v.startswith("4") and len(v) in (95, 106):
            return v.lower()
        return v.strip()

    elif entity_type in ("CVE", "CVE_NUMBER"):
        v = v.upper().strip()
        v = re.sub(r"\s+", "-", v)
        return v

    elif entity_type in ("FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"):
        return v.lower()

    elif entity_type == "MITRE_TECHNIQUE":
        return v.upper().strip()

    elif entity_type in ("EMAIL", "EMAIL_ADDRESS"):
        return v.lower().strip()

    elif entity_type == "ONION_URL":
        v = v.lower().rstrip("/")
        v = re.sub(r"^https://", "http://", v)
        return v

    elif entity_type in ("PGP_KEY", "PGP_KEY_BLOCK"):
        normalized = re.sub(r"\s+", "", v).upper()
        return "pgp:" + hashlib.sha256(normalized.encode()).hexdigest()

    else:
        v = v.lower().strip()

    return v[:1024]


def are_same_entity(type_a: str, value_a: str, type_b: str, value_b: str) -> bool:
    """Returns True if two entities should be considered the same."""
    if type_a != type_b:
        return False
    return canonicalize_entity_value(type_a, value_a) == canonicalize_entity_value(type_b, value_b)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def normalize_entities(
    raw_entities: dict[str, list[str]],
    page_url: str,
    page_id: Optional[uuid.UUID] = None,
    page_text: Optional[str] = None,
) -> list[NormalizedEntity]:
    """
    Convert raw extraction results into deduplicated NormalizedEntity records.
    """
    seen_values: set[str] = set()
    result: list[NormalizedEntity] = []

    tool_count = 0
    generic_count = 0
    leet_count = 0
    noise_count = 0

    for entity_type, values in raw_entities.items():
        confidence = _confidence_for(entity_type)
        for raw_value in values:
            if not raw_value or not raw_value.strip():
                continue

            if entity_type in ("FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"):
                if not _validate_hash_length(entity_type, raw_value):
                    logger.debug(
                        f"Hash length validation failed for {entity_type}={raw_value}"
                    )
                    continue

            if entity_type == "ONION_URL":
                if not _validate_onion_url(raw_value):
                    logger.debug("ONION_URL discarded (not a valid onion address): %r", raw_value)
                    continue

            canonical = _normalize_value(entity_type, raw_value)
            if not canonical:
                continue

            if entity_type not in _REGEX_TYPES:
                value_lower = canonical.lower()
                if is_blocked_entity(entity_type, canonical):
                    if entity_type == "THREAT_ACTOR_HANDLE" and value_lower in KNOWN_TOOLS:
                        tool_count += 1
                    elif entity_type == "THREAT_ACTOR_HANDLE" and LEET_GENERIC.match(value_lower):
                        leet_count += 1
                    elif value_lower in ENTITY_BLOCKLIST:
                        generic_count += 1
                    else:
                        noise_count += 1

                    logger.debug(
                        "Filtered blocked entity: %s=%s", entity_type, canonical
                    )
                    continue

            dedup_key = f"{entity_type}::{canonical}"
            if dedup_key in seen_values:
                continue
            seen_values.add(dedup_key)
            snip = _context_snippet(page_text, canonical) if page_text else ""
            result.append(
                NormalizedEntity(
                    entity_type=entity_type,
                    value=canonical,
                    confidence=confidence,
                    source_url=page_url,
                    page_id=page_id,
                    context_snippet=snip,
                    extraction_method=_extraction_method_for(entity_type),
                )
            )

    total_filtered = tool_count + leet_count + generic_count + noise_count
    if total_filtered:
        logger.warning(
            f"Entity blocklist filtered {total_filtered} entities "
            f"(tool_names={tool_count}, generic_terms={generic_count}, "
            f"leet_generic={leet_count}, NER/LLM noise={noise_count})"
        )

    return result


def merge_with_db(
    entities: list[NormalizedEntity],
    investigation_id: Optional[uuid.UUID] = None,
) -> list:
    """
    Upsert each entity to the DB entities table using canonical deduplication.
    Returns a list of DB-assigned entity IDs (as strings).
    """
    if not os.getenv("DATABASE_URL"):
        logger.warning(
            "DATABASE_URL not set — skipping DB persist (%d entities)", len(entities)
        )
        return []

    if not entities:
        return []

    ids: list = []
    new_count = 0
    dedup_count = 0

    try:
        from db.session import get_session
        from db.queries import upsert_entity_canonical, create_page, get_page_by_url

        with get_session() as session:
            page_cache: dict[str, object] = {}

            for entity in entities:
                url = entity.source_url
                if url not in page_cache:
                    page = get_page_by_url(session, url)
                    if page is None:
                        page = create_page(session, url=url)
                    page_cache[url] = page

                page = page_cache[url]

                db_entity, created = upsert_entity_canonical(
                    session=session,
                    investigation_id=investigation_id,
                    entity_type=entity.entity_type,
                    entity_value=entity.value,
                    confidence=entity.confidence,
                    source_page_id=page.id,
                    context_snippet=entity.context_snippet,
                    extraction_method=entity.extraction_method or None,
                )

                if created:
                    new_count += 1
                else:
                    dedup_count += 1

                ids.append(str(db_entity.id))

            session.commit()
            if investigation_id:
                logger.warning(
                    f"[{investigation_id}] Entity dedup: {new_count} new, {dedup_count} merged with existing"
                )

    except Exception as exc:
        logger.warning("merge_with_db failed: %s", exc)
        return []

    return ids