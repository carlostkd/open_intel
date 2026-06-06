"""
extractor/regex_patterns.py — Pre-compiled regex patterns for entity extraction.

All patterns are compiled at module load time.  No pattern is ever compiled
inside a function call.

Public interface
----------------
extract_all(text)           → dict[str, list[str]]
extract_type(text, entity_type) → list[str]   raises ValueError on unknown type

Entity type constants are exported so callers can use them symbolically
(e.g. regex_patterns.BITCOIN_ADDRESS) rather than raw strings.
"""

from __future__ import annotations

import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Entity type constants
# ---------------------------------------------------------------------------

BITCOIN_ADDRESS = "BITCOIN_ADDRESS"
ETHEREUM_ADDRESS = "ETHEREUM_ADDRESS"
MONERO_ADDRESS = "MONERO_ADDRESS"
ONION_URL = "ONION_URL"
EMAIL_ADDRESS = "EMAIL_ADDRESS"
PGP_KEY_BLOCK = "PGP_KEY_BLOCK"
CVE_NUMBER = "CVE_NUMBER"
IP_ADDRESS = "IP_ADDRESS"
PHONE_NUMBER = "PHONE_NUMBER"
PASTE_URL = "PASTE_URL"
FILE_HASH_MD5 = "FILE_HASH_MD5"
FILE_HASH_SHA1 = "FILE_HASH_SHA1"
FILE_HASH_SHA256 = "FILE_HASH_SHA256"
MITRE_TECHNIQUE = "MITRE_TECHNIQUE"

ENTITY_TYPES: frozenset[str] = frozenset({
    BITCOIN_ADDRESS,
    ETHEREUM_ADDRESS,
    MONERO_ADDRESS,
    ONION_URL,
    EMAIL_ADDRESS,
    PGP_KEY_BLOCK,
    CVE_NUMBER,
    IP_ADDRESS,
    PHONE_NUMBER,
    PASTE_URL,
    FILE_HASH_MD5,
    FILE_HASH_SHA1,
    FILE_HASH_SHA256,
    MITRE_TECHNIQUE,
})

# ---------------------------------------------------------------------------
# Pre-compiled regex patterns
# ---------------------------------------------------------------------------

# Bitcoin — three formats, all word-bounded:
#   Bech32 (native segwit):  bc1 + bech32 charset, 25-62 chars
#   P2PKH legacy:            starts with 1, base58 charset, 25-34 chars
#   P2SH:                    starts with 3, base58 charset, 25-34 chars
_BITCOIN_RE = re.compile(
    r"\b(?:"
    r"bc1[a-zA-HJ-NP-Z0-9]{25,62}"
    r"|1[a-km-zA-HJ-NP-Z1-9]{25,34}"
    r"|3[a-km-zA-HJ-NP-Z1-9]{25,34}"
    r")\b"
)

# Ethereum — 0x + exactly 40 hex chars, word-bounded to exclude longer hex blobs
_ETHEREUM_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# Monero — starts with 4, second char in [0-9AB], 93 base58 chars, total 95
_MONERO_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# Onion URLs — full URL (http/https + path) tried before bare hostname so the
# longer form is preferred by re.finditer when both would match the same text.
_ONION_RE = re.compile(
    r"https?://[a-z2-7]{16,56}\.onion(?:/[^\s\"'<>]*)?"
    r"|[a-z2-7]{16,56}\.onion(?:/[^\s\"'<>]*)?",
    re.IGNORECASE,
)

# Email — simplified RFC 5322.  Leading/trailing-dot and consecutive-dot
# validation is done in _is_valid_email() rather than in the regex itself
# to keep the pattern readable.
_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9][a-zA-Z0-9._%+\-]*@[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}\b"
)

# PGP — full armored block (multiline, lazy inner match)
_PGP_BLOCK_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)

# PGP — colon-separated fingerprint: 20 groups of exactly 2 hex chars
# e.g. AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01
# Also space-separated (with or without spaces): ABCD 1234 ABCD 1234...
_PGP_FINGERPRINT_RE = re.compile(
    r"\b[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){19}\b|"
    r"\b[0-9A-F]{4}(?:\s?[0-9A-F]{4}){9}\b",
    re.IGNORECASE,
)

# PGP — explicit fingerprint keyword context (within 50 chars of hex string)
_PGP_CONTEXT_RE = re.compile(
    r"fingerprint[\s:]{0,50}[0-9A-Fa-f]{40}"
)

# MD5 — exactly 32 hex chars, word-bounded
_FILE_HASH_MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")

# SHA1 — exactly 40 hex chars, word-bounded (used to exclude from PGP)
_FILE_HASH_SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")

# SHA256 — exactly 64 hex chars, word-bounded
_FILE_HASH_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")

# CVE — case insensitive; 4-digit year + 4-7 digit ID
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# MITRE ATT&CK technique — T + 4 digits, optional . + 3 sub-technique digits
# e.g. T1486, T1071.001, T1059.003 (case-insensitive)
_MITRE_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# IPv4 — strict octet ranges (0-255), word-bounded.
# RFC1918/loopback filtering happens in _is_public_ip() — not in regex.
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Phone — E.164 (+[1-9] then 6-14 digits) captures most international formats.
_PHONE_RE = re.compile(r"\+[1-9]\d{6,14}\b")

# Paste site URLs — known domains only, full URL required
_PASTE_DOMAINS = (
    r"(?:pastebin\.com|rentry\.co|ghostbin\.com|paste\.ee"
    r"|hastebin\.com|privatebin\.net|bin\.bini\.monster)"
)
_PASTE_RE = re.compile(
    rf"https?://(?:www\.)?{_PASTE_DOMAINS}/[^\s\"'<>]*",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Private IP ranges to exclude (RFC1918 + loopback)
# ---------------------------------------------------------------------------

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_public_ip(addr: str) -> bool:
    """Return True if *addr* is a syntactically valid, non-private IPv4 address."""
    try:
        ip = ipaddress.ip_address(addr)
        return not any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _is_valid_email(email: str) -> bool:
    """Return False for emails with consecutive dots or leading/trailing dots."""
    local, _, domain = email.partition("@")
    if ".." in local or ".." in domain:
        return False
    if local.startswith(".") or local.endswith("."):
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    return True


def _findall(pattern: re.Pattern, text: str) -> list[str]:
    """Return all non-overlapping matches as full-match strings."""
    return [m.group(0) for m in pattern.finditer(text)]


def _dedup(values) -> list[str]:
    """Deduplicate while preserving first-occurrence order."""
    seen: set[str] = set()
    result: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result


# ---------------------------------------------------------------------------
# Per-type extractor lambdas (used by extract_type)
# ---------------------------------------------------------------------------

def _extract_bitcoin(text: str) -> list[str]:
    return _dedup(_findall(_BITCOIN_RE, text))


def _extract_ethereum(text: str) -> list[str]:
    return _dedup(_findall(_ETHEREUM_RE, text))


def _extract_monero(text: str) -> list[str]:
    return _dedup(_findall(_MONERO_RE, text))


def _extract_onion(text: str) -> list[str]:
    return _dedup(_findall(_ONION_RE, text))


def _extract_email(text: str) -> list[str]:
    return _dedup(m for m in _findall(_EMAIL_RE, text) if _is_valid_email(m))


def _extract_pgp(text: str) -> list[str]:
    blocks = _findall(_PGP_BLOCK_RE, text)
    fingerprints = _findall(_PGP_FINGERPRINT_RE, text)
    context_hits = _findall(_PGP_CONTEXT_RE, text)
    sha1_hashes = set(_findall(_FILE_HASH_SHA1_RE, text))
    result = []
    for h in blocks:
        if h not in sha1_hashes:
            result.append(h)
    for h in fingerprints:
        if h not in sha1_hashes:
            result.append(h)
    for h in context_hits:
        result.append(h)
    return _dedup(result)


def _extract_md5(text: str) -> list[str]:
    return _dedup(_findall(_FILE_HASH_MD5_RE, text))


def _extract_sha1(text: str) -> list[str]:
    return _dedup(_findall(_FILE_HASH_SHA1_RE, text))


def _extract_sha256(text: str) -> list[str]:
    return _dedup(_findall(_FILE_HASH_SHA256_RE, text))


def _extract_cve(text: str) -> list[str]:
    return _dedup(m.upper() for m in _findall(_CVE_RE, text))


def _extract_mitre(text: str) -> list[str]:
    return _dedup(m.upper() for m in _findall(_MITRE_TECHNIQUE_RE, text))


def _extract_ip(text: str) -> list[str]:
    return _dedup(m for m in _findall(_IP_RE, text) if _is_public_ip(m))


def _extract_phone(text: str) -> list[str]:
    return _dedup(_findall(_PHONE_RE, text))


def _extract_paste(text: str) -> list[str]:
    return _dedup(_findall(_PASTE_RE, text))


_EXTRACTORS: dict[str, object] = {
    BITCOIN_ADDRESS: _extract_bitcoin,
    ETHEREUM_ADDRESS: _extract_ethereum,
    MONERO_ADDRESS: _extract_monero,
    ONION_URL: _extract_onion,
    EMAIL_ADDRESS: _extract_email,
    PGP_KEY_BLOCK: _extract_pgp,
    FILE_HASH_MD5: _extract_md5,
    FILE_HASH_SHA1: _extract_sha1,
    FILE_HASH_SHA256: _extract_sha256,
    CVE_NUMBER: _extract_cve,
    MITRE_TECHNIQUE: _extract_mitre,
    IP_ADDRESS: _extract_ip,
    PHONE_NUMBER: _extract_phone,
    PASTE_URL: _extract_paste,
}

# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def extract_all(text: str) -> dict[str, list[str]]:
    """
    Run all entity patterns against *text*.

    Returns a dict keyed by entity-type constant.  Every key is always present;
    types with no matches map to an empty list.  Never raises.
    """
    result: dict[str, list[str]] = {}
    try:
        for entity_type, extractor in _EXTRACTORS.items():
            result[entity_type] = extractor(text)  # type: ignore[operator]
    except Exception:
        logger.exception("extract_all encountered an unexpected error")
        for entity_type in ENTITY_TYPES:
            result.setdefault(entity_type, [])
    return result


def extract_type(text: str, entity_type: str) -> list[str]:
    """
    Extract a single entity type from *text*.

    Raises ValueError for unknown entity_type.
    """
    if entity_type not in _EXTRACTORS:
        raise ValueError(
            f"Unknown entity type {entity_type!r}. "
            f"Valid types: {sorted(ENTITY_TYPES)}"
        )
    return _EXTRACTORS[entity_type](text)  # type: ignore[operator]