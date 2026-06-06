"""
graph/model.py — Pure data definitions for the Open_Intel graph layer.

No graph logic here — only node/edge type constants and dataclasses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Node type constants
# ---------------------------------------------------------------------------


class NODE_TYPES:
    THREAT_ACTOR = "ThreatActor"
    CRYPTO_WALLET = "CryptoWallet"
    ONION_URL = "OnionURL"
    FORUM = "Forum"
    MALWARE_FAMILY = "MalwareFamily"
    RANSOMWARE_GROUP = "RansomwareGroup"
    PGP_KEY = "PGPKey"
    EMAIL_ADDRESS = "EmailAddress"
    CVE = "CVE"
    PASTE = "Paste"
    IP_ADDRESS = "IPAddress"
    PHONE_NUMBER = "PhoneNumber"
    ORGANIZATION = "Organization"
    DATE = "Date"


# ---------------------------------------------------------------------------
# Edge type constants
# ---------------------------------------------------------------------------


class EDGE_TYPES:
    CO_APPEARED_ON = "CO_APPEARED_ON"           # two entities on the same page
    POSTED_BY = "POSTED_BY"                     # content attributed to a handle
    LINKED_TO = "LINKED_TO"                     # URL links to URL
    MEMBER_OF = "MEMBER_OF"                     # handle to group/forum
    USED = "USED"                               # actor used a malware family
    CLAIMED = "CLAIMED"                         # group claimed an attack
    LIKELY_SAME_ACTOR = "LIKELY_SAME_ACTOR"     # inferred, medium confidence
    CONFIRMED_SAME_ACTOR = "CONFIRMED_SAME_ACTOR"  # PGP key match, high confidence
    CO_INVESTIGATION = "CO_INVESTIGATION"       # Entities found in same investigation across multiple pages
    PAID_TO = "PAID_TO"                         # financial transaction
    FUNDED_BY = "FUNDED_BY"                     # financial transaction



# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class GraphNode:
    """Represents a single entity node in the relationship graph."""

    node_id: str                        # canonical value (wallet address, handle, etc.)
    node_type: str                      # one of NODE_TYPES constants
    first_seen: datetime
    last_seen: datetime
    source_urls: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Represents a directed relationship edge in the graph."""

    source_id: str                      # node_id of the source node
    target_id: str                      # node_id of the target node
    edge_type: str                      # one of EDGE_TYPES constants
    confidence: float                   # 0.0–1.0
    source_url: str                     # page where the relationship was observed
    timestamp: datetime
    metadata: dict[str, Any] = field(default_factory=dict)
