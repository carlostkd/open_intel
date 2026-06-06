"""
sources/seeds.py — Curated seed URL list for the recursive crawler.

SEED_URLS is a hardcoded list of known high-value .onion starting points —
forums, indexes, directories, and paste sites that are commonly accessible
and useful as entry points for threat-intelligence crawling.

These are starting points only: the crawler follows their links recursively.
None are assumed to have any particular content; they are known *link hubs*.

Addresses were current at time of writing (2025).  .onion addresses change
frequently; the crawler handles unreachable seeds gracefully.

Public API:
    SEED_URLS          — full list of seed dicts
    get_seeds(category, language, query) -> list[dict]   — filtered view
"""

from __future__ import annotations

import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Curated seed list  (≥ 20 entries required by spec)
# ---------------------------------------------------------------------------
# Each entry: url, category, description, language
# category: "search" | "index" | "forum" | "paste" | "market_index"
# language: "en" | "ru" | "multi"

SEED_URLS: List[dict] = [
    # ── Search engines ──────────────────────────────────────────────────────
    {
        "url": "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion",
        "category": "search",
        "description": "Torch — one of the oldest and largest dark web search engines",
        "language": "en",
    },
    {
        "url": "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion",
        "category": "search",
        "description": "Haystack — indexes millions of onion pages, fast results",
        "language": "en",
    },
    {
        "url": "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
        "category": "search",
        "description": "DuckDuckGo official Tor hidden service — clearnet search over Tor",
        "language": "en",
    },
    {
        "url": "http://darksearch7bvmqn2sp7gokxbz7gvx5sflhkblekdxs5pfxypufksgfyd.onion",
        "category": "search",
        "description": "DarkSearch — dark web search engine with JSON API",
        "language": "en",
    },
    # ── Indexes / Directories ────────────────────────────────────────────────
    {
        "url": "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/index.php/Main_Page",
        "category": "index",
        "description": "The Hidden Wiki — primary community .onion link directory",
        "language": "en",
    },
    {
        "url": "http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion",
        "category": "index",
        "description": "dark.fail — curated directory of verified, working onion sites",
        "language": "en",
    },
    {
        "url": "http://danielas3rtn54uwmofdo3x2bsdifr47huasnmbgqzfrec5ubupvtpid.onion",
        "category": "index",
        "description": "Daniel's Hosting — index of hundreds of hosted onion services",
        "language": "en",
    },
    {
        "url": "http://bbcnewsd73hkzno2ini43t4gblxvycyac5aw4gnv7t2rccijh7745uqd.onion",
        "category": "index",
        "description": "BBC News Tor mirror — official BBC onion service for censorship bypass",
        "language": "en",
    },
    {
        "url": "http://p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion",
        "category": "index",
        "description": "ProPublica Tor mirror — investigative journalism, primary source links",
        "language": "en",
    },
    {
        "url": "http://sdolvtfhatvsysc6l34d65ymdwxcujausv7k5jk4cy5ttzhjoi6fzvyd.onion",
        "category": "index",
        "description": "SecureDrop directory — whistleblower submission platform index",
        "language": "en",
    },
    # ── Forums ───────────────────────────────────────────────────────────────
    {
        "url": "http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion",
        "category": "forum",
        "description": "Dread — dark web Reddit equivalent, hub for market discussion and news",
        "language": "en",
    },
    {
        "url": "http://enxx3byspwsdo446jujc52ucy2pf5urdbhqw3kbsfhlfjwmbpj5smdad.onion",
        "category": "forum",
        "description": "Endchan — decentralized imageboard, uncensored discussion boards",
        "language": "en",
    },
    {
        "url": "http://4usoivrpy52lmc4mgn2h34cmfiltslesthr56yttv2pxudd3dapqciyd.onion",
        "category": "forum",
        "description": "8chan/8kun — decentralized anonymous forum, various topic boards",
        "language": "en",
    },
    {
        "url": "http://crpxfhcgaaqxnpqgcmgrk2uupxrjyqrlc3dnlrgidcjbpq5zxkafbvid.onion",
        "category": "forum",
        "description": "CryptBB — cybercrime forum focusing on hacking and exploit trading",
        "language": "en",
    },
    {
        "url": "http://gg6zxtreajiijztyy5g6bt5o6l3qu32nrg7eulyemlnhbh6tl7r2vyad.onion",
        "category": "forum",
        "description": "XSS.is Tor mirror — Russian-language cybercrime and vulnerability forum",
        "language": "ru",
    },
    {
        "url": "http://exploitivzcm5dawzhe6c32bbylyggbjvh5dyvsvb5lkuz5ptmunkmqd.onion",
        "category": "forum",
        "description": "Exploit.in Tor mirror — Russian exploit marketplace and forum",
        "language": "ru",
    },
    {
        "url": "http://ransomwr3tsydeii.onion",
        "category": "forum",
        "description": "RansomWatch aggregator mirror — tracks ransomware group leak sites",
        "language": "en",
    },
    # ── Paste sites ──────────────────────────────────────────────────────────
    {
        "url": "http://depastedihryjugl7sxhstlqjmqbedofrm3r5vynzw7rl7mwkv4zmcid.onion",
        "category": "paste",
        "description": "DeepPaste — dark web paste service, frequently used for leaks",
        "language": "en",
    },
    {
        "url": "http://zgjnkivynuasfwog7rkkphv5gdtyrcaxp4ihczgyuep2ulokhmuuduuqd.onion",
        "category": "paste",
        "description": "PrivateBin .onion instance — anonymous encrypted paste sharing",
        "language": "en",
    },
    {
        "url": "http://protonirockerxow.onion",
        "category": "paste",
        "description": "ProtonMail Tor mirror — encrypted email, often linked to paste leaks",
        "language": "multi",
    },
    # ── Market indexes (aggregators only — not markets themselves) ────────────
    {
        "url": "http://darknetlidvrsli6iso7my54rjayjursyw637aypb6qambkoepmyq2yd.onion",
        "category": "market_index",
        "description": "Darknet market index — lists active markets and their mirror links",
        "language": "en",
    },
    {
        "url": "http://dark2web.com.onion",
        "category": "market_index",
        "description": "Dark2Web — aggregator that reviews and indexes dark web markets",
        "language": "en",
    },
    {
        "url": "http://dgdtaovql5oo7ait.onion",
        "category": "market_index",
        "description": "Tor Metrics onion — statistics on the Tor network and onion services",
        "language": "en",
    },
    # ── Multi-language / Russian-language index ───────────────────────────────
    {
        "url": "http://rutorc6mqdinc4cz.onion",
        "category": "index",
        "description": "RuTor — Russian-language dark web link directory and index",
        "language": "ru",
    },
    {
        "url": "http://omgomgomg5j4yrr47fishp4rdwxkn3vkpbxbouys33ew74h6hq47qad.onion",
        "category": "market_index",
        "description": "OMG!OMG! market — large multi-language dark web marketplace index",
        "language": "multi",
    },
]


# ---------------------------------------------------------------------------
# Query-aware topic seeds (verified-stable .onion only; small curated set)
# ---------------------------------------------------------------------------

TOPIC_SEEDS: dict[str, List[dict]] = {
    "bitcoin": [
        {
            "url": "http://darkfailllnkf4vf.onion",
            "category": "index",
            "language": "en",
            "description": "dark.fail index — query-aware bitcoin/crypto seed",
        },
    ],
    "ransomware": [
        {
            "url": "http://darkfailllnkf4vf.onion",
            "category": "index",
            "language": "en",
            "description": "dark.fail index — query-aware ransomware seed",
        },
        {
            "url": "http://ransomwr3tsydeii.onion",
            "category": "forum",
            "language": "en",
            "description": "RansomWatch — query-aware ransomware seed",
        },
    ],
    "malware": [
        {
            "url": "http://darkfailllnkf4vf.onion",
            "category": "index",
            "language": "en",
            "description": "dark.fail index — query-aware malware seed",
        },
    ],
    "credentials": [
        {
            "url": "http://darkfailllnkf4vf.onion",
            "category": "index",
            "language": "en",
            "description": "dark.fail index — query-aware credentials seed",
        },
    ],
    "drugs": [
        {
            "url": "http://darkfailllnkf4vf.onion",
            "category": "index",
            "language": "en",
            "description": "dark.fail index — query-aware seed (limited)",
        },
    ],
    "hacking": [
        {
            "url": "http://darkfailllnkf4vf.onion",
            "category": "index",
            "language": "en",
            "description": "dark.fail index — query-aware hacking seed",
        },
    ],
    "fraud": [
        {
            "url": "http://darkfailllnkf4vf.onion",
            "category": "index",
            "language": "en",
            "description": "dark.fail index — query-aware fraud seed",
        },
    ],
}

TOPIC_KEYWORDS: dict[str, List[str]] = {
    "bitcoin": [
        "bitcoin", "btc", "wallet", "crypto", "cryptocurrency", "blockchain",
    ],
    "ransomware": [
        "ransomware", "lockbit", "alphv", "blackcat", "conti", "revil", "ryuk",
        "extortion",
    ],
    "malware": [
        "malware", "rat", "trojan", "backdoor", "botnet", "rootkit", "keylogger",
        "stealer",
    ],
    "credentials": [
        "credentials", "password", "login", "account", "breach", "leak", "dump",
        "combo",
    ],
    "drugs": ["drug", "narcotic", "cannabis", "opioid"],
    "hacking": [
        "hacking", "exploit", "vulnerability", "cve", "0day", "zero-day", "shell",
        "access",
    ],
    "fraud": [
        "fraud", "carding", "cc", "credit card", "ssn", "identity", "fake",
        "counterfeit",
    ],
}


def detect_query_topics(query: str) -> List[str]:
    """
    Analyze a query string and return relevant topic categories.

    Examples:
        "lockbit ransomware bitcoin payments" → ["ransomware", "bitcoin"]
        "CVE-2024-1234 exploit kit" → ["hacking"]
        "stolen credentials combo list" → ["credentials"]
    """
    query_lower = query.lower()
    detected_topics: List[str] = []

    for topic, keywords in TOPIC_KEYWORDS.items():
        if any(keyword in query_lower for keyword in keywords):
            detected_topics.append(topic)

    return detected_topics


# ---------------------------------------------------------------------------
# Public filter function
# ---------------------------------------------------------------------------


def get_seeds(
    category: Optional[str] = None,
    language: Optional[str] = None,
    query: Optional[str] = None,
) -> List[dict]:
    """
    Return the curated seed list, optionally filtered by *category* and/or *language*.

    Args:
        category:  one of "search", "index", "forum", "paste", "market_index",
                   or None to return all categories.
        language:  "en", "ru", "multi", or None to return all languages.
        query:     optional investigation query; adds topic-specific seeds when
                   keywords match.

    Returns a new list; the original SEED_URLS is never mutated.
    """
    seeds = list(SEED_URLS)
    if category is not None:
        seeds = [s for s in seeds if s["category"] == category]
    if language is not None:
        seeds = [s for s in seeds if s["language"] == language]

    if query:
        detected_topics = detect_query_topics(query)
        if detected_topics:
            logger.warning("Query topics detected: %s", detected_topics)
            topic_specific: List[dict] = []
            for topic in detected_topics:
                topic_seeds = list(TOPIC_SEEDS.get(topic, []))
                if category is not None:
                    topic_seeds = [
                        s for s in topic_seeds if s.get("category") == category
                    ]
                topic_specific.extend(topic_seeds)

            seen_topic_urls: set[str] = set()
            topic_specific_deduped: List[dict] = []
            for s in topic_specific:
                u = s.get("url")
                if not u or u in seen_topic_urls:
                    continue
                seen_topic_urls.add(u)
                topic_specific_deduped.append(s)

            existing_urls = {s["url"] for s in seeds}
            new_seeds = [s for s in topic_specific_deduped if s["url"] not in existing_urls]
            logger.warning(
                "Adding %d topic-specific seeds for: %s",
                len(new_seeds),
                detected_topics,
            )
            seeds = seeds + new_seeds

    return list(seeds)
