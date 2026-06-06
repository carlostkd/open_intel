# sources/ — Phase 1D Expanded Source Coverage

Multiplies Open_Intel's dark web coverage beyond the 16 search engines in `search.py`
by adding a JSON API engine, HTML-scraping aggregators, a curated seed list,
paste site monitoring, and a Telegram channel monitor.

## Files

| File | Role |
|---|---|
| `engines.py` | DarkSearch JSON API + Torch/Haystack HTML scraping (`search_darksearch`, `search_onionsearch`) |
| `seeds.py` | 25-entry curated .onion seed list; `get_seeds(category, language)` filter |
| `pastes.py` | Fetches recent-paste index pages from known .onion paste sites, keyword-matches content |
| `telegram.py` | Telethon-based public Telegram channel monitor (clearnet, credentials optional) |
| `__init__.py` | `collect_all_sources()` — unified async aggregator |

## Quick start

```python
import asyncio
from sources import collect_all_sources

result = asyncio.run(collect_all_sources(
    query="ransomware affiliate",
    include_telegram=True,
    telegram_channels=["@darkwebintel"],
    seed_categories=["forum", "index"],
))

print(len(result["search_results"]), "search results")
print(len(result["paste_results"]), "paste matches")
print(len(result["seed_urls"]), "seed URLs for crawler")
```

## Engine details

### DarkSearch
- Endpoint: `http://darksearch.io/api/search` (routed through Tor for anonymity)
- Optional auth: set `DARKSEARCH_API_KEY` in `.env`
- Paginates up to `pages` pages (default 2)

### OnionSearch (Torch + Haystack)
- Scrapes HTML result pages from Torch and Haystack .onion search engines
- Extracts all `.onion` hrefs + anchor text as results

## Seed list

25 curated entries across five categories:

| Category | Count | Notes |
|---|---|---|
| `search` | 4 | Torch, Haystack, DuckDuckGo Tor, DarkSearch |
| `index` | 7 | Hidden Wiki, dark.fail, Daniel's, BBC, ProPublica, SecureDrop, RuTor |
| `forum` | 6 | Dread, Endchan, 8chan, CryptBB, XSS.is, Exploit.in |
| `paste` | 3 | DeepPaste, ZeroBin, ProtonMail |
| `market_index` | 3 | Darknet index, Dark2Web, OMG!OMG! |

Filter by category or language with `get_seeds(category="forum", language="ru")`.

## Telegram setup

1. Create an app at https://my.telegram.org/apps → get `API_ID` and `API_HASH`
2. Set `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `TELEGRAM_PHONE` in `.env`
3. Run the app once — Telethon will prompt for the verification code and save
   a session file (`open_intel_telegram.session`) in the working directory
4. Subsequent calls are fully automated

Telegram is always optional.  If credentials are missing, `fetch_telegram_messages`
returns `[]` and logs a warning — the rest of the pipeline is unaffected.

## New env vars

```
DARKSEARCH_API_KEY=    # optional
TELEGRAM_API_ID=       # integer, required for Telegram
TELEGRAM_API_HASH=     # string, required for Telegram
TELEGRAM_PHONE=        # E.164 format, needed for first-time auth
```
