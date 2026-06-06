# crawler/ — Phase 1C Recursive .onion Spider

Transforms Open_Intel from a search-engine client into a real dark web crawler.
Starting from one or more seed `.onion` URLs, it recursively follows links,
scoring each for relevance to the active investigation query, and archives
content to the Phase 1A database.

## Files

| File | Role |
|---|---|
| `spider.py` | `Spider` class + `crawl()` async entry point + `CrawlResult` dataclass |
| `frontier.py` | Min-heap priority queue; scores URLs via sentence-transformer cosine similarity |
| `dedup.py` | `UrlDedup` (in-memory set) + `ContentDedup` (SHA-256 vs DB pages table) |
| `utils.py` | `extract_onion_links`, `is_valid_onion`, `normalize_url` |
| `__init__.py` | Re-exports `CrawlResult` and `crawl` as the public API |

## Quick start

```python
import asyncio
from crawler import crawl

result = asyncio.run(crawl(
    seed_urls=["http://<v3-onion-address>.onion"],
    query="ransomware affiliate recruitment",
    max_depth=2,
    max_pages=100,
    min_relevance=0.3,
))
print(f"Crawled {result.pages_crawled} pages, found {result.new_urls_discovered} new URLs")
```

## Politeness rules

- **Same-domain delay:** 2–8 seconds random between consecutive requests
- **First access to a new domain:** 0.5–2 seconds
- **Per-domain concurrency cap:** 3 simultaneous requests (`asyncio.Semaphore`)
- **Download cap:** 1 MB per page (same as `scrape.py`)

## Relevance scoring

Uses `sentence-transformers/all-MiniLM-L6-v2` to embed `"<url> <page snippet>"` and
compute cosine similarity against the investigation query embedding.
Score range: 0.0–1.0.  URLs scoring below `min_relevance` are discovered
(persisted to the `sources` table) but not enqueued for crawling.

The model is loaded once as a module-level singleton — subsequent crawl runs
in the same process pay no re-load cost.

## Database integration

Every URL discovered → `sources` table, `status='discovered'`  
Every successfully scraped page → `pages` table (content-hash deduplication)  
Failed pages → source `status='failed'`  
Successfully scraped pages → source `status='active'`  

Requires `DATABASE_URL` env var (see `config.py`). Runs without a DB if
`DATABASE_URL` is not set — content is still returned in `CrawlResult.results`.
