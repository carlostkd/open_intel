# Contributing Seeds to VoidAccess

The seed list lives at [data/onion_seeds.json](../data/onion_seeds.json). Anyone can submit a PR adding new addresses — they become available to every VoidAccess deployment on the next release.

When an investigation runs, VoidAccess scores every seed against the user's query (by tag and name match) and injects the top matches into the scrape queue **before** the search-engine fan-out. Good seeds drastically improve result quality for their topic.

## Format

Each entry in a category's `seeds` array looks like this:

```json
{
  "name": "Short descriptive name",
  "url": "http://example.onion",
  "tags": ["relevant", "tags"],
  "status": "unknown",
  "added": "YYYY-MM-DD"
}
```

## Categories

Place your seed under the most specific category that fits:

- `ransomware_leak_sites` — RaaS data-leak and negotiation portals
- `hacker_forums` — underground forums, exploit/malware trading boards
- `carding_fraud` — carding shops, dumps markets, fraud forums
- `initial_access_brokers` — IAB shops, stealer log markets
- `malware_tools` — malware sample repos, exploit kits, C2 panels
- `search_and_indexes` — onion search engines and directory indexes
- `paste_and_leaks` — paste sites and leak repositories
- `threat_intelligence` — CTI resources and security research
- `discovered` — auto-added by the pipeline (do not edit by hand)

## Rules

1. **Must be a `.onion` address.** Prefer v3 (56-character) addresses — they're stable and don't expire.
2. **Must be relevant to threat intelligence.** General-purpose sites, mirrors of clearnet content, and personal blogs don't belong here.
3. **No CSAM, gore, or content that violates [USAGE_POLICY.md](USAGE_POLICY.md).** Such submissions are rejected automatically by the content-safety layer.
4. **Add realistic tags.** Tags drive relevance matching. For a LockBit leak site, include `["lockbit", "ransomware", "leak"]` so queries mentioning any of those match.
5. **Set `status` to `"unknown"`.** The weekly scheduled job (and the `POST /admin/seeds/validate` endpoint) will validate it over Tor and update the status to `active` or `unreachable`.
6. **Use today's date for `added`.**

## How relevance scoring works

For each seed, the manager computes a score against the (query + refined-query) text:

- `+3` for every per-seed or per-category tag that appears as a substring of the query
- `+2` for every word (4+ chars) in the query that appears in the seed name
- `+1` if `status == "active"`
- Base score of `1` for any seed in a search/index category (so generic queries still get a directory)

The top 10 highest-scoring seeds are injected into the scrape queue. Seeds bypass the LLM filter — they are already known intelligence sources.

## Auto-discovery

When the pipeline finds a new `.onion` link in a scraped page, it can call `SeedManager.add_discovered_seed()` to add it under the `discovered` category. Those entries are saved back to `onion_seeds.json` automatically. Periodically a maintainer should review and re-categorize them.

## Validating your contribution locally

```bash
docker compose exec fastapi python3 -c "
from sources.seed_manager import get_seed_manager
sm = get_seed_manager()
print(f'Seeds loaded: {len(sm.list_seeds())}')
"
```

To check reachability over Tor (slow — only run if you have Tor running):

```bash
curl -X POST http://localhost:8000/admin/seeds/validate \
     -H "Authorization: Bearer $TOKEN"
```
