# extractor — Phase 2 Entity Extraction Pipeline

Converts raw scraped text into structured, queryable intelligence records.

## Architecture

```
raw page text
      │
      ▼
┌─────────────────┐
│ regex_patterns  │  Fast, precise extraction of fixed-format entities
│                 │  (wallets, CVEs, IPs, emails, PGP keys, paste URLs)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     ner.py      │  Dictionary + heuristic extraction of named entities
│                 │  (malware families, ransomware groups, threat actors)
│                 │  spaCy for org names (en_core_web_sm)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  llm_extract    │  LLM-assisted extraction (optional, runs only when
│                 │  regex/NER already found entities on the page)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  normalizer     │  Canonical value normalisation + per-call deduplication
│                 │  Upserts to DB via db/queries.py
└────────┬────────┘
         │
         ▼
   ExtractionResult
```

## Entity Types

| Type | Source | Example |
|---|---|---|
| `BITCOIN_ADDRESS` | regex | `bc1qxy2k...`, `1A1z...`, `3J98t...` |
| `ETHEREUM_ADDRESS` | regex | `0x742d35Cc...` |
| `MONERO_ADDRESS` | regex | `4...` (95 chars) |
| `ONION_URL` | regex | `http://xyz.onion/path` |
| `EMAIL_ADDRESS` | regex | `user@example.com` |
| `PGP_KEY_BLOCK` | regex | Full armored block or fingerprint |
| `CVE_NUMBER` | regex | `CVE-2024-12345` |
| `IP_ADDRESS` | regex | Public IPv4 only (RFC1918 excluded) |
| `PHONE_NUMBER` | regex | `+14155552671` |
| `PASTE_URL` | regex | `https://pastebin.com/abc123` |
| `THREAT_ACTOR_HANDLE` | NER | Context-detected username/alias |
| `MALWARE_FAMILY` | NER | `LockBit`, `Emotet`, `RedLine` |
| `RANSOMWARE_GROUP` | NER | `BlackCat`, `REvil`, `Conti` |
| `ORGANIZATION_NAME` | NER | orgs in threat context (spaCy) |

## Usage

```python
from extractor import extract_entities_from_page, extract_entities_from_pages

# Single page
result = await extract_entities_from_page(
    page_text="...",
    page_url="http://example.onion/page",
    page_id=42,
    investigation_id=7,
    llm=my_llm,           # optional
    run_llm_extraction=True,
)
print(result.entity_count, result.entities_by_type)

# Multiple pages (concurrent, semaphore-limited)
results = await extract_entities_from_pages(
    pages=[{"url": "...", "text": "..."}],
    max_concurrent=5,
)
```

## Dependencies

- `spacy` + `en_core_web_sm` model for organisation-name extraction
  - Install model: `python -m spacy download en_core_web_sm`
  - If the model is absent, NER falls back to dictionary + heuristics only
- `eth_utils` (optional) for EIP-55 Ethereum address checksum — degrades to
  lowercase without it
- All DB operations require `DATABASE_URL` to be set; without it, entities are
  extracted but not persisted

## Configuration

No new environment variables.  Uses the same `DATABASE_URL` and LLM
configuration (via `llm.py` / `llm_utils.py`) already present from Phase 1.
