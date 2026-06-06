# Contributing to VoidAccess

Contributions are welcome. The project is actively maintained, and there's a clear roadmap. If you're looking to contribute, here's what helps most:

- Bug reports with real steps to reproduce
- Bug fixes (especially around the API or scraper)
- New enrichment sources (more threat intel feeds)

Before starting work on these, open an issue first to avoid wasted effort:

- New pipeline stages (the core pipeline is stable for a reason)
- UI redesigns (the Next.js frontend has an evolving design system)

We don't accept contributions that would make VoidAccess useful for offensive operations, or that weaken the content filter. This tool is for defenders and investigators.

---

## 1. Setting up dev environment

### 1.1 Clone and create your environment

```bash
git clone https://github.com/YOUR_USERNAME/open_intel.git
cd open_intel
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\Activate    # Windows
pip install -r requirements.txt
pip install -r dev-requirements.txt
python -m spacy download en_core_web_sm
```

### 1.2 Environment variables

Copy `.env.example` to `.env`. Only `JWT_SECRET` is required:

```bash
cp .env.example .env
# Edit .env and set JWT_SECRET
# Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
```

Optional keys enable more features:

- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY` — LLM providers
- `OTX_API_KEY`, `VT_API_KEY`, `ABUSECH_API_KEY` — threat intel feeds
- `TOR_PROXY_HOST=127.0.0.1`, `TOR_PROXY_PORT=9050` — local Tor (required for dark web search)
- `REDIS_URL` — for rate limiting (optional)
- `PLAYWRIGHT_ENABLED=true` — enables JS rendering for heavy .onion pages

### 1.3 Running the app

**Backend only (FastAPI on port 8000):**

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

**Frontend only (Next.js on port 3000):**

```bash
cd web
npm install
npm run dev
```

**Full stack with Docker:**

```bash
docker compose up --build
```

This starts: PostgreSQL (port 5433), Tor proxy (9050), FastAPI (8000), Next.js (3001).

**Just database + Redis for live-service development:**

```bash
docker compose up postgres tor
```

Then run the FastAPI backend locally pointing at Docker services:

```bash
export DATABASE_URL="postgresql://open_intel:open_intel@localhost:5433/open_intel"
export TOR_PROXY_HOST="127.0.0.1"
export TOR_PROXY_PORT="9050"
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 2. Submitting a bug report

Use GitHub issues. Include:

- VoidAccess version (check `git log -1 --format=%h` or Docker tag)
- OS and Docker version
- The query that triggered the issue
- What happened vs. what you expected
- Relevant logs

Where logs are in Docker:

```bash
docker compose logs fastapi
docker compose logs nextjs
```

If you're hitting a dark web search engine that returns nothing, that's not a bug — those services go offline frequently. Check the health sidebar in the app before filing.

---

## 3. Submitting a pull request

1. Fork the repo
2. Create a branch:
   - `fix/short-description`
   - `feat/short-description`
   - `docs/short-description`
3. Make your changes
4. Open a PR against `main`

Your PR needs:

- A clear description of what changed and why
- Before/after screenshots if it's a UI change
- A note if it touches the scraping or extraction pipeline (test it against at least two real queries and include results)

Keep PRs focused. One feature or fix per PR.

---

## 4. Code standards

### 4.1 Backend (Python)

Run formatting before pushing:

```bash
black .
isort .
ruff check .
```

Type hints are required for new functions. Check types:

```bash
mypy .
```

Tests live in `tests/`. Run them:

```bash
pytest tests/
pytest tests/test_api.py -v        # specific file
pytest tests/ --cov=. --cov-report=term-missing  # with coverage
```

**Backend architecture:**

- `api/main.py` — FastAPI entry point, route registration, middleware
- `api/routes/` — HTTP route handlers (depends on services in `llm.py`, `search.py`, `scrape.py`, etc.)
- `db/models.py` — SQLAlchemy ORM models
- `db/queries.py` — Raw SQL queries for performance-critical operations
- `sources/` — Enrichment sources (threat intel APIs)
- `extractor/` — Entity extraction pipeline
- `monitor/` — Scheduled jobs and alerting

Route handlers call services. Don't put business logic in route files.

### 4.2 Frontend (Next.js/TypeScript)

Run linting and type checks:

```bash
cd web
npm run lint
```

**Frontend architecture:**

- `web/app/` — Next.js App Router pages
- `web/components/` — React components
- `web/lib/` — API client, utilities, auth helpers
- State lives in React hooks or URL params

Follow existing component patterns.

### 4.3 New dependencies

Don't add dependencies without a good reason. If you need one:

1. Add it to `requirements.in` (unpinned)
2. Run: `pip-compile requirements.in --output-file requirements.txt`
3. Explain why in your PR

Same for the frontend — add to `web/package.json`, explain in PR.

---

## 5. Adding a new enrichment source

This is the most common meaningful contribution. Here's how it works:

### 5.1 The pattern

Each source in `sources/` is an async function that returns raw data from an external API. The results then get converted to "page-shaped dicts" that the entity extractor can process.

A page-shaped dict has:

```python
{
    "url": "https://source.example.com/...",
    "link": "https://source.example.com/...",
    "content": "extracted text for entity extraction",
    "text": "extracted text for entity extraction",
    "status": 200,
    "source": "source_name",
    "title": "Page title",
    "via": "source_api",
}
```

### 5.2 Where sources are registered

In `sources/enrichment.py`, the `enrich_investigation()` function runs multiple sources concurrently and aggregates results. Your source should:

1. Take a query string and optional entities list
2. Return list[dict] of enrichment results
3. Handle rate limits gracefully (log a warning and return empty on failure)
4. Include a 30-second timeout per request

Example structure (see `sources/cisa.py`, `sources/shodan.py` for real implementations):

```python
async def enrich_example(query: str) -> list[dict]:
    """Query Example API for threat intel."""
    results = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.example.com/search?q={query}") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("results", []):
                        results.append({
                            "source": "example",
                            "entity_value": item.get("indicator"),
                            "extra_field": item.get("extra"),
                        })
    except asyncio.TimeoutError:
        logger.warning("Example: request timed out")
    except Exception as e:
        logger.warning("Example: error %s", e)
    return results
```

### 5.3 Adding your source to the pipeline

In `sources/enrichment.py`, add your function to the `_enrich_new_sources()` async gather:

```python
async def _enrich_new_sources(query: str, entities: list[dict]) -> list[dict]:
    # ... existing sources ...
    example_results, = await asyncio.gather(
        enrich_example(query),
        return_exceptions=True,
    )
    if isinstance(example_results, Exception):
        example_results = []
    pages.extend(_example_to_pages(example_results))
```

Then write a converter function that transforms your raw results into page-shaped dicts.

### 5.4 What to provide

Your source needs to specify:

- What it queries against (IP, hash, domain, actor name, CVE, etc.)
- What it returns (dict structure with entity_value, source, and meaningful fields)
- Rate limits and how to handle failures (most APIs have free tiers with rate limits)

---

## 6. A note on the content filter

The content filter blocks material that makes this tool useful for offensive operations. It's not up for modification in any direction — don't try to weaken what it blocks, and don't change how it works silently.

PRs that touch the filter to weaken it will be closed without discussion.

The content filter has its own test coverage in `tests/test_content_safety.py`. To run just these tests:

```bash
pytest tests/test_content_safety.py -v
```

---

## Questions?

Open an issue on GitHub. For security issues, see `SECURITY.md`.