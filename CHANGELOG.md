# Changelog

All notable changes to Open_Intel are documented here.

## [1.4.7] - 2026-06-04
### Fixed
- Critical: clearnet pages (GitHub, GitLab,
  paste sites, RSS feeds) were silently dropped
  due to text_content key mismatch in CLI
  pipeline merge step. Every --no-tor
  investigation returned 0 entities from
  clearnet sources. Fix adds text_content to
  the fallback chain. Before: 0 pages, 0
  entities. After: 24+ pages, 113+ entities.
  (PR #12 by SecJuan)

## [1.4.6] - 2026-06-01
### Fixed
- Domain/hash/email enrichment steps now run
  before graph building (were running after
  finalize, too late to affect results)
- Cache expires_at datetime tzinfo error on
  Python 3.13 / SQLAlchemy 2.x
- Increased LLM filter top_n from 5 to 15
  for more pages scraped per investigation

## [1.4.3] - 2026-05-31

### Fixed

- Empty env vars causing HTTP 401 on keyless APIs
- spaCy model auto-installs on first investigate run
- Banner centering and circular shape corrected
- STIX/MISP export path collision fixed
- Content safety check added to CLI pipeline
- show --no-tui flag added for scripted use

## [1.4.2] - 2026-05-21

### Fixed

- PyPI version metadata corrected
- Banner callback condition fixed for Windows

## [1.4.1] - 2026-05-21

### Fixed

- Package namespace collision with other CLI tools (cli/ renamed to open_intel_cli/)
- CLI interface - pip install open_intel
- open_intel investigate, show, export, enrich, list, status, configure commands
- SQLite persistence at ~/.open_intel/
- Textual TUI entity browser
- Lavender circle ASCII banner
- Tor auto-detection (9050/9150)
- All export formats (STIX/MISP/Sigma/CSV/MD)
- Re-enrichment of saved investigations

## [1.3.0] - 2025-05-18

### Added

**IP Reputation Enrichment (Step 6.1)**
- Feodo Tracker (abuse.ch) and C2IntelFeeds (montysecurity/C2-Tracker, 6 frameworks) blocklist checks — free, no key required
- AbuseIPDB community abuse reports (`ABUSEIPDB_API_KEY`; 1,000 free checks/day)
- GreyNoise scanner classification (`GREYNOISE_API_KEY`); IPs classified `benign_scanner` are suppressed from entity results
- `MALWARE_FAMILY` entities auto-created from confirmed C2 framework names
- `C2_FEED_CACHE_TTL` config variable (hours between blocklist refreshes, default 24)

**Domain Reputation Enrichment (Step 6.2)**
- crt.sh certificate transparency log lookup — subdomain enumeration; free
- URLScan.io live domain scan data and malicious verdicts (`URLSCAN_API_KEY` optional)
- Wayback Machine historical snapshot detection; `ARCHIVED` tag on domain entities
- `URLSCAN_SUBMIT` config variable (default `false`; set `true` to trigger new public scans)

**Hash Reputation Enrichment (Step 6.3)**
- Hybrid Analysis behavioral sandbox verdict, AV detection ratio, contacted IPs/domains (`HYBRID_ANALYSIS_API_KEY`)
- VirusTotal hash lookups now also run in the post-extraction enrichment pass (`VT_API_KEY`)
- `MALWARE_FAMILY` entities auto-created from confirmed family names; linked to source hash

**Email Reputation Enrichment (Step 6.4)**
- Disposable email domain blocklist — daily-refreshed from disposable-email-domains project; free
- EmailRep reputation scoring and platform presence (`EMAILREP_API_KEY` optional)
- HaveIBeenPwned breach history lookup (`HIBP_API_KEY`; paid)
- Custom-domain email addresses now generate new `DOMAIN` entities for downstream enrichment

**Entity Quality Badges (UI)**
- `C2` badge — IP confirmed on Feodo Tracker or C2IntelFeeds
- `Malicious` badge — GreyNoise or AbuseIPDB confirmed malicious
- `Breached` badge — email found in HIBP breach data
- `Disposable` badge — email uses a known throwaway domain
- `Archived` badge — domain has Wayback Machine historical snapshots
- `Taken Down` badge — domain scan shows no live content
- `AV ratio` badge — file hash AV detection ratio from Hybrid Analysis or VirusTotal

---

## [1.2.0] - 2025-04-15

### Added

**Clearnet Collection Sources (parallel with Tor search)**
- Paste site scraping: Pastebin, dpaste, paste.ee, Rentry — `PASTE_SCRAPING_ENABLED`, `PASTE_MAX_RESULTS`
- GitHub code search and repository READMEs — `GITHUB_SCRAPING_ENABLED`, `GITHUB_TOKEN`, `GITHUB_MAX_RESULTS`
- GitLab code search and project pages — `GITLAB_SCRAPING_ENABLED`, `GITLAB_TOKEN`, `GITLAB_MAX_RESULTS`
- RSS security feed integration — 20 curated feeds (Krebs, BleepingComputer, Talos, Mandiant, CrowdStrike, Unit 42, CISA, and more); 1-hour per-URL cache — `RSS_FEEDS_ENABLED`, `RSS_MAX_ARTICLES`

**Curated Seed Catalogue**
- `data/onion_seeds.json` — 31 vetted `.onion` seeds across 8 categories
- `SeedManager` relevance scoring: tag and name matching against the query; up to 10 seeds per investigation
- Seeds bypass the LLM filter and are injected before the search fan-out
- Weekly refresh job (APScheduler, Sunday 03:00 UTC) and Sunday 02:00 seed reachability validation

**DNS/WHOIS Enrichment (Step 6.8)**
- CIRCL passive DNS history and CIRCL PSSL certificate history for IPs and domains — free
- RDAP (ARIN/rdap.org) WHOIS registration data — free
- SecurityTrails detailed DNS history (`SECURITYTRAILS_API_KEY`; 50 queries/month free)
- `DNS_ENRICHMENT_ENABLED` config variable

**Infrastructure Cluster Detection**
- `_detect_infrastructure_clusters()` groups IPs and domains sharing ASN, CIDR, or WHOIS registrant
- Clusters exposed on the investigation detail endpoint as `infrastructure_clusters`
- `InfrastructureClusters` UI panel

**Investigation Cancellation**
- `POST /investigations/{id}/cancel` endpoint
- Checkpoints after Steps 1, 2–4 (parallel phase), 5, and 6
- Partial results preserved on cancellation; status set to `cancelled`

**Sources Panel**
- `sources_used` dict returned on investigation detail — per-source status and result count
- `SourcesPanel` UI component

---

## [1.1.0] - 2025-03-10

### Added

- Content safety filters — 6 mandatory layers (query intake, URL pre-scan, paste/RSS content, scraped content, post-extraction entity values, audit logging)
- `content_safety_events` table — audit log for all blocked content (hash prefix only; no actual content stored)
- IOC freshness decay — `FreshnessTag` assigned per entity based on `last_seen_at` and entity type; thresholds vary by type
- Defanged output — `utils/defang.py`; toggled per investigation in the UI (`defangEnabled`, default `true`)
- Graph UX improvements — node size scaling, handle disambiguation (`handle@forum-domain`), `LIKELY_SAME_ACTOR` and `CONFIRMED_SAME_ACTOR` inference passes
- Rate limiting on `POST /investigations` — 3 requests per minute per IP via `slowapi`; `DISABLE_RATE_LIMIT` bypass for development
- Query validation — blocked terms and pattern list checked at intake; HTTP 400 on match
- Export fixes — STIX 2.1, MISP, Sigma, and CSV exports corrected and tested

---

## [1.0.0] - 2025-02-01

### Initial Release

- 13-step investigation pipeline: LLM query refinement → Tor search fan-out → LLM filter → threat intel enrichment → recursive crawler → vector cache → Tor scraping → entity extraction → graph construction → LLM summary
- Tor-routed dark web search — 16+ `.onion` engines, multilingual (EN/RU/ZH), concurrent fan-out with circuit-breaker weights
- Four-stage entity extraction: regex → NER → LLM → normalisation; confidence threshold 0.80; 400-entity global cap
- Threat intel enrichment: AlienVault OTX, MalwareBazaar, ThreatFox, URLhaus, ransomware.live, CISA KEV, Shodan InternetDB, VirusTotal
- Blockchain wallet enrichment: BlockCypher (BTC/ETH), Etherscan (ETH); `PAID_TO` graph edges
- Stylometry fingerprinting and actor profiling (`fingerprint/`)
- OPSEC failure detection — timezone leaks, language switches, clearnet slips; 0–100 risk score
- Temporal activity analysis and anomaly detection
- Export: STIX 2.1, MISP JSON, Sigma YAML rules, CSV
- Monitoring system: APScheduler keyword and URL watches; Telegram and SMTP alert delivery
- JWT authentication; per-user encrypted API key storage (Fernet AES-128)
- PostgreSQL 16 + SQLAlchemy 2.x ORM + Alembic migrations
- ChromaDB vector cache with sentence-transformer embeddings; 24-hour TTL
- Docker Compose stack: postgres, tor, fastapi, nextjs
- Next.js 14 + TypeScript + Tailwind frontend
