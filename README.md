# OSINT Platform Comparison

> Paid alternatives vs. open_intel (self-hosted, open-source).

| Tool | Type | Pricing | Key Features | Differences from open_intel |
|------|------|---------|--------------|-----------------------------|
| **open_intel** | Open-source | Free | Multi-source aggregation, entity extraction, graph analysis, crawler, dark web (Ahmia), leak DB (IntelX), API, CLI, monitoring | — |
| **Maltego** | Paid | ~€999/yr (CT) | Visual link analysis, 40+ transforms, graph mapping | Requires subscription for full transforms; no built-in crawler or dark web search |
| **Lampyre** | Paid | ~€49/mo | Automated multi-source data enrichment, payments/crypto/social lookups | No graph analysis or self-hosting; limited to vendor's data sources |
| **SpiderFoot HX** | Paid | ~$129/yr | 200+ modules, attack surface mapping, scheduled scanning | Self-hosted but closed-source; focused on infrastructure, not social profiling |
| **Recorded Future** | Enterprise | Custom ($$$) | Real-time threat intel, AI analysis, API, TIP integration | Enterprise-only; no self-hosting; overkill for individual/small-team profiling |
| **Social Links** | Paid | ~$300/mo | Social media profiling, face recognition, cross-platform matching | No dark web / crawler; subscription lock-in for social APIs |
| **Skopenow** | Paid | Custom ($$) | Social media monitoring, location tracking, threat detection | No graph or entity extraction; black-box scoring |
| **Videris** | Paid | Custom ($$$) | AI-assisted investigation workflow, automation, visual mapping | No self-hosting; closed-source; custom pricing |
| **Shodan** | Freemium | ~$49/mo (pro) | Device/iot discovery, exposed services, port scanning | Single-purpose (infrastructure); no social/leak profiling |

## Why open_intel stands out

- **No subscriptions** — fully free and self-hosted
- **Your data stays with you** — no third-party servers
- **All-in-one** — crawler, social scraper, dark web, leak DB, entity graph, CLI, API, GUI
- **Modular & extensible** — swap in your own sources, LLMs, or storage
- **No API rate-limit bottlenecks** — you control the infra





## About This Project
**Open_Intel** is a fork of [VoidAccess](https://github.com/KatrielMoses/voidaccess), the self-hosted dark web OSINT platform. This fork extends the original with clearnet intelligence sources and additional LLM provider support.

### What's Different from VoidAccess

| Change                    | Description                                                                                                                                                 |
|---------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Renamed to Open_Intel** | Reflects expanded focus on both dark web and clearnet sources                                                                                               |
| **IntelX Integration**    | Added [Intelligence X](https://intelx.io) as a clearnet search source for darknet markets, paste sites, leak databases, and forum content via their free API tier (`sources/intelx_scraper.py`) |
| **Lumo LLM Provider**     | Added [Proton Lumo](https://lumo.proton.me) alongside OpenAI, Anthropic, Google, Groq, and Ollama                                                          |
| **`--no-refine` Flag**    | Skips LLM query refinement while retaining LLM for filtering and summary; useful when using original query verbatim                                         |
| **Content Safety Removed**| Mandatory content-safety filters from the original VoidAccess have been removed. Unrestricted operational scope guarantees zero barriers to data acquisition and analysis no query, URL, or content blocking |
| **Updated Branding**      | Logo, banner, and tagline updated to "Dark and Clear WEB OSINT Intelligence"                                                                                |

## Quick Start

### CLI (No Docker, 30 Seconds)

git clone https://github.com/carlostkd/open_intel.git
cd open_intel
pip install -r requirements.txt
python -m spacy download en_core_web_sm
cp .env.example .env
python -m open_intel_cli configure
python -m open_intel_cli investigate "Android 16 CVE"

Requires local Tor for dark web sources:
- Install from https://torproject.org
- Use `--no-tor` for clearnet-only investigations

The CLI stores config in ~/.open_intel/config.json and writes results to ~/.open_intel/results/.

### CLI Commands

| Command                   | Description                      |
|--------------------------|----------------------------------|
| `open_intel investigate` | Run an investigation             |
| `open_intel show`        | Interactive entity browser       |
| `open_intel export`      | Export STIX/MISP/Sigma/CSV/MD   |
| `open_intel enrich`      | Re-enrich saved results          |
| `open_intel list`        | List saved investigations        |
| `open_intel status`      | Config and API key status        |
| `open_intel configure`   | Setup wizard                     |

### Useful Flags

| Flag          | Description                                        |
|---------------|----------------------------------------------------|
| `--no-refine` | Skip LLM query refinement, keep LLM for filtering/summary |
| `--no-llm`    | Skip all LLM features (refinement, filtering, summary)   |
| `--no-tor`    | Clearnet-only mode (skip Tor engines)                     |
| `--depth`     | Values: shallow, normal, deep                             |
| `--format`    | Values: json, md, both                                    |
| `--quiet`     | Disable live display                                      |

## How It Works (The 13-Step Pipeline)

1. **LLM Query Refinement**: Optimizes search terms for `.onion` engine indexing (skippable with `--no-refine`).
2. **Parallel Collection**: Queries 16+ Tor search engines simultaneously alongside IntelX, paste sites (Pastebin, dpaste, paste.ee), GitHub, GitLab, and curated RSS security feeds.
3. **Intelligence Filtering**: LLM filters noise, keeping only relevant intelligence pages.
4. **Multi-Source Enrichment**: Pulls from AlienVault OTX, abuse.ch, ransomware.live, CISA KEV, Shodan, GreyNoise, AbuseIPDB, Feodo Tracker, C2IntelFeeds, and more—running in parallel with collection.
5. **Recursive `.onion` Discovery**: Discovers hidden links via seed URL crawling.
6. **Vector Cache Check**: Avoids redundant scraping for recently visited pages (24h TTL).
7. **Tor-Routed Scraping**: Safely fetches page content with a 1MB safety cap.
8. **Persistence**: Stores new content in the local vector cache.
9. **Intelligence Merging**: Combines scraped and enriched data for processing.
10. **Advanced Extraction**: Regex, NER, and LLM-based entity identification.
11. **Historical Cross-Referencing**: Validates data against seed datasets.
12. **Graph Construction**: Builds relationship nodes based on co-occurrence.
13. **Final Intelligence Summary**: LLM generates a structured technical briefing.

## Collection Sources

| Source                                   | Type                              | Key Required                  |
|------------------------------------------|----------------------------------|--------------------------------|
| **Tor Search Engines** (16+)             | Dark Web                         | No                             |
| **IntelX**                               | Clearnet + Darknet/Pastes/Leaks  | Free API Key                   |
| **Paste Sites** (Pastebin, dpaste, etc.) | Clearnet                         | No                             |
| **GitHub** (Code + Repos)               | Clearnet                         | Optional (higher rate limit)   |
| **GitLab** (Code + Projects)            | Clearnet                         | Optional (higher rate limit)   |
| **RSS Feeds** (20 Curated Blogs)        | Clearnet                         | No                             |

## What It Extracts

| Category            | Examples                                                    |
|---------------------|-------------------------------------------------------------|
| **Cryptocurrency**  | Bitcoin, Ethereum, Monero wallet addresses                  |
| **Network Indicators** | IPv4 addresses, `.onion` URLs, domains, email, PGP keys  |
| **File Indicators** | MD5, SHA1, SHA256 hashes                                    |
| **Vulnerabilities** | CVE numbers, MITRE ATT&CK techniques                        |
| **Threat Actors**   | Actor handles, malware families, ransomware group names     |
| **Paste Sites**     | Pastebin, Ghostbin, Rentry, and similar links               |
| **People/Orgs**     | Named persons, organization names, locations                |

## LLM & Enrichment Ecosystem

### Supported LLM Providers

| Provider         | Models                        | Notes                                    |
|------------------|-------------------------------|------------------------------------------|
| **OpenRouter**   | DeepSeek, Llama 3.3, Claude Haiku | Recommended default; free models available |
| **Groq**         | Llama 3.3, Llama 3.1         | Fast inference; free tier                |
| **OpenAI**       | GPT-4o Mini                   | API key required                         |
| **Anthropic**    | Claude Haiku                  | Haiku is the tested default              |
| **Google Gemini**| Gemini 1.5 Flash, 2.5 Pro    | Free tier via AI Studio                  |
| **Ollama**       | Any local model               | Air-gapped; no API key needed            |
| **Lumo** (Proton)| Auto                          | Free tier available; privacy-focused     |

### Optional Enrichment API Keys

| Key                          | What It Does                         | Free                       | Sign Up                     |
|------------------------------|--------------------------------------|----------------------------|-----------------------------|
| `INTELX_API_KEY`             | IntelX darknet/paste/leak search     | Yes (50 lookups/day)       | intelx.io                   |
| `OTX_API_KEY`                | AlienVault OTX threat pulses         | Yes                        | otx.alienvault.com          |
| `VT_API_KEY`                 | VirusTotal file hash AV detections   | Yes (4 req/min)            | virustotal.com              |
| `ABUSECH_API_KEY`            | MalwareBazaar, ThreatFox, URLhaus    | Yes                        | abuse.ch                    |
| `ABUSEIPDB_API_KEY`          | IP abuse reports, 1,000 checks/day   | Yes                        | abuseipdb.com/register      |
| `GREYNOISE_API_KEY`          | Suppresses known scanner IPs         | Free tier                  | greynoise.io/pricing        |
| `URLSCAN_API_KEY`            | Domain scan data                     | Yes (public without key)   | urlscan.io/user/signup      |
| `HYBRID_ANALYSIS_API_KEY`    | Sandbox analysis for file hashes     | Yes                        | hybrid-analysis.com/signup  |
| `HIBP_API_KEY`               | Email breach history                 | No ($3.50/month)           | haveibeenpwned.com/API/Key  |

##

MIT License

Copyright (c) 2026 KatrielMoses (VoidAccess)
Copyright (c) 2026 CarlosTkd (Open_Intel Fork)
