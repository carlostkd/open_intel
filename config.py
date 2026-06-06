import os
import secrets
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def _clean_env(name, default=None):
	value = os.getenv(name, default)
	if value is None:
		return None
	value = str(value).strip()
	# Support accidentally quoted values copied into .env
	if len(value) >= 2 and (
		(value[0] == value[-1] == '"') or (value[0] == value[-1] == "'")
	):
		value = value[1:-1].strip()
	return value

# Configuration variables loaded from the .env file
OPENAI_API_KEY = _clean_env("OPENAI_API_KEY")
GOOGLE_API_KEY = _clean_env("GOOGLE_API_KEY")
ANTHROPIC_API_KEY = _clean_env("ANTHROPIC_API_KEY")
OLLAMA_BASE_URL = _clean_env("OLLAMA_BASE_URL")
OPENROUTER_BASE_URL = _clean_env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_API_KEY = _clean_env("OPENROUTER_API_KEY")
GROQ_API_KEY = _clean_env("GROQ_API_KEY", "")
LUMO_API_KEY = _clean_env("LUMO_API_KEY", "")
LUMO_BASE_URL = _clean_env("LUMO_BASE_URL", "https://lumo.proton.me/api/ai/v1")
LLAMA_CPP_BASE_URL = _clean_env("LLAMA_CPP_BASE_URL")

# Database
DATABASE_URL = _clean_env("DATABASE_URL")

# Tor proxy (configurable so Docker can point to a tor service by name)
TOR_PROXY_HOST = _clean_env("TOR_PROXY_HOST", "127.0.0.1")
TOR_PROXY_PORT = _clean_env("TOR_PROXY_PORT", "9050")

# Phase 1D — expanded sources (all optional; missing vars disable that source)
DARKSEARCH_API_KEY = _clean_env("DARKSEARCH_API_KEY")          # optional free-tier key
TELEGRAM_API_ID   = _clean_env("TELEGRAM_API_ID")              # from my.telegram.org
TELEGRAM_API_HASH = _clean_env("TELEGRAM_API_HASH")            # from my.telegram.org
TELEGRAM_PHONE    = _clean_env("TELEGRAM_PHONE")               # E.164, e.g. +12025551234

# Phase 4 — vector store + alert channels (all optional)
CHROMA_PERSIST_DIR = _clean_env("CHROMA_PERSIST_DIR", "./chroma_db")
TELEGRAM_BOT_TOKEN = _clean_env("TELEGRAM_BOT_TOKEN")          # one-way alerts; separate from Telethon API vars
SMTP_HOST          = _clean_env("SMTP_HOST")
SMTP_PORT          = _clean_env("SMTP_PORT", "587")
SMTP_USER          = _clean_env("SMTP_USER")
SMTP_PASS          = _clean_env("SMTP_PASS")

# Phase 5 — REST API server
API_HOST = _clean_env("API_HOST", "0.0.0.0")
API_PORT = _clean_env("API_PORT", "8000")

# Phase 6 — advanced capabilities
DEEPL_API_KEY        = _clean_env("DEEPL_API_KEY")           # optional; translation
STYLOMETRY_THRESHOLD = _clean_env("STYLOMETRY_THRESHOLD", "0.85")  # same-author detection

# LLM extraction cache (optional — defaults to enabled)
DISABLE_EXTRACTION_CACHE = _clean_env("DISABLE_EXTRACTION_CACHE")
if DISABLE_EXTRACTION_CACHE is not None:
    DISABLE_EXTRACTION_CACHE = DISABLE_EXTRACTION_CACHE.lower() == "true"
else:
    DISABLE_EXTRACTION_CACHE = False

# i18n / Query Expansion
# Languages to include in query expansion (comma-separated ISO 639-1 codes)
# Default: en, ru, zh (English, Russian, Chinese)
I18N_LANGUAGES = _clean_env("I18N_LANGUAGES", "en,ru,zh")
if I18N_LANGUAGES and isinstance(I18N_LANGUAGES, str):
    I18N_LANGUAGES = [lang.strip() for lang in I18N_LANGUAGES.split(",") if lang.strip()]
else:
    I18N_LANGUAGES = ["en", "ru", "zh"]

# Threat Intelligence API Keys
OTX_API_KEY = _clean_env("OTX_API_KEY", "")  # AlienVault OTX — free at otx.alienvault.com
VT_API_KEY = _clean_env("VT_API_KEY", "")    # VirusTotal — free tier at virustotal.com

# IP Reputation Enrichment (all optional — features degrade gracefully without keys)
ABUSEIPDB_API_KEY = _clean_env("ABUSEIPDB_API_KEY", "")   # Community IP abuse reports
GREYNOISE_API_KEY = _clean_env("GREYNOISE_API_KEY", "")   # Suppresses benign scanner IPs
C2_FEED_CACHE_TTL = _clean_env("C2_FEED_CACHE_TTL", "24") # Hours between feed refreshes

# Domain Reputation Enrichment
URLSCAN_API_KEY        = _clean_env("URLSCAN_API_KEY", "")
SECURITYTRAILS_API_KEY = _clean_env("SECURITYTRAILS_API_KEY", "")

# Code Intelligence (GitHub / GitLab scraping)
GITHUB_TOKEN = _clean_env("GITHUB_TOKEN", "")
GITLAB_TOKEN = _clean_env("GITLAB_TOKEN", "")

# Intelligence X (IntelX) — clearnet dark web intelligence search
INTELX_API_KEY = _clean_env("INTELX_API_KEY", "")
INTELX_USER = _clean_env("INTELX_USER", "")

# Hash Reputation Enrichment
HYBRID_ANALYSIS_API_KEY = _clean_env("HYBRID_ANALYSIS_API_KEY", "")

# Email Reputation Enrichment
HIBP_API_KEY      = _clean_env("HIBP_API_KEY", "")
EMAILREP_API_KEY  = _clean_env("EMAILREP_API_KEY", "")

SHODAN_RATE_LIMIT_DELAY = 1.0        # seconds between Shodan requests (InternetDB)
MAX_IPS_PER_INVESTIGATION = 50      # max IPs to query Shodan per investigation
MAX_HASHES_PER_INVESTIGATION = 20    # max file hashes to query VirusTotal per investigation

# Blockchain API Keys (optional — free tiers work without)
BLOCKCYPHER_TOKEN = _clean_env("BLOCKCYPHER_TOKEN", "")
ETHERSCAN_API_KEY = _clean_env("ETHERSCAN_API_KEY", "")

# Auth — REQUIRED in production. Generate with: python -c "import secrets; print(secrets.token_hex(32))"
_jwt_secret = _clean_env("JWT_SECRET")
if _jwt_secret is None:
    raise RuntimeError(
        "JWT_SECRET environment variable is not set. "
        "Generate a secure secret with: python -c \"import secrets; print(secrets.token_hex(32))\" "
        "and set it as JWT_SECRET in your .env file. "
        "Do NOT use a random secret — it will change on restart and invalidate all issued tokens."
    )
JWT_SECRET = _jwt_secret

# Token blacklist Redis (optional — omit to disable blacklist checks)
REDIS_URL = _clean_env("REDIS_URL")

# Playwright JS rendering for JavaScript-heavy .onion sites
# Set to False to disable (faster startup, lower memory usage)
# Requires: playwright installed + browsers downloaded
PLAYWRIGHT_ENABLED = _clean_env("PLAYWRIGHT_ENABLED", "true")
if PLAYWRIGHT_ENABLED is not None:
    PLAYWRIGHT_ENABLED = PLAYWRIGHT_ENABLED.lower() == "true"
else:
    PLAYWRIGHT_ENABLED = True


DEFAULT_MODELS = {
    "openrouter": "deepseek/deepseek-chat",
    "openai":     "gpt-4o-mini",
    "anthropic":  "claude-haiku-4-5-20251001",
    "google":     "gemini-1.5-flash",
    "groq":       "llama-3.3-70b-versatile",
    "ollama":     "llama3.2",
    "lumo":       "auto",
}

DEFAULT_MODEL = os.getenv(
    "DEFAULT_MODEL",
    "openrouter/deepseek/deepseek-chat"
)

REQUIRED_KEYS = [
    "JWT_SECRET",
]

OPTIONAL_KEYS = [
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "ANTHROPIC_API_KEY",
    "OTX_API_KEY",
    "DEEPL_API_KEY",
    "DARKSEARCH_API_KEY",
    "INTELX_API_KEY",
    "INTELX_USER",
    "OLLAMA_BASE_URL",
    "OPENROUTER_API_KEY",
    "LUMO_API_KEY",
    "LLAMA_CPP_BASE_URL",
    "BLOCKCYPHER_TOKEN",
    "ETHERSCAN_API_KEY",
]


def validate_config():
    missing_required = []
    for key in REQUIRED_KEYS:
        if _clean_env(key) is None:
            missing_required.append(key)
    if missing_required:
        raise RuntimeError(f"Missing required configuration keys: {', '.join(missing_required)}")
    for key in OPTIONAL_KEYS:
        val = _clean_env(key)
        if val is None:
            logger.debug(f"Optional configuration key '%s' is not set - related features will be disabled", key)


validate_config()
