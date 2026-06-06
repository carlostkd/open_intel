import logging
import requests
from urllib.parse import urljoin
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from typing import Callable, Optional, List
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.callbacks.base import BaseCallbackHandler
import os
from config import (
    OLLAMA_BASE_URL,
    OPENROUTER_BASE_URL,
    OPENROUTER_API_KEY,
    GOOGLE_API_KEY,
    OPENAI_API_KEY,
    ANTHROPIC_API_KEY,
    LLAMA_CPP_BASE_URL,
    GROQ_API_KEY,
    LUMO_API_KEY,
    LUMO_BASE_URL,
    DEFAULT_MODELS,
    DEFAULT_MODEL,
)

logger = logging.getLogger(__name__)


class BufferedStreamingHandler(BaseCallbackHandler):
    def __init__(self, buffer_limit: int = 60, ui_callback: Optional[Callable[[str], None]] = None):
        self.buffer = ""
        self.buffer_limit = buffer_limit
        self.ui_callback = ui_callback

    def on_llm_new_token(self, token: str, **kwargs) -> None:
        self.buffer += token
        if "\n" in token or len(self.buffer) >= self.buffer_limit:
            print(self.buffer, end="", flush=True)
            if self.ui_callback:
                self.ui_callback(self.buffer)
            self.buffer = ""

    def on_llm_end(self, response, **kwargs) -> None:
        if self.buffer:
            print(self.buffer, end="", flush=True)
            if self.ui_callback:
                self.ui_callback(self.buffer)
            self.buffer = ""


# --- Configuration Data ---
# Instantiate common dependencies once
_common_callbacks = [BufferedStreamingHandler(buffer_limit=60)]

# Define common parameters for most LLMs
_common_llm_params = {
    "temperature": 0,
    "streaming": True,
    "callbacks": _common_callbacks,
    "timeout": 30.0,
}

RECOMMENDED_MODELS = [
    {
        "id": "openrouter/deepseek/deepseek-chat",
        "name": "DeepSeek Chat",
        "provider": "OpenRouter",
        "free_tier": False,
        "recommended": True,
        "default": True,
        "note": "Recommended default — fast, cheap, no refusals"
    },
    {
        "id": "openrouter/meta-llama/llama-3.3-70b-instruct:free",
        "name": "Llama 3.3 70B (Free)",
        "provider": "OpenRouter",
        "free_tier": True,
        "recommended": True,
        "default": False,
        "note": "Free via OpenRouter — rate limited"
    },
    {
        "id": "groq/llama-3.3-70b-versatile",
        "name": "Llama 3.3 70B",
        "provider": "Groq",
        "free_tier": True,
        "recommended": True,
        "default": False,
        "note": "Free via Groq — fastest inference"
    },
    {
        "id": "groq/llama-3.1-8b-instant",
        "name": "Llama 3.1 8B Instant",
        "provider": "Groq",
        "free_tier": True,
        "recommended": False,
        "default": False,
        "note": "Free via Groq — fastest, lower quality"
    },
    {
        "id": "openrouter/deepseek/deepseek-r1",
        "name": "DeepSeek R1",
        "provider": "OpenRouter",
        "free_tier": False,
        "recommended": False,
        "default": False,
        "note": "Reasoning model — slower but thorough"
    },
    {
        "id": "openrouter/google/gemini-2.0-flash-001",
        "name": "Gemini 2.0 Flash",
        "provider": "OpenRouter",
        "free_tier": False,
        "recommended": False,
        "default": False,
        "note": "Fast, large context"
    },
    {
        "id": "openrouter/anthropic/claude-haiku-4-5",
        "name": "Claude Haiku",
        "provider": "OpenRouter",
        "free_tier": False,
        "recommended": False,
        "default": False,
        "note": "Fast Anthropic model via OpenRouter"
    },
    {
        "id": "gpt-4o-mini",
        "name": "GPT-4o Mini",
        "provider": "OpenAI",
        "free_tier": False,
        "recommended": True,
        "default": False,
        "note": "Best OpenAI price/performance"
    },
    {
        "id": "claude-haiku-4-5-20251001",
        "name": "Claude Haiku",
        "provider": "Anthropic",
        "free_tier": False,
        "recommended": True,
        "default": False,
        "note": "Fastest Claude model"
    },
    {
        "id": "gemini-1.5-flash",
        "name": "Gemini 1.5 Flash",
        "provider": "Google",
        "free_tier": True,
        "recommended": True,
        "default": False,
        "note": "Free tier via Google AI Studio"
    },
]

# Map input model choices (lowercased) to their configuration
# Each config includes the class and any model-specific constructor parameters
_llm_config_map = {
    'gpt-4.1': {
        'class': ChatOpenAI,
        'constructor_params': {'model_name': 'gpt-4.1'} 
    },
    'gpt-5.2': {
        'class': ChatOpenAI,
        'constructor_params': {'model_name': 'gpt-5.2'} 
    },
    'gpt-5.1': {
        'class': ChatOpenAI,
        'constructor_params': {'model_name': 'gpt-5.1'} 
    },
    'gpt-5-mini': {
        'class': ChatOpenAI,
        'constructor_params': {'model_name': 'gpt-5-mini'} 
    },
    'gpt-5-nano': { 
        'class': ChatOpenAI,
        'constructor_params': {'model_name': 'gpt-5-nano'} 
    },
    'claude-sonnet-4-5': {
        'class': ChatAnthropic,
        'constructor_params': {'model': 'claude-sonnet-4-5'}
    },
    'claude-sonnet-4-0': {
        'class': ChatAnthropic,
        'constructor_params': {'model': 'claude-sonnet-4-0'}
    },
    'gemini-2.5-flash': {
        'class': ChatGoogleGenerativeAI,
        'constructor_params': {'model': 'gemini-2.5-flash', 'google_api_key': GOOGLE_API_KEY }
    },
    'gemini-2.5-flash-lite': {
        'class': ChatGoogleGenerativeAI,
        'constructor_params': {'model': 'gemini-2.5-flash-lite', 'google_api_key': GOOGLE_API_KEY}
    },
    'gemini-2.5-pro': {
        'class': ChatGoogleGenerativeAI,
        'constructor_params': {'model': 'gemini-2.5-pro', 'google_api_key': GOOGLE_API_KEY}
    },
    'deepseek-v3-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'deepseek/deepseek-chat-v3-0324',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY,
        }
    },
    'minimax-m2.5-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'minimax/minimax-m2.5',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY,
        }
    },
    'qwen3-80b-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'qwen/qwen3-next-80b-a3b-instruct:free',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY
        }
    },
    'nemotron-nano-9b-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'nvidia/nemotron-nano-9b-v2:free',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },
    'gpt-oss-120b-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'openai/gpt-oss-120b:free',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },
    'gpt-5.1-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'openai/gpt-5.1',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },
    'gpt-5-mini-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'openai/gpt-5-mini',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },
    'claude-sonnet-4.5-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'anthropic/claude-sonnet-4.5',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },
    'grok-4.1-fast-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'x-ai/grok-4.1-fast',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY  # Use OpenRouter API key
        }
    },
    'groq/llama-3.3-70b': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'llama-3.3-70b-versatile',
            'base_url': 'https://api.groq.com/openai/v1',
            'api_key': GROQ_API_KEY,
        },
        'label': 'Llama 3.3 70B (Groq — Free tier)',
        'recommended': True,
        'free_tier': True,
    },
    'groq/llama-3.1-8b': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'llama-3.1-8b-instant',
            'base_url': 'https://api.groq.com/openai/v1',
            'api_key': GROQ_API_KEY,
        },
        'label': 'Llama 3.1 8B Instant (Groq — Free tier, fast)',
        'recommended': False,
        'free_tier': True,
    },
    'minimax-m2.1-openrouter': {
        'class': ChatOpenAI,
        'constructor_params': {
            'model_name': 'minimax/minimax-m2.1',
            'base_url': OPENROUTER_BASE_URL,
            'api_key': OPENROUTER_API_KEY,
        }
    },
    # 'llama3.2': {
    #     'class': ChatOllama,
    #     'constructor_params': {'model': 'llama3.2:latest', 'base_url': OLLAMA_BASE_URL}
    # },
    # 'llama3.1': {
    #     'class': ChatOllama,
    #     'constructor_params': {'model': 'llama3.1:latest', 'base_url': OLLAMA_BASE_URL}
    # },
    # 'gemma3': {
    #     'class': ChatOllama,
    #     'constructor_params': {'model': 'gemma3:latest', 'base_url': OLLAMA_BASE_URL}
    # },
    # 'deepseek-r1': {
    #     'class': ChatOllama,
    #     'constructor_params': {'model': 'deepseek-r1:latest', 'base_url': OLLAMA_BASE_URL}
    # },
    
    # Add more models here easily:
    # 'mistral7b': {
    #     'class': ChatOllama,
    #     'constructor_params': {'model': 'mistral:7b', 'base_url': OLLAMA_BASE_URL}
    # },
    # 'gpt3.5': {
    #      'class': ChatOpenAI,
    #      'constructor_params': {'model_name': 'gpt-3.5-turbo', 'base_url': OLLAMA_BASE_URL}
    # }
}


def _normalize_model_name(name: str) -> str:
    return name.strip().lower()


def _get_ollama_base_url() -> Optional[str]:
    if not OLLAMA_BASE_URL:
        return None
    return OLLAMA_BASE_URL.rstrip("/") + "/"


def fetch_ollama_models() -> List[str]:
    """
    Retrieve the list of locally available Ollama models by querying the Ollama HTTP API.
    Returns an empty list if the API isn't reachable or the base URL is not defined.
    """
    base_url = _get_ollama_base_url()
    if not base_url:
        return []

    try:
        resp = requests.get(urljoin(base_url, "api/tags"), timeout=3)
        resp.raise_for_status()
        models = resp.json().get("models", [])
        available = []
        for m in models:
            name = m.get("name") or m.get("model")
            if name:
                available.append(name)
        return available
    except (requests.RequestException, ValueError):
        return []


# Added Support for llama.cpp models since they use OpenAI-compatible API
def fetch_llama_cpp_models() -> List[str]:
    """
    Retrieve available models from an OpenAI-compatible llama.cpp server.
    Uses /v1/models.
    """
    if not LLAMA_CPP_BASE_URL:
        return []

    base = LLAMA_CPP_BASE_URL.rstrip("/")
    try:
        resp = requests.get(f"{base}/v1/models", timeout=3)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        return [m["id"] for m in data if "id" in m]
    except (requests.RequestException, ValueError, KeyError):
        return []



def _is_set(v: Optional[str]) -> bool:
    return bool(v and str(v).strip() and "your_" not in str(v))


# Changed it so the GUI only loaded available models
def get_model_choices() -> List[str]:
    """
    Combine configured cloud models with locally available Ollama models.
    Cloud models are shown only if required API keys are present.
    """
    gated_base_models: List[str] = []

    openai_ok = _is_set(OPENAI_API_KEY)
    anthropic_ok = _is_set(ANTHROPIC_API_KEY)
    google_ok = _is_set(GOOGLE_API_KEY)
    openrouter_ok = _is_set(OPENROUTER_API_KEY) and _is_set(OPENROUTER_BASE_URL)
    groq_ok = _is_set(GROQ_API_KEY)

    for k, cfg in _llm_config_map.items():
        cls = cfg.get("class")
        ctor = cfg.get("constructor_params", {}) or {}

        # OpenRouter models (ChatOpenAI with base_url set to OpenRouter)
        if cls is ChatOpenAI and (ctor.get("base_url") == OPENROUTER_BASE_URL or "openrouter" in k):
            if openrouter_ok:
                gated_base_models.append(k)
            continue

        # Groq models (ChatOpenAI with base_url set to Groq)
        if cls is ChatOpenAI and ctor.get("base_url") == "https://api.groq.com/openai/v1":
            if groq_ok:
                gated_base_models.append(k)
            continue

        # Direct OpenAI models
        if cls is ChatOpenAI:
            if openai_ok:
                gated_base_models.append(k)
            continue

        # Anthropic
        if cls is ChatAnthropic:
            if anthropic_ok:
                gated_base_models.append(k)
            continue

        # Google Gemini
        if cls is ChatGoogleGenerativeAI:
            if google_ok:
                gated_base_models.append(k)
            continue

        # Anything else: keep
        gated_base_models.append(k)

    # Local Models
    dynamic_models = []

    # Dynamic local models via Ollama-style API (/api/tags)
    dynamic_models += fetch_ollama_models()

    # Dynamic local models via llama.cpp which uses OpenAI style API
    dynamic_models += fetch_llama_cpp_models()

    normalized = {_normalize_model_name(m): m for m in gated_base_models}
    for dm in dynamic_models:
        key = _normalize_model_name(dm)
        if key not in normalized:
            normalized[key] = dm

    ordered_dynamic = sorted(
        [name for key, name in normalized.items() if name not in gated_base_models],
        key=_normalize_model_name,
    )
    return gated_base_models + ordered_dynamic




def resolve_model_config(model_choice: str):
    """
    Resolve a model choice (case-insensitive) to the corresponding configuration.
    Supports both the predefined remote models and any locally installed Ollama models.
    """
    model_choice_lower = _normalize_model_name(model_choice)
    config = _llm_config_map.get(model_choice_lower)
    if config:
        return config

    # llama.cpp (OpenAI-compatible)
    for llama_model in fetch_llama_cpp_models():
        if _normalize_model_name(llama_model) == model_choice_lower:
            return {
                "class": ChatOpenAI,
                "constructor_params": {
                    "model_name": llama_model,
                    "base_url": LLAMA_CPP_BASE_URL,
                    "api_key": OPENAI_API_KEY or "sk-local",
                },
            }

    for ollama_model in fetch_ollama_models():
        if _normalize_model_name(ollama_model) == model_choice_lower:
            return {
                "class": ChatOllama,
                "constructor_params": {"model": ollama_model, "base_url": OLLAMA_BASE_URL},
            }

    return None


# ---------------------------------------------------------------------------
# _make_*_llm helpers — used by the model-validate endpoint and as
# fallback routing inside resolve_model_config() for dynamic model IDs.
# Each helper raises ValueError with a clear message if the key is absent.
# ---------------------------------------------------------------------------

def _resolve_key(key_name: str, api_keys: Optional[dict]) -> Optional[str]:
    """Return user-override key if available, else fall back to server config."""
    if api_keys:
        v = api_keys.get(key_name)
        if v and str(v).strip():
            return str(v).strip()
    return globals().get(key_name) or None


def _make_openrouter_llm(model_id: str, api_keys: Optional[dict] = None):
    """Build a ChatOpenAI instance pointed at OpenRouter for *model_id*."""
    if not model_id:
        model_id = DEFAULT_MODELS["openrouter"]
    key = _resolve_key("OPENROUTER_API_KEY", api_keys)
    if not key:
        raise ValueError(
            "No API key configured for OpenRouter. "
            "Add OPENROUTER_API_KEY in Settings."
        )
    base = (OPENROUTER_BASE_URL or "https://openrouter.ai/api/v1").rstrip("/")
    return ChatOpenAI(
        **{**_common_llm_params, "model_name": model_id, "base_url": base, "api_key": key}
    )


def _make_groq_llm(model_id: str, api_keys: Optional[dict] = None):
    """Build a ChatOpenAI instance pointed at Groq for *model_id*."""
    if not model_id:
        model_id = DEFAULT_MODELS["groq"]
    key = _resolve_key("GROQ_API_KEY", api_keys)
    if not key:
        raise ValueError(
            "No API key configured for Groq. "
            "Add GROQ_API_KEY in Settings."
        )
    return ChatOpenAI(
        **{**_common_llm_params, "model_name": model_id,
           "base_url": "https://api.groq.com/openai/v1", "api_key": key}
    )


def _make_openai_llm(model_id: str, api_keys: Optional[dict] = None):
    """Build a ChatOpenAI instance for a native OpenAI model."""
    if not model_id:
        model_id = DEFAULT_MODELS["openai"]
    key = _resolve_key("OPENAI_API_KEY", api_keys)
    if not key:
        raise ValueError(
            "No API key configured for OpenAI. "
            "Add OPENAI_API_KEY in Settings."
        )
    return ChatOpenAI(**{**_common_llm_params, "model_name": model_id, "api_key": key})


def _make_anthropic_llm(model_id: str, api_keys: Optional[dict] = None):
    """Build a ChatAnthropic instance."""
    if not model_id:
        model_id = DEFAULT_MODELS["anthropic"]
    key = _resolve_key("ANTHROPIC_API_KEY", api_keys)
    if not key:
        raise ValueError(
            "No API key configured for Anthropic. "
            "Add ANTHROPIC_API_KEY in Settings."
        )
    base = {k: v for k, v in _common_llm_params.items() if k != "streaming"}
    return ChatAnthropic(**{**base, "model": model_id, "anthropic_api_key": key})


def _make_google_llm(model_id: str, api_keys: Optional[dict] = None):
    """Build a ChatGoogleGenerativeAI instance."""
    if not model_id:
        model_id = DEFAULT_MODELS["google"]
    key = _resolve_key("GOOGLE_API_KEY", api_keys)
    if not key:
        raise ValueError(
            "No API key configured for Google Gemini. "
            "Add GOOGLE_API_KEY in Settings."
        )
    base = {k: v for k, v in _common_llm_params.items() if k != "streaming"}
    return ChatGoogleGenerativeAI(**{**base, "model": model_id, "google_api_key": key})


def _make_ollama_llm(model_id: str, api_keys: Optional[dict] = None):
    """Build a ChatOllama instance for a locally running model."""
    if not model_id:
        model_id = DEFAULT_MODELS["ollama"]
    base_url = OLLAMA_BASE_URL or "http://localhost:11434"
    return ChatOllama(**{**_common_llm_params, "model": model_id, "base_url": base_url})


# ---------------------------------------------------------------------------
# Dynamic resolve — prefix routing appended as final fallback so that any
# model ID like "openrouter/x/y", "groq/llama-3.3-70b-versatile",
# "gpt-4o", "claude-3-5-sonnet-20241022", etc. resolves correctly even if
# it isn't in _llm_config_map.  Returns a synthetic config dict that
# llm.py's get_llm() can consume via the normal code-path.
# ---------------------------------------------------------------------------

def _resolve_model_config_by_prefix(model_choice: str) -> Optional[dict]:
    """
    Detect provider from model ID prefix and return a synthetic config dict.

    Model ID conventions:
    - "openrouter/..."  → OpenRouter (strip the prefix → actual model ID)
    - "groq/..."        → Groq (strip the prefix)
    - "gpt-..."         → OpenAI direct
    - "claude-..."      → Anthropic
    - "gemini-..."      → Google
    - "ollama/..."      → Ollama (strip the prefix)
    - anything else     → OpenRouter fallback (with warning)
    """
    mc = model_choice.strip()

    if mc.startswith("openrouter/"):
        actual = mc[len("openrouter/"):]
        base = (OPENROUTER_BASE_URL or "https://openrouter.ai/api/v1").rstrip("/")
        return {
            "class": ChatOpenAI,
            "constructor_params": {
                "model_name": actual,
                "base_url": base,
                "api_key": OPENROUTER_API_KEY,
            },
        }

    if mc.startswith("groq/"):
        actual = mc[len("groq/"):]
        return {
            "class": ChatOpenAI,
            "constructor_params": {
                "model_name": actual,
                "base_url": "https://api.groq.com/openai/v1",
                "api_key": GROQ_API_KEY,
            },
        }

    if mc.startswith("gpt-"):
        return {
            "class": ChatOpenAI,
            "constructor_params": {"model_name": mc, "api_key": OPENAI_API_KEY},
        }

    if mc.startswith("claude-"):
        return {
            "class": ChatAnthropic,
            "constructor_params": {"model": mc, "anthropic_api_key": ANTHROPIC_API_KEY},
        }

    if mc.startswith("gemini-"):
        return {
            "class": ChatGoogleGenerativeAI,
            "constructor_params": {"model": mc, "google_api_key": GOOGLE_API_KEY},
        }

    if mc.startswith("ollama/"):
        actual = mc[len("ollama/"):]
        return {
            "class": ChatOllama,
            "constructor_params": {
                "model": actual,
                "base_url": OLLAMA_BASE_URL or "http://localhost:11434",
            },
        }

    if mc.startswith("lumo/"):
        actual = mc[len("lumo/"):] or "auto"
        return {
            "class": ChatOpenAI,
            "constructor_params": {
                "model": actual,
                "model_name": actual,
                "base_url": LUMO_BASE_URL.rstrip("/"),
                "api_key": os.environ.get("LUMO_API_KEY") or LUMO_API_KEY,
                "streaming": False,
                "stream": False,
                "timeout": 120,
            },
        }

    # Unknown prefix — attempt OpenRouter as fallback
    logger.warning(
        "Unknown model prefix for '%s' — attempting OpenRouter fallback", model_choice
    )
    base = (OPENROUTER_BASE_URL or "https://openrouter.ai/api/v1").rstrip("/")
    return {
        "class": ChatOpenAI,
        "constructor_params": {
            "model_name": mc,
            "base_url": base,
            "api_key": OPENROUTER_API_KEY,
        },
    }


# Patch resolve_model_config to also use prefix routing as its last-resort fallback.
# We keep the original function body intact and append an extra branch here.
_original_resolve_model_config = resolve_model_config


def resolve_model_config(model_choice: str):  # type: ignore[redefined-outer-name]
    """
    Resolve a model choice to the corresponding configuration.

    Lookup order:
    1. Predefined _llm_config_map (case-insensitive, includes all hardcoded models).
    2. llama.cpp dynamic list (/v1/models).
    3. Ollama dynamic list (/api/tags).
    4. Prefix-based routing for dynamic model IDs (openrouter/, groq/, gpt-*, …).
    """
    result = _original_resolve_model_config(model_choice)
    if result is not None:
        return result
    # Fall through to prefix-based dynamic routing
    return _resolve_model_config_by_prefix(model_choice)