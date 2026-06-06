"""
Settings API — per-user API key management.

GET    /settings/api-keys          — list key names and their configured status
POST   /settings/api-keys          — upsert a key
DELETE /settings/api-keys/{key_name} — remove a user's key
POST   /settings/api-keys/test     — test a key without saving it
GET    /settings/models            — list available models per configured provider
POST   /settings/models/validate   — test a model ID is accessible

All routes require authentication (JWT).
"""

import asyncio
import time
from typing import Annotated, Optional, List

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import select as sa_select

from api.auth import get_current_user, require_password_not_reset_pending, CurrentUser
from db.models import UserApiKey
from db.session import get_async_session
from utils.encryption import encrypt_api_key


router = APIRouter(prefix="/settings", tags=["settings"])


ALLOWED_KEY_NAMES = {
    "OPENAI_API_KEY": {
        "label": "OpenAI",
        "description": "Enables GPT-4o and GPT-4 models",
        "test_url": "https://api.openai.com/v1/models",
        "test_header": "Authorization",
        "test_prefix": "Bearer ",
    },
    "ANTHROPIC_API_KEY": {
        "label": "Anthropic",
        "description": "Enables Claude models",
        "test_url": "https://api.anthropic.com/v1/models",
        "test_header": "x-api-key",
        "test_prefix": "",
    },
    "GOOGLE_API_KEY": {
        "label": "Google Gemini",
        "description": "Enables Gemini models (free tier available)",
        "test_url": "https://generativelanguage.googleapis.com/v1/models?key={key}",
        "test_header": None,
        "test_prefix": None,
    },
    "OPENROUTER_API_KEY": {
        "label": "OpenRouter",
        "description": "Access 100+ models including free tier options",
        "test_url": "https://openrouter.ai/api/v1/models",
        "test_header": "Authorization",
        "test_prefix": "Bearer ",
    },
    "GROQ_API_KEY": {
        "label": "Groq (Free tier)",
        "description": "Fast inference — Llama 3.3 70B free. Sign up at console.groq.com",
        "test_url": "https://api.groq.com/openai/v1/models",
        "test_header": "Authorization",
        "test_prefix": "Bearer ",
    },
    "OTX_API_KEY": {
        "label": "AlienVault OTX",
        "description": "Threat intelligence enrichment",
        "test_url": "https://otx.alienvault.com/api/v1/user/me",
        "test_header": "X-OTX-API-KEY",
        "test_prefix": "",
    },
    "VT_API_KEY": {
        "label": "VirusTotal",
        "description": "File hash enrichment (optional)",
        "test_url": "https://www.virustotal.com/api/v3/users/current",
        "test_header": "x-apikey",
        "test_prefix": "",
    },
    "GITHUB_TOKEN": {
        "label": "GitHub Token",
        "description": (
            "Optional. Increases rate limit from 10 to 30 requests/min. "
            "No scopes needed — public repo access only."
        ),
        "test_url": "https://api.github.com/rate_limit",
        "test_header": "Authorization",
        "test_prefix": "Bearer ",
    },
    "GITLAB_TOKEN": {
        "label": "GitLab Token",
        "description": (
            "Optional. Increases rate limit from ~15 to ~60 requests/min. "
            "No scopes needed — public repo access only. "
            "Create at gitlab.com/-/profile/personal_access_tokens."
        ),
        "test_url": "https://gitlab.com/api/v4/user",
        "test_header": "PRIVATE-TOKEN",
        "test_prefix": "",
    },
    "SECURITYTRAILS_API_KEY": {
        "label": "SecurityTrails API Key",
        "description": (
            "Optional. Enhanced DNS history and domain infrastructure data. "
            "Free tier: 50 queries/month."
        ),
        "test_url": "https://api.securitytrails.com/v1/ping",
        "test_header": "APIKEY",
        "test_prefix": "",
    },
    "ABUSEIPDB_API_KEY": {
        "label": "AbuseIPDB",
        "description": (
            "Community IP abuse reports. "
            "Free tier: 1000 checks/day. "
            "Sign up at abuseipdb.com/register"
        ),
        "test_url": "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=1",
        "test_header": "Key",
        "test_prefix": "",
    },
    "GREYNOISE_API_KEY": {
        "label": "GreyNoise",
        "description": (
            "IP noise classification. "
            "Suppresses known benign scanners (Shodan, Censys, researchers) from results. "
            "Sign up at greynoise.io/pricing"
        ),
        "test_url": "https://api.greynoise.io/v3/community/8.8.8.8",
        "test_header": "key",
        "test_prefix": "",
    },
    "URLSCAN_API_KEY": {
        "label": "URLScan.io",
        "description": (
            "Domain scan data and malicious URL detection. "
            "Optional — free public data available without key. "
            "Sign up at urlscan.io/user/signup"
        ),
        "test_url": "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1",
        "test_header": "API-Key",
        "test_prefix": "",
    },
    "HYBRID_ANALYSIS_API_KEY": {
        "label": "Hybrid Analysis",
        "description": (
            "Malware sandbox behavioral analysis. "
            "Extracts verdicts, malware families, AV detections, and network IOCs "
            "from file hashes. Free tier available."
        ),
        "test_url": "https://www.hybrid-analysis.com/api/v2/key/current",
        "test_header": "api-key",
        "test_prefix": "",
    },
    "HIBP_API_KEY": {
        "label": "HaveIBeenPwned",
        "description": (
            "Email breach lookup. Paid API ($3.50/month individual). "
            "Most valuable for threat actor attribution — breach history can expose "
            "password reuse patterns and reveal real identity across platforms. "
            "Sign up at haveibeenpwned.com/API/Key"
        ),
        "test_url": "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com",
        "test_header": "hibp-api-key",
        "test_prefix": "",
    },
    "EMAILREP_API_KEY": {
        "label": "EmailRep",
        "description": (
            "Email reputation scoring, disposable detection, and platform presence. "
            "Works without a key at reduced rate limits. "
            "Key increases throughput for large investigations."
        ),
        "test_url": "https://emailrep.io/test@example.com",
        "test_header": "Key",
        "test_prefix": "",
    },
}


class ApiKeyItem(BaseModel):
    key_name: str
    is_set: bool
    server_configured: bool
    label: str
    description: str


class ApiKeyListResponse(BaseModel):
    keys: list[ApiKeyItem]


class UpsertKeyRequest(BaseModel):
    key_name: str
    value: str


class UpsertKeyResponse(BaseModel):
    key_name: str
    is_set: bool


class TestKeyRequest(BaseModel):
    key_name: str
    value: str


class TestKeyResponse(BaseModel):
    valid: bool
    message: str


@router.get("/api-keys", response_model=ApiKeyListResponse)
async def get_api_keys(current_user: CurrentUser = Depends(get_current_user)) -> ApiKeyListResponse:
    async with get_async_session() as session:
        result = await session.execute(
            sa_select(UserApiKey).where(UserApiKey.user_id == current_user.user.id)
        )
        user_keys = {r.key_name: r for r in result.scalars().all()}

        import config as _config

        keys = []
        for key_name, meta in ALLOWED_KEY_NAMES.items():
            is_set = key_name in user_keys
            server_configured = bool(getattr(_config, key_name, None))
            keys.append(
                ApiKeyItem(
                    key_name=key_name,
                    is_set=is_set,
                    server_configured=server_configured,
                    label=meta["label"],
                    description=meta["description"],
                )
            )
        return ApiKeyListResponse(keys=keys)


@router.post("/api-keys", response_model=UpsertKeyResponse)
async def upsert_api_key(
    body: UpsertKeyRequest, current_user: CurrentUser = Depends(require_password_not_reset_pending)
) -> UpsertKeyResponse:
    if body.key_name not in ALLOWED_KEY_NAMES:
        raise HTTPException(status_code=400, detail=f"Unknown key_name: {body.key_name}")

    encrypted = encrypt_api_key(body.value)

    async with get_async_session() as session:
        result = await session.execute(
            sa_select(UserApiKey).where(
                UserApiKey.user_id == current_user.user.id,
                UserApiKey.key_name == body.key_name,
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            existing.encrypted_value = encrypted
        else:
            record = UserApiKey(
                user_id=current_user.user.id,
                key_name=body.key_name,
                encrypted_value=encrypted,
            )
            session.add(record)

        await session.commit()

    return UpsertKeyResponse(key_name=body.key_name, is_set=True)


@router.delete("/api-keys/{key_name}", status_code=204)
async def delete_api_key(key_name: str, current_user: CurrentUser = Depends(get_current_user)) -> Response:
    if key_name not in ALLOWED_KEY_NAMES:
        raise HTTPException(status_code=400, detail=f"Unknown key_name: {key_name}")

    async with get_async_session() as session:
        result = await session.execute(
            sa_select(UserApiKey).where(
                UserApiKey.user_id == current_user.user.id,
                UserApiKey.key_name == key_name,
            )
        )
        record = result.scalar_one_or_none()
        if record:
            await session.delete(record)
            await session.commit()

    return Response(status_code=204)


async def test_github_token(token: str) -> dict:
    """Probe /rate_limit so we can surface the hourly quota the token grants."""
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://api.github.com/rate_limit",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                limit = (
                    data.get("resources", {}).get("core", {}).get("limit", 0)
                )
                return {
                    "valid": True,
                    "message": f"GitHub token valid — {limit} requests/hour",
                }
            return {"valid": False, "message": "Invalid GitHub token"}


async def test_gitlab_token(token: str) -> dict:
    """Probe /user to confirm the token is valid and surface the username."""
    import aiohttp

    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://gitlab.com/api/v4/user",
            headers={"PRIVATE-TOKEN": token},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                username = data.get("username", "unknown")
                return {
                    "valid": True,
                    "message": f"GitLab token valid — authenticated as @{username}",
                }
            if resp.status == 401:
                return {"valid": False, "message": "Invalid or expired GitLab token"}
            return {"valid": False, "message": f"GitLab returned HTTP {resp.status}"}


@router.post("/api-keys/test", response_model=TestKeyResponse)
async def test_api_key(body: TestKeyRequest) -> TestKeyResponse:
    if body.key_name not in ALLOWED_KEY_NAMES:
        raise HTTPException(status_code=400, detail=f"Unknown key_name: {body.key_name}")

    # GitHub: dedicated probe surfaces the actual hourly quota the token grants.
    if body.key_name == "GITHUB_TOKEN":
        try:
            result = await test_github_token(body.value)
            return TestKeyResponse(valid=result["valid"], message=result["message"])
        except Exception as exc:
            return TestKeyResponse(valid=False, message=str(exc))

    # GitLab: dedicated probe surfaces the authenticated username.
    if body.key_name == "GITLAB_TOKEN":
        try:
            result = await test_gitlab_token(body.value)
            return TestKeyResponse(valid=result["valid"], message=result["message"])
        except Exception as exc:
            return TestKeyResponse(valid=False, message=str(exc))

    meta = ALLOWED_KEY_NAMES[body.key_name]
    test_url = meta["test_url"]
    test_header = meta["test_header"]
    test_prefix = meta["test_prefix"]

    if test_header is None:
        test_url = test_url.replace("{key}", body.value)

    headers = {}
    if test_header and test_prefix is not None:
        headers[test_header] = f"{test_prefix}{body.value}"
    elif test_header:
        headers[test_header] = body.value

    try:
        import aiohttp

        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as http_session:
            async with http_session.get(test_url, headers=headers) as resp:
                if resp.status in (200, 201):
                    return TestKeyResponse(valid=True, message="Connected successfully")
                text = await resp.text()
                return TestKeyResponse(
                    valid=False, message=f"API returned {resp.status}: {text[:200]}"
                )
    except aiohttp.ClientError as exc:
        return TestKeyResponse(valid=False, message=f"Connection failed: {exc}")
    except Exception as exc:
        return TestKeyResponse(valid=False, message=str(exc))


# ---------------------------------------------------------------------------
# Model List — GET /settings/models
# ---------------------------------------------------------------------------

# Simple in-memory TTL cache: {user_id: (timestamp, result)}
_models_cache: dict = {}
_MODELS_CACHE_TTL = 300  # 5 minutes

# Simple per-user validate rate-limit: {user_id: [timestamps]}
_validate_rate: dict = {}
_VALIDATE_RATE_LIMIT = 10   # max calls per minute
_VALIDATE_RATE_WINDOW = 60  # seconds


class ModelInfo(BaseModel):
    id: str
    name: str
    provider: str
    free_tier: bool = False
    recommended: bool = False
    context_window: Optional[int] = None


class ProviderInfo(BaseModel):
    name: str
    key_name: str
    configured: bool
    models: List[ModelInfo]


class ModelListResponse(BaseModel):
    providers: List[ProviderInfo]
    custom_model_allowed: bool = True


class ValidateModelRequest(BaseModel):
    model_id: str


class ValidateModelResponse(BaseModel):
    valid: bool
    model_id: str
    provider: Optional[str] = None
    message: str
    error: Optional[str] = None
    suggestion: Optional[str] = None


def _infer_provider(model_id: str) -> str:
    """Return a friendly provider name from a model ID."""
    mc = model_id.lower()
    if mc.startswith("openrouter/"):
        return "OpenRouter"
    if mc.startswith("groq/"):
        return "Groq"
    if mc.startswith("gpt-"):
        return "OpenAI"
    if mc.startswith("claude-"):
        return "Anthropic"
    if mc.startswith("gemini-"):
        return "Google"
    if mc.startswith("ollama/"):
        return "Ollama"
    return "OpenRouter"


async def _fetch_openrouter_models(api_key: str) -> List[ModelInfo]:
    """Fetch models from OpenRouter API, capped at 100."""
    import aiohttp
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
        raw = data.get("data", [])
        models = []
        for m in raw[:100]:
            mid = m.get("id", "")
            if not mid:
                continue
            name = m.get("name") or mid.split("/")[-1]
            ctx = m.get("context_length") or m.get("context_window")
            is_free = ":free" in mid or "free" in (m.get("pricing", {}).get("prompt", "") or "0")
            models.append(ModelInfo(
                id=f"openrouter/{mid}",
                name=name,
                provider="OpenRouter",
                free_tier=is_free,
                recommended=is_free,
                context_window=int(ctx) if ctx else None,
            ))
        return models
    except Exception:
        return []


async def _fetch_groq_models(api_key: str) -> List[ModelInfo]:
    """Fetch models from Groq API."""
    import aiohttp
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(
                "https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
        raw = data.get("data", [])
        models = []
        for m in raw:
            mid = m.get("id", "")
            if not mid:
                continue
            models.append(ModelInfo(
                id=f"groq/{mid}",
                name=mid.replace("-", " ").title(),
                provider="Groq",
                free_tier=True,
                recommended="llama-3.3" in mid or "70b" in mid,
            ))
        return models
    except Exception:
        return []


async def _fetch_openai_models(api_key: str) -> List[ModelInfo]:
    """Fetch GPT-4* and GPT-3.5* models from OpenAI."""
    import aiohttp
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
        raw = data.get("data", [])
        models = []
        for m in raw:
            mid = m.get("id", "")
            if not (mid.startswith("gpt-4") or mid.startswith("gpt-3.5")):
                continue
            models.append(ModelInfo(
                id=mid,
                name=mid,
                provider="OpenAI",
                recommended="gpt-4o" in mid,
            ))
        return sorted(models, key=lambda x: x.id)
    except Exception:
        return []


async def _fetch_ollama_models(base_url: str) -> List[ModelInfo]:
    """Fetch locally available Ollama models."""
    import aiohttp
    try:
        url = base_url.rstrip("/") + "/api/tags"
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(url) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
        models = []
        for m in data.get("models", []):
            name = m.get("name") or m.get("model", "")
            if not name:
                continue
            models.append(ModelInfo(
                id=f"ollama/{name}",
                name=name,
                provider="Ollama",
                free_tier=True,
            ))
        return models
    except Exception:
        return []


@router.get("/models", response_model=ModelListResponse)
async def get_models(
    current_user: CurrentUser = Depends(get_current_user),
) -> ModelListResponse:
    """Return all available models grouped by provider, based on configured API keys."""
    user_id = current_user.user.id

    # TTL cache check
    cached = _models_cache.get(user_id)
    if cached and (time.time() - cached[0]) < _MODELS_CACHE_TTL:
        return cached[1]

    import config as _config

    # Resolve effective keys (user override > server)
    async with get_async_session() as session:
        from utils.user_keys import resolve_api_key
        keys = {}
        for key_name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
                         "OPENROUTER_API_KEY", "GROQ_API_KEY"):
            keys[key_name] = await resolve_api_key(user_id, key_name, session)

    openrouter_key = keys.get("OPENROUTER_API_KEY") or ""
    groq_key = keys.get("GROQ_API_KEY") or ""
    openai_key = keys.get("OPENAI_API_KEY") or ""
    anthropic_key = keys.get("ANTHROPIC_API_KEY") or ""
    google_key = keys.get("GOOGLE_API_KEY") or ""
    ollama_url = getattr(_config, "OLLAMA_BASE_URL", "") or ""

    # Fetch live model lists concurrently where available
    fetch_tasks = []
    task_labels = []

    if openrouter_key:
        fetch_tasks.append(_fetch_openrouter_models(openrouter_key))
        task_labels.append("openrouter")
    if groq_key:
        fetch_tasks.append(_fetch_groq_models(groq_key))
        task_labels.append("groq")
    if openai_key:
        fetch_tasks.append(_fetch_openai_models(openai_key))
        task_labels.append("openai")
    if ollama_url:
        fetch_tasks.append(_fetch_ollama_models(ollama_url))
        task_labels.append("ollama")

    fetched_results = {}
    if fetch_tasks:
        results = await asyncio.gather(*fetch_tasks, return_exceptions=True)
        for label, result in zip(task_labels, results):
            fetched_results[label] = result if isinstance(result, list) else []

    # Hardcoded model lists for providers without free list APIs
    anthropic_models = [
        ModelInfo(id="claude-opus-4-5", name="Claude Opus 4.5", provider="Anthropic", recommended=True),
        ModelInfo(id="claude-sonnet-4-5", name="Claude Sonnet 4.5", provider="Anthropic", recommended=True),
        ModelInfo(id="claude-haiku-4-5-20251001", name="Claude Haiku 4.5", provider="Anthropic"),
    ]
    google_models = [
        ModelInfo(id="gemini-2.0-flash", name="Gemini 2.0 Flash", provider="Google", recommended=True),
        ModelInfo(id="gemini-1.5-pro", name="Gemini 1.5 Pro", provider="Google"),
        ModelInfo(id="gemini-1.5-flash", name="Gemini 1.5 Flash", provider="Google"),
    ]

    providers = [
        ProviderInfo(
            name="OpenRouter",
            key_name="OPENROUTER_API_KEY",
            configured=bool(openrouter_key),
            models=fetched_results.get("openrouter", []),
        ),
        ProviderInfo(
            name="Groq",
            key_name="GROQ_API_KEY",
            configured=bool(groq_key),
            models=fetched_results.get("groq", []),
        ),
        ProviderInfo(
            name="Anthropic",
            key_name="ANTHROPIC_API_KEY",
            configured=bool(anthropic_key),
            models=anthropic_models if anthropic_key else [],
        ),
        ProviderInfo(
            name="OpenAI",
            key_name="OPENAI_API_KEY",
            configured=bool(openai_key),
            models=fetched_results.get("openai", []),
        ),
        ProviderInfo(
            name="Google",
            key_name="GOOGLE_API_KEY",
            configured=bool(google_key),
            models=google_models if google_key else [],
        ),
        ProviderInfo(
            name="Ollama",
            key_name="",
            configured=bool(ollama_url),
            models=fetched_results.get("ollama", []),
        ),
    ]

    response = ModelListResponse(providers=providers, custom_model_allowed=True)
    _models_cache[user_id] = (time.time(), response)
    return response


# ---------------------------------------------------------------------------
# Model Validate — POST /settings/models/validate
# ---------------------------------------------------------------------------

@router.post("/models/validate", response_model=ValidateModelResponse)
async def validate_model(
    body: ValidateModelRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> ValidateModelResponse:
    """
    Test whether a model ID is accessible with the current keys.
    Makes a minimal 1-token API call and returns typed success/failure.
    Rate limited to 10 requests per minute per user.
    """
    user_id = current_user.user.id
    model_id = body.model_id.strip()

    # Per-user rate limiting
    now = time.time()
    history = _validate_rate.get(user_id, [])
    history = [t for t in history if now - t < _VALIDATE_RATE_WINDOW]
    if len(history) >= _VALIDATE_RATE_LIMIT:
        return ValidateModelResponse(
            valid=False,
            model_id=model_id,
            error="rate_limited",
            message="Too many validation requests. Please wait a moment and try again.",
        )
    history.append(now)
    _validate_rate[user_id] = history

    if not model_id:
        return ValidateModelResponse(
            valid=False,
            model_id=model_id,
            error="model_not_found",
            message="Model ID cannot be empty.",
        )

    # Resolve user keys
    async with get_async_session() as session:
        from utils.user_keys import resolve_api_key
        api_keys = {}
        for key_name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
                         "OPENROUTER_API_KEY", "GROQ_API_KEY"):
            api_keys[key_name] = await resolve_api_key(user_id, key_name, session)

    provider = _infer_provider(model_id)

    try:
        from open_intel.llm_utils import resolve_model_config, _common_llm_params
        from langchain_openai import ChatOpenAI
        from langchain_anthropic import ChatAnthropic
        from langchain_google_genai import ChatGoogleGenerativeAI
        from langchain_ollama import ChatOllama

        config = resolve_model_config(model_id)
        if config is None:
            return ValidateModelResponse(
                valid=False,
                model_id=model_id,
                provider=provider,
                error="model_not_found",
                message=f"Model '{model_id}' could not be resolved to any provider.",
                suggestion="Check the model ID or browse available models.",
            )

        llm_class = config["class"]
        ctor_params = dict(config.get("constructor_params", {}))

        # Inject user-override API keys into constructor params
        _ENV_TO_PARAM = {
            "OPENAI_API_KEY": "api_key",
            "OPENROUTER_API_KEY": "api_key",
            "ANTHROPIC_API_KEY": "anthropic_api_key",
            "GOOGLE_API_KEY": "google_api_key",
            "GROQ_API_KEY": "api_key",
        }
        for env_key, param_key in _ENV_TO_PARAM.items():
            user_val = api_keys.get(env_key)
            if user_val:
                ctor_params[param_key] = user_val

        # Build minimal (non-streaming) LLM instance for probe
        probe_params = {k: v for k, v in _common_llm_params.items() if k != "streaming"}
        probe_params["streaming"] = False
        all_params = {**probe_params, **ctor_params, "max_tokens": 1}

        def _probe():
            llm = llm_class(**all_params)
            llm.invoke("hi")

        await asyncio.wait_for(asyncio.to_thread(_probe), timeout=15)

        return ValidateModelResponse(
            valid=True,
            model_id=model_id,
            provider=provider,
            message="Model accessible",
        )

    except asyncio.TimeoutError:
        return ValidateModelResponse(
            valid=False,
            model_id=model_id,
            provider=provider,
            error="provider_error",
            message="Model validation timed out. The provider may be slow or unreachable.",
        )
    except ValueError as exc:
        msg = str(exc)
        if "No API key" in msg or "not set" in msg.lower():
            return ValidateModelResponse(
                valid=False,
                model_id=model_id,
                provider=provider,
                error="no_key_configured",
                message=msg,
                suggestion="Add the required API key in Settings.",
            )
        return ValidateModelResponse(
            valid=False,
            model_id=model_id,
            provider=provider,
            error="model_not_found",
            message=msg,
            suggestion="Browse available models or check the provider docs for valid IDs.",
        )
    except Exception as exc:
        exc_str = str(exc)
        if "401" in exc_str or "authentication" in exc_str.lower() or "invalid api key" in exc_str.lower():
            return ValidateModelResponse(
                valid=False,
                model_id=model_id,
                provider=provider,
                error="invalid_api_key",
                message="API key is invalid or expired. Check your key in Settings.",
            )
        if "404" in exc_str or "not found" in exc_str.lower() or "does not exist" in exc_str.lower():
            return ValidateModelResponse(
                valid=False,
                model_id=model_id,
                provider=provider,
                error="model_not_found",
                message=f"Model '{model_id}' not found. Check the model ID and try again.",
                suggestion=f"Browse available models or check https://openrouter.ai/models for valid IDs.",
            )
        if "429" in exc_str or "rate limit" in exc_str.lower():
            return ValidateModelResponse(
                valid=False,
                model_id=model_id,
                provider=provider,
                error="rate_limited",
                message="Provider rate limit hit. Try again in a moment.",
            )
        return ValidateModelResponse(
            valid=False,
            model_id=model_id,
            provider=provider,
            error="provider_error",
            message=f"Provider returned an unexpected error: {exc_str[:200]}",
        )

