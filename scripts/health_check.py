import time
import socket
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add the project root to sys.path so we can import from other modules
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from search.search import SEARCH_ENGINES, get_tor_session, USER_AGENTS
from open_intel.llm import get_llm
from open_intel.llm_utils import resolve_model_config
from config import TOR_PROXY_HOST, TOR_PROXY_PORT, DEFAULT_MODEL


def check_tor_proxy():
    """Test that the configured Tor SOCKS5 proxy is accepting connections."""
    try:
        start = time.time()
        sock = socket.create_connection((TOR_PROXY_HOST, int(TOR_PROXY_PORT)), timeout=5)
        sock.close()
        latency_ms = round((time.time() - start) * 1000)
        return {"status": "up", "latency_ms": latency_ms, "error": None}
    except Exception as e:
        return {"status": "down", "latency_ms": None, "error": str(e)}


def check_llm_health(model_choice):
    """
    Test actual connectivity to the selected LLM by sending a minimal prompt.
    Returns {status, latency_ms, error, provider}.
    """
    config = resolve_model_config(model_choice)
    if config is None:
        return {
            "status": "error",
            "latency_ms": None,
            "error": f"Unknown model: {model_choice}",
            "provider": "unknown",
        }

    # Determine provider name for display
    class_name = getattr(config["class"], "__name__", str(config["class"]))
    ctor = config.get("constructor_params", {}) or {}
    if "ChatAnthropic" in class_name:
        provider = "Anthropic"
    elif "ChatGoogleGenerativeAI" in class_name:
        provider = "Google Gemini"
    elif "ChatOllama" in class_name:
        provider = "Ollama (local)"
    elif "ChatOpenAI" in class_name:
        base_url = (ctor.get("base_url") or "").lower()
        if "openrouter" in base_url:
            provider = "OpenRouter"
        elif "llama" in base_url or "localhost" in base_url or "127.0.0.1" in base_url:
            provider = "llama.cpp (local)"
        else:
            provider = "OpenAI"
    else:
        provider = class_name

    try:
        start = time.time()
        llm = get_llm(model_choice)
        # Send a tiny prompt — cheapest possible API call
        response = llm.invoke("Say OK")
        latency_ms = round((time.time() - start) * 1000)
        # Extract text from response
        text = getattr(response, "content", str(response))
        if text and len(text.strip()) > 0:
            return {
                "status": "up",
                "latency_ms": latency_ms,
                "error": None,
                "provider": provider,
            }
        else:
            return {
                "status": "down",
                "latency_ms": latency_ms,
                "error": "Empty response from API",
                "provider": provider,
            }
    except Exception as e:
        latency_ms = round((time.time() - start) * 1000)
        return {
            "status": "down",
            "latency_ms": latency_ms,
            "error": str(e),
            "provider": provider,
        }


def _ping_single_engine(engine):
    """Ping a single search engine via Tor and return its status."""
    name = engine["name"]
    # Extract base URL (host only) from the template URL
    url_template = engine["url"]
    # Use a dummy query to form a valid URL for the ping
    url = url_template.format(query="test")

    try:
        session = get_tor_session()
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        start = time.time()
        resp = session.get(url, headers=headers, timeout=20)
        latency_ms = round((time.time() - start) * 1000)
        return {
            "name": name,
            "status": "up" if resp.status_code == 200 else "down",
            "latency_ms": latency_ms,
            "error": None if resp.status_code == 200 else f"HTTP {resp.status_code}",
        }
    except Exception as e:
        return {
            "name": name,
            "status": "down",
            "latency_ms": None,
            "error": str(e)[:80],
        }


def check_search_engines(max_workers=8):
    """
    Concurrently ping all search engines via Tor.
    Returns a list of per-engine status dicts.
    """
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_engine = {
            executor.submit(_ping_single_engine, eng): eng
            for eng in SEARCH_ENGINES
        }
        for future in as_completed(future_to_engine):
            results.append(future.result())

    # Sort by original engine order
    name_order = {e["name"]: i for i, e in enumerate(SEARCH_ENGINES)}
    results.sort(key=lambda r: name_order.get(r["name"], 999))
    return results


if __name__ == "__main__":
    print("\n--- Open_Intel Health Diagnostic ---\n")
    
    # 1. Tor Check
    print(f"[*] Checking Tor Proxy ({TOR_PROXY_HOST}:{TOR_PROXY_PORT})...", end=" ", flush=True)
    tor = check_tor_proxy()
    if tor["status"] == "up":
        print(f"UP ({tor['latency_ms']}ms)")
    else:
        print(f"DOWN\n    Error: {tor['error']}")
        print("\n[!] Critical failure: Tor is required for dark web access. Exiting.")
        sys.exit(1)

    # 2. LLM Check
    print(f"[*] Checking LLM Connectivity ({DEFAULT_MODEL})...", end=" ", flush=True)
    llm = check_llm_health(DEFAULT_MODEL)
    if llm["status"] == "up":
        print(f"UP ({llm['latency_ms']}ms) via {llm['provider']}")
    else:
        print(f"DOWN\n    Error: {llm['error']}")

    # 3. Search Engines Check
    print(f"[*] Checking {len(SEARCH_ENGINES)} Search Engines via Tor (this may take a moment)...")
    engines = check_search_engines()
    up_engines = [e for e in engines if e["status"] == "up"]
    print(f"[*] Status: {len(up_engines)}/{len(engines)} engines reachable.")
    
    for eng in engines:
        symbol = "✅" if eng["status"] == "up" else "❌"
        latency = f"({eng['latency_ms']}ms)" if eng["latency_ms"] else ""
        err = f" -- {eng['error']}" if eng["error"] else ""
        print(f"    {symbol} {eng['name']:<15} {latency}{err}")

    print("\n--- Diagnostic Complete ---")
