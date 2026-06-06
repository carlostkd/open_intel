"""
cli/tor_detect.py — Locate a running Tor SOCKS5 proxy.

Probe order:
    1. 127.0.0.1:9050  (system tor)
    2. 127.0.0.1:9150  (Tor Browser bundle)
    3. config override (cli/config.py)

Tests by performing a SOCKS5 handshake — no full HTTP round-trip required,
so detection stays fast even when the wider Tor network is slow.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional

from open_intel_cli.config import load_config


@dataclass
class TorStatus:
    proxy_url: Optional[str]
    source: str  # "system_tor" | "tor_browser" | "config" | "none"
    host: Optional[str] = None
    port: Optional[int] = None


def _socks5_handshake(host: str, port: int, timeout: float = 2.0) -> bool:
    """Open TCP, send a SOCKS5 NO-AUTH greeting, expect 0x05 0x00 back."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"\x05\x01\x00")
            resp = sock.recv(2)
            return len(resp) == 2 and resp[0] == 0x05 and resp[1] == 0x00
    except Exception:
        return False


def detect_tor() -> TorStatus:
    cfg = load_config()
    cfg_host = cfg.get("tor", {}).get("host", "127.0.0.1")
    cfg_port = int(cfg.get("tor", {}).get("port", 9050))

    probes = [
        ("system_tor", "127.0.0.1", 9050),
        ("tor_browser", "127.0.0.1", 9150),
    ]
    if (cfg_host, cfg_port) not in {(h, p) for _, h, p in probes}:
        probes.append(("config", cfg_host, cfg_port))

    for source, host, port in probes:
        if _socks5_handshake(host, port):
            return TorStatus(
                proxy_url=f"socks5://{host}:{port}",
                source=source,
                host=host,
                port=port,
            )

    return TorStatus(proxy_url=None, source="none")


def tor_unavailable_message() -> str:
    return (
        "Tor not found. Install: https://torproject.org\n"
        "Or run Tor Browser before investigating.\n"
        "Use --no-tor to skip Tor entirely (clearnet sources only)."
    )
