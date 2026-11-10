"""连通性探测：确认这台 HA 能连上哪些 ACME 目录。"""

from __future__ import annotations

import asyncio
import time

import pathlib

import aiohttp

CONFIG_FILE = "/config/configuration.yaml"

ACME_CANDIDATES = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "zerossl": "https://acme.zerossl.com/v2/DV90",
    "google": "https://dv.acme-v02.api.pki.goog/directory",
    "buypass": "https://api.buypass.com/acme/directory",
    "controls": "https://github.com",
}


async def _async_probe_one(
    session: aiohttp.ClientSession, name: str, url: str, timeout: int
) -> dict[str, object]:
    started = time.monotonic()
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout)
        ) as resp:
            await resp.read()
            status = resp.status
        return {
            "name": name,
            "url": url,
            "ok": status < 500,
            "status": status,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }
    except (aiohttp.ClientError, asyncio.TimeoutError) as err:
        return {
            "name": name,
            "url": url,
            "ok": False,
            "error": f"{type(err).__name__}: {err}",
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }


async def async_probe_cas(
    session: aiohttp.ClientSession, timeout: int = 15
) -> list[dict[str, object]]:
    """Probe every candidate ACME directory in parallel."""
    return await asyncio.gather(
        *(
            _async_probe_one(session, name, url, timeout)
            for name, url in ACME_CANDIDATES.items()
        )
    )


def read_http_section() -> dict[str, object]:
    """Return what the http: block of configuration.yaml currently looks like."""
    path = pathlib.Path(CONFIG_FILE)
    if not path.exists():
        return {"exists": False}
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    http_lines: list[str] = []
    for index, line in enumerate(lines):
        if line.strip() == "http:":
            http_lines = lines[index : index + 6]
            break
    return {
        "exists": True,
        "has_ssl_certificate": "ssl_certificate" in text,
        "http_block": http_lines,
        "tail": lines[-6:],
    }
