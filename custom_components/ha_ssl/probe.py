"""连通性探测：确认这台 HA 能连上哪些 ACME 目录。"""

from __future__ import annotations

import asyncio
import time

import json
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


async def async_probe_self(session: aiohttp.ClientSession) -> list[dict[str, object]]:
    """Check what protocol the local HA instance is actually serving."""
    results: list[dict[str, object]] = []
    for scheme, ssl_flag in (("http", False), ("https", False)):
        started = time.monotonic()
        url = f"{scheme}://127.0.0.1:8123/api/"
        kwargs: dict[str, object] = {"timeout": aiohttp.ClientTimeout(total=10)}
        if scheme == "https":
            kwargs["ssl"] = ssl_flag
        try:
            async with session.get(url, **kwargs) as resp:
                await resp.read()
                results.append(
                    {
                        "scheme": scheme,
                        "status": resp.status,
                        "elapsed_ms": int((time.monotonic() - started) * 1000),
                    }
                )
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            results.append(
                {
                    "scheme": scheme,
                    "error": f"{type(err).__name__}: {err}",
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                }
            )
    return results


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
    blocks: list[list[str]] = []
    for index, line in enumerate(lines):
        if line.strip() == "http:":
            blocks.append(lines[index : index + 8])

    def _stat(path: str) -> dict[str, object]:
        item = pathlib.Path(path)
        try:
            info = item.stat()
            return {"path": path, "exists": True, "size": info.st_size}
        except OSError:
            return {"path": path, "exists": False}

    return {
        "exists": True,
        "has_ssl_certificate": "ssl_certificate" in text,
        "http_block_count": len(blocks),
        "http_blocks": blocks,
        "tail": lines[-6:],
        "certs": [
            _stat("/config/ssl/fullchain.pem"),
            _stat("/config/ssl/privkey.pem"),
            _stat("/ssl/fullchain.pem"),
        ],
    }


def read_http_storage() -> dict[str, object]:
    """Look for the HTTP server settings Home Assistant keeps in .storage."""
    base = pathlib.Path("/config/.storage")
    candidates = ["http", "core.http", "http_server", "network"]
    found: dict[str, object] = {}
    if not base.is_dir():
        return {"storage_dir": False}
    for name in candidates:
        path = base / name
        if path.is_file():
            try:
                found[name] = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError as err:
                found[name] = {"_parse_error": str(err)}
    return {
        "storage_dir": True,
        "files": sorted(item.name for item in base.iterdir() if item.is_file()),
        "matched": found,
    }
