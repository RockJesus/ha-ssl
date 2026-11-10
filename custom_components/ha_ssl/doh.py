"""DoH 解析器：让 ACME 请求绕开宿主机 DNS，并且只走 IPv4。

很多家庭网络里 HA 宿主机拿到的 DNS 结果不可靠（被运营商劫持、返回不可用
的 IPv6 记录），表现为连 Let's Encrypt 的 directory 时直接超时。这里用公共
DoH 端点解析 A 记录，再交给 aiohttp 连接，SNI 仍然是原域名，证书校验不变。
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

DOH_ENDPOINTS = (
    "https://223.5.5.5/resolve",
    "https://dns.alidns.com/resolve",
    "https://dns.google/resolve",
)

_CACHE_TTL = 600


class DohResolverError(OSError):
    """所有 DoH 端点都拿不到地址。"""


class DohResolver(aiohttp.abc.AbstractResolver):
    """只解析 IPv4 的 aiohttp 解析器。"""

    def __init__(self) -> None:
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=8)
        )
        self._cache: dict[str, tuple[str, float]] = {}

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, Any]]:
        ip = await self._async_lookup(host)
        return [
            {
                "hostname": host,
                "host": ip,
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
            }
        ]

    async def _async_lookup(self, host: str) -> str:
        loop = asyncio.get_running_loop()
        cached = self._cache.get(host)
        if cached and cached[1] > loop.time():
            return cached[0]

        errors: list[str] = []
        for endpoint in DOH_ENDPOINTS:
            try:
                ip = await self._async_query(endpoint, host)
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as err:
                errors.append(f"{endpoint}: {type(err).__name__}")
                continue
            if ip:
                self._cache[host] = (ip, loop.time() + _CACHE_TTL)
                return ip
            errors.append(f"{endpoint}: 无 A 记录")

        raise DohResolverError(
            f"DoH 解析 {host} 失败（{'；'.join(errors)}）"
        )

    async def _async_query(self, endpoint: str, host: str) -> str:
        timeout = aiohttp.ClientTimeout(total=8)
        async with self._session.get(
            endpoint,
            params={"name": host, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
        ) as resp:
            if resp.status != 200:
                raise ValueError(f"HTTP {resp.status}")
            data = await resp.json(content_type=None)

        for answer in data.get("Answer") or []:
            if answer.get("type") == 1 and answer.get("data"):
                return str(answer["data"])
        return ""

    async def close(self) -> None:
        """Close the helper session used for DoH queries."""
        await self._session.close()
