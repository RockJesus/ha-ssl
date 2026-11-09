"""Tencent Cloud DNSPod provider (dnsapi.cn).

Credentials are the API token pair (ID,Token) from DNSPod 账号设置 → 密钥管理.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import aiohttp

from ..const import PROVIDER_API_TIMEOUT, DNSPOD_ENDPOINT
from .base import DnsProvider, DnsProviderError

_LOGGER = logging.getLogger(__name__)

RECORD_LINE = "默认"


class DnspodProvider(DnsProvider):
    """DNSPod provider."""

    key = "dnspod"
    label = "腾讯云 DNSPod"

    def __init__(self, session: aiohttp.ClientSession, token_id: str, token: str) -> None:
        """Store the API token pair."""
        super().__init__(session)
        self._login_token = f"{token_id.strip()},{token.strip()}"

    async def _async_post(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        """Call one API endpoint and unwrap the status envelope."""
        data = {
            "login_token": self._login_token,
            "format": "json",
            "lang": "zh",
            **params,
        }
        timeout = aiohttp.ClientTimeout(total=PROVIDER_API_TIMEOUT)
        async with self._session.post(f"{DNSPOD_ENDPOINT}{path}", data=data, timeout=timeout) as resp:
            text = await resp.text()
            try:
                payload = json.loads(text)
            except ValueError as err:
                raise DnsProviderError(f"DNSPod 返回非 JSON 响应：HTTP {resp.status}") from err

        status = payload.get("status") or {}
        if str(status.get("code")) != "1":
            message = status.get("message") or f"HTTP {resp.status}"
            raise DnsProviderError(f"DNSPod 接口报错：{message}", payload)
        return payload

    async def async_find_zone(self, fqdn: str) -> tuple[str, str]:
        """Match the name against the domain list of the account."""
        payload = await self._async_post("Domain.List", {})
        domains = [
            str(item.get("name", ""))
            for item in payload.get("domains") or []
            if item.get("name")
        ]

        labels = fqdn.strip().rstrip(".").split(".")
        best: tuple[str, int] | None = None
        for index in range(0, len(labels) - 1):
            candidate = ".".join(labels[index:])
            if candidate in domains and (best is None or index < best[1]):
                best = (candidate, index)
                break

        if best is None:
            raise DnsProviderError(
                f"在 DNSPod 账号里找不到 {fqdn} 所属的域名，请确认 API 密钥有该域名的管理权限"
            )

        zone, index = best
        relative = ".".join(labels[:index]) if index else ""
        return zone, relative

    async def async_add_txt(self, zone: str, rr: str, value: str, ttl: int = 600) -> str:
        """Create a TXT record and return a zone|record handle."""
        payload = await self._async_post(
            "Record.Create",
            {
                "domain": zone,
                "sub_domain": rr,
                "record_type": "TXT",
                "record_line": RECORD_LINE,
                "value": value,
                "ttl": str(ttl),
            },
        )
        record = payload.get("record") or {}
        record_id = record.get("id")
        if not record_id:
            raise DnsProviderError("创建 TXT 记录失败：响应缺少 record.id", payload)
        return f"{zone}|{record_id}"

    async def async_delete_txt(self, handle: str) -> None:
        """Delete a record created earlier."""
        zone, _, record_id = handle.partition("|")
        if not record_id:
            _LOGGER.debug("无效的 DNSPod 记录句柄：%s", handle)
            return
        try:
            await self._async_post(
                "Record.Remove", {"domain": zone, "record_id": record_id}
            )
        except DnsProviderError as err:
            if "不存在" in str(err) or "not exist" in str(err).lower():
                _LOGGER.debug("TXT 记录已不存在，无需删除：%s", record_id)
                return
            raise

    async def async_list_txt(self, zone: str, rr: str) -> list[str]:
        """List TXT records at a relative name."""
        payload = await self._async_post(
            "Record.List",
            {"domain": zone, "sub_domain": rr, "record_type": "TXT"},
        )
        return [
            f"{zone}|{item.get('id')}"
            for item in payload.get("records") or []
            if item.get("id")
        ]
