"""Cloudflare DNS provider (API Token, dns_records scope)."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

from ..const import CLOUDFLARE_API_BASE, PROVIDER_API_TIMEOUT
from .base import DnsProvider, DnsProviderError

_LOGGER = logging.getLogger(__name__)


class CloudflareProvider(DnsProvider):
    """Cloudflare provider."""

    key = "cloudflare"
    label = "Cloudflare"

    def __init__(self, session: aiohttp.ClientSession, api_token: str) -> None:
        """Store the API token."""
        super().__init__(session)
        self._token = api_token.strip()
        self._headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    async def _async_request(
        self, method: str, path: str, **kwargs: Any
    ) -> dict[str, Any]:
        """Call the v4 API and validate the success envelope."""
        url = f"{CLOUDFLARE_API_BASE}{path}"
        timeout = aiohttp.ClientTimeout(total=PROVIDER_API_TIMEOUT)
        async with self._session.request(
            method, url, headers=self._headers, timeout=timeout, **kwargs
        ) as resp:
            payload = await resp.json(content_type=None)
            status = resp.status

        if status >= 400 or not payload.get("success"):
            errors = payload.get("errors") or []
            message = "; ".join(str(item.get("message", "")) for item in errors)
            raise DnsProviderError(
                f"Cloudflare 接口报错：{message or f'HTTP {status}'}", payload
            )
        return payload

    async def _async_zone_id(self, zone: str) -> str:
        """Resolve the zone id for an exact zone name."""
        payload = await self._async_request(
            "GET", "/zones", params={"name": zone, "per_page": 1}
        )
        result = payload.get("result") or []
        if not result:
            raise DnsProviderError(f"Cloudflare 账号里没有域名 {zone}")
        return str(result[0]["id"])

    async def async_find_zone(self, fqdn: str) -> tuple[str, str]:
        """Ask Cloudflare which zone owns the name."""
        for candidate, index in self._zone_candidates(fqdn):
            try:
                payload = await self._async_request(
                    "GET", "/zones", params={"name": candidate, "per_page": 1}
                )
            except DnsProviderError:
                continue
            result = payload.get("result") or []
            if result:
                relative = ".".join(fqdn.strip().rstrip(".").split(".")[:index]) if index else ""
                return str(result[0]["name"]), relative

        raise DnsProviderError(
            f"在 Cloudflare 账号里找不到 {fqdn} 所属的域名，请确认 API Token 有该域名的 DNS 编辑权限"
        )

    async def async_add_txt(self, zone: str, rr: str, value: str, ttl: int = 600) -> str:
        """Create a TXT record and return a zone_id|record_id handle."""
        zone_id = await self._async_zone_id(zone)
        name = f"{rr}.{zone}" if rr else zone
        payload = await self._async_request(
            "POST",
            f"/zones/{zone_id}/dns_records",
            json={
                "type": "TXT",
                "name": name,
                "content": value,
                "ttl": 120,
                "comment": "acme dns-01",
            },
        )
        record = payload.get("result") or {}
        record_id = record.get("id")
        if not record_id:
            raise DnsProviderError("创建 TXT 记录失败：响应缺少记录 id", payload)
        return f"{zone_id}|{record_id}"

    async def async_delete_txt(self, handle: str) -> None:
        """Delete a record created earlier."""
        zone_id, _, record_id = handle.partition("|")
        if not record_id:
            _LOGGER.debug("无效的 Cloudflare 记录句柄：%s", handle)
            return
        try:
            await self._async_request(
                "DELETE", f"/zones/{zone_id}/dns_records/{record_id}"
            )
        except DnsProviderError as err:
            if "not found" in str(err).lower() or "81044" in str(err):
                _LOGGER.debug("TXT 记录已不存在，无需删除：%s", record_id)
                return
            raise

    async def async_list_txt(self, zone: str, rr: str) -> list[str]:
        """List TXT records at a relative name."""
        zone_id = await self._async_zone_id(zone)
        name = f"{rr}.{zone}" if rr else zone
        payload = await self._async_request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            params={"type": "TXT", "name": name, "per_page": 100},
        )
        return [
            f"{zone_id}|{item.get('id')}"
            for item in payload.get("result") or []
            if item.get("id")
        ]
