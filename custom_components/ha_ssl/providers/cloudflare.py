"""Cloudflare DNS provider (API Token with Zone.DNS edit)."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

from ..const import CLOUDFLARE_API_BASE, PROVIDER_API_TIMEOUT
from .base import DnsProvider, DnsProviderError

_LOGGER = logging.getLogger(__name__)

# Cloudflare 要求 /zones 的 per_page 在 5~50 之间
ZONE_PAGE_SIZE = 5
RECORD_PAGE_SIZE = 100
MAX_PAGES = 10
RECORD_NOT_FOUND = "81044"


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
            code = str(errors[0].get("code")) if errors and errors[0].get("code") else None
            raise DnsProviderError(
                f"Cloudflare 接口报错（{code or status}）：{message or '请求失败'}",
                payload,
                code,
            )
        return payload

    async def _async_zone(self, zone: str) -> dict[str, Any] | None:
        """Look up a zone by its exact name."""
        payload = await self._async_request(
            "GET", "/zones", params={"name": zone, "per_page": ZONE_PAGE_SIZE}
        )
        for item in payload.get("result") or []:
            if str(item.get("name", "")).lower() == zone.lower():
                return item
        return None

    async def _async_zone_id(self, zone: str) -> str:
        """Resolve the zone id for an exact zone name."""
        item = await self._async_zone(zone)
        if item is None:
            raise DnsProviderError(f"Cloudflare 账号里没有域名 {zone}")
        return str(item["id"])

    async def async_find_zone(self, fqdn: str) -> tuple[str, str]:
        """Ask Cloudflare which zone owns the name."""
        labels = fqdn.strip().rstrip(".").split(".")
        for index in range(0, len(labels) - 1):
            candidate = ".".join(labels[index:])
            try:
                item = await self._async_zone(candidate)
            except DnsProviderError as err:
                if err.code in {"1000", "10000"}:
                    continue
                raise
            if item is not None:
                relative = ".".join(labels[:index]) if index else ""
                return str(item["name"]), relative

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
                "ttl": max(60, ttl),
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
            if err.code == RECORD_NOT_FOUND or "does not exist" in str(err).lower():
                _LOGGER.debug("TXT 记录已不存在，无需删除：%s", record_id)
                return
            raise

    async def async_list_txt(self, zone: str, rr: str) -> list[str]:
        """List TXT records at a relative name by filtering locally.

        dns_records 的 name 查询参数已经是对象过滤器（exact/contains/...），
        这里按类型取回再在本地比对完整名称，避免依赖查询参数的语义。
        """
        zone_id = await self._async_zone_id(zone)
        target = (f"{rr}.{zone}" if rr else zone).lower()
        handles: list[str] = []

        page = 1
        while page <= MAX_PAGES:
            payload = await self._async_request(
                "GET",
                f"/zones/{zone_id}/dns_records",
                params={"type": "TXT", "page": page, "per_page": RECORD_PAGE_SIZE},
            )
            for item in payload.get("result") or []:
                if (
                    str(item.get("name", "")).lower().rstrip(".") == target
                    and item.get("id")
                ):
                    handles.append(f"{zone_id}|{item['id']}")

            info = payload.get("result_info") or {}
            total_pages = int(info.get("total_pages") or 1)
            if page >= total_pages:
                break
            page += 1

        return handles
