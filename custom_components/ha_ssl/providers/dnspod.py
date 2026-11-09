"""Tencent Cloud DNSPod provider (dnsapi.cn, 传统 API).

Credentials are the API token pair (ID,Token) from DNSPod 密钥管理. The
traditional API only accepts a main-account token, so sub-accounts are not
supported by design.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import aiohttp

from ..const import DNSPOD_ENDPOINT, PROVIDER_API_TIMEOUT
from .base import DnsProvider, DnsProviderError

_LOGGER = logging.getLogger(__name__)

RECORD_LINE = "默认"
EMPTY_RESULT = "10"
DUPLICATE_RECORD = "104"
NOT_FOUND_CODES = {"8", "10"}
MAX_PAGE_SIZE = 3000


class DnspodProvider(DnsProvider):
    """DNSPod provider."""

    key = "dnspod"
    label = "腾讯云 DNSPod"

    def __init__(self, session: aiohttp.ClientSession, token_id: str, token: str) -> None:
        """Store the API token pair."""
        super().__init__(session)
        self._login_token = f"{token_id.strip()},{token.strip()}"

    async def _async_post(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        """Call one endpoint; only status code 1 counts as success."""
        data = {
            "login_token": self._login_token,
            "format": "json",
            "lang": "zh",
            **params,
        }
        timeout = aiohttp.ClientTimeout(total=PROVIDER_API_TIMEOUT)
        async with self._session.post(
            f"{DNSPOD_ENDPOINT}{path}",
            data=data,
            timeout=timeout,
            headers={"User-Agent": "ha-ssl (Home Assistant)"},
        ) as resp:
            text = await resp.text()
            try:
                payload = json.loads(text)
            except ValueError as err:
                raise DnsProviderError(
                    f"DNSPod 返回非 JSON 响应：HTTP {resp.status}"
                ) from err

        status = payload.get("status") or {}
        code = str(status.get("code"))
        if code != "1":
            message = status.get("message") or f"HTTP {resp.status}"
            raise DnsProviderError(
                f"DNSPod 接口报错（{code}）：{message}", payload, code
            )
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
        for index in range(0, len(labels) - 1):
            candidate = ".".join(labels[index:])
            if candidate in domains:
                relative = ".".join(labels[:index]) if index else ""
                return candidate, relative

        raise DnsProviderError(
            f"在 DNSPod 账号里找不到 {fqdn} 所属的域名，请确认该 API Token 有域名管理权限"
        )

    async def async_add_txt(self, zone: str, rr: str, value: str, ttl: int = 600) -> str:
        """Create a TXT record and return a zone|record_id handle."""
        try:
            payload = await self._async_post(
                "Record.Create",
                {
                    "domain": zone,
                    "sub_domain": rr,
                    "record_type": "TXT",
                    "record_line": RECORD_LINE,
                    "value": value,
                    "ttl": str(max(600, ttl)),
                },
            )
        except DnsProviderError as err:
            if err.code != DUPLICATE_RECORD:
                raise
            handle = await self._async_find_handle(zone, rr, value)
            if handle is None:
                raise DnsProviderError(
                    f"DNSPod 提示记录已存在，但没能找到对应的 TXT 记录：{rr}.{zone}"
                ) from err
            _LOGGER.debug("TXT 记录已存在，复用 %s", handle)
            return handle

        record = payload.get("record") or {}
        record_id = record.get("id")
        if not record_id:
            raise DnsProviderError("创建 TXT 记录失败：响应缺少 record.id", payload)
        return f"{zone}|{record_id}"

    async def _async_find_handle(self, zone: str, rr: str, value: str) -> str | None:
        """Find an existing TXT record with the same value."""
        payload = await self._async_post(
            "Record.List",
            {
                "domain": zone,
                "sub_domain": rr,
                "record_type": "TXT",
                "length": str(MAX_PAGE_SIZE),
            },
        )
        for item in payload.get("records") or []:
            if item.get("value") == value and item.get("id"):
                return f"{zone}|{item['id']}"
        return None

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
            if err.code in NOT_FOUND_CODES or "不存在" in str(err):
                _LOGGER.debug("TXT 记录已不存在，无需删除：%s", record_id)
                return
            raise

    async def async_list_txt(self, zone: str, rr: str) -> list[str]:
        """List TXT records at a relative name."""
        handles: list[str] = []
        offset = 0
        while True:
            try:
                payload = await self._async_post(
                    "Record.List",
                    {
                        "domain": zone,
                        "sub_domain": rr,
                        "record_type": "TXT",
                        "offset": str(offset),
                        "length": str(MAX_PAGE_SIZE),
                    },
                )
            except DnsProviderError as err:
                if err.code == EMPTY_RESULT:
                    return handles
                raise

            records = payload.get("records") or []
            for item in records:
                if item.get("name") == rr and item.get("type") == "TXT" and item.get("id"):
                    handles.append(f"{zone}|{item['id']}")

            returned = int((payload.get("info") or {}).get("records_num") or len(records))
            if returned < MAX_PAGE_SIZE:
                return handles
            offset += returned
