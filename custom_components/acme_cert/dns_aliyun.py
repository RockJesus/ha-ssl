"""Aliyun DNS (AliDNS) RPC client used for dns-01 challenges.

It talks to the OpenAPI directly, so the zone lookup never depends on the
host resolver - which is exactly where the Let's Encrypt add-on fails.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import aiohttp

from .const import ALIYUN_DNS_ENDPOINT, ALIYUN_DNS_VERSION

_LOGGER = logging.getLogger(__name__)


class AliyunDnsError(Exception):
    """Raised when the Aliyun DNS API returns an error payload."""

    def __init__(self, message: str, payload: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.payload = payload or {}


def _percent_encode(value: str) -> str:
    encoded = quote(value, safe="")
    return encoded.replace("+", "%20").replace("*", "%2A").replace("%7E", "~")


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AliyunDnsClient:
    """Minimal client for the records CRUD used by ACME."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        access_key_id: str,
        access_key_secret: str,
    ) -> None:
        self._session = session
        self._key_id = access_key_id.strip()
        self._secret = access_key_secret.strip()

    def _signature(self, params: dict[str, str]) -> str:
        """Compute the RPC HMAC-SHA1 signature."""
        canonical = "&".join(
            f"{_percent_encode(key)}={_percent_encode(params[key])}"
            for key in sorted(params)
        )
        string_to_sign = f"GET&%2F&{_percent_encode(canonical)}"
        digest = hmac.new(
            f"{self._secret}&".encode(), string_to_sign.encode(), hashlib.sha1
        ).digest()
        return base64.b64encode(digest).decode()

    async def _async_request(
        self, action: str, params: dict[str, str]
    ) -> dict[str, Any]:
        common = {
            "AccessKeyId": self._key_id,
            "Action": action,
            "Format": "JSON",
            "SignatureMethod": "HMAC-SHA1",
            "SignatureNonce": uuid.uuid4().hex,
            "SignatureVersion": "1.0",
            "Timestamp": _timestamp(),
            "Version": ALIYUN_DNS_VERSION,
        }
        common.update(params)
        common["Signature"] = self._signature(common)

        query = "&".join(
            f"{_percent_encode(key)}={_percent_encode(value)}"
            for key, value in common.items()
        )
        url = f"{ALIYUN_DNS_ENDPOINT}?{query}"

        timeout = aiohttp.ClientTimeout(total=20)
        async with self._session.get(url, timeout=timeout) as resp:
            text = await resp.text()
            try:
                payload = json.loads(text)
            except ValueError as err:
                raise AliyunDnsError(
                    f"阿里云 DNS 返回非 JSON 响应：HTTP {resp.status}"
                ) from err

        if resp.status >= 400 or payload.get("Code"):
            message = (
                payload.get("Message")
                or payload.get("Recommend")
                or f"HTTP {resp.status}"
            )
            raise AliyunDnsError(f"阿里云 DNS 接口报错：{message}", payload)

        return payload

    async def async_find_zone(self, fqdn: str) -> tuple[str, str]:
        """Return (zone, relative_prefix) for the given FQDN."""
        labels = fqdn.strip().rstrip(".").split(".")
        for index in range(0, len(labels) - 1):
            candidate = ".".join(labels[index:])
            try:
                payload = await self._async_request(
                    "DescribeDomainRecords",
                    {"DomainName": candidate, "PageSize": "1"},
                )
            except AliyunDnsError:
                continue
            if "PageNumber" in payload or "TotalCount" in payload:
                relative = ".".join(labels[:index]) if index else ""
                return candidate, relative

        raise AliyunDnsError(
            f"在阿里云账号里找不到 {fqdn} 所属的域名，请确认 AccessKey 有该域名的解析权限"
        )

    async def async_add_txt(self, zone: str, rr: str, value: str, ttl: int = 600) -> str:
        """Create a TXT record and return its RecordId."""
        payload = await self._async_request(
            "AddDomainRecord",
            {
                "DomainName": zone,
                "RR": rr,
                "Type": "TXT",
                "Value": value,
                "TTL": str(ttl),
            },
        )
        record_id = payload.get("RecordId")
        if not record_id:
            raise AliyunDnsError("创建 TXT 记录失败：响应缺少 RecordId", payload)
        return str(record_id)

    async def async_delete_txt(self, record_id: str) -> None:
        """Delete a record by id, ignoring already-removed records."""
        try:
            await self._async_request("DeleteDomainRecord", {"RecordId": record_id})
        except AliyunDnsError as err:
            if "RecordId" in str(err) or "not exist" in str(err).lower():
                _LOGGER.debug("TXT 记录已不存在，无需删除：%s", record_id)
                return
            raise

    async def async_list_txt(self, zone: str, rr: str) -> list[dict[str, Any]]:
        """List existing TXT records for a relative name."""
        payload = await self._async_request(
            "DescribeDomainRecords",
            {
                "DomainName": zone,
                "RRKeyWord": rr,
                "TypeKeyWord": "TXT",
                "PageSize": "100",
            },
        )
        records = payload.get("DomainRecords", {}).get("Record", [])
        return [item for item in records if item.get("RR") == rr]
