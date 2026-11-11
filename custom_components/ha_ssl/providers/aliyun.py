"""Aliyun DNS (阿里云云解析) provider.

Uses the RPC OpenAPI with an AccessKey, so the zone lookup never depends on
the host resolver.
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

from ..const import ALIYUN_API_TIMEOUT, ALIYUN_DNS_ENDPOINT, ALIYUN_DNS_VERSION
from .base import DnsProvider, DnsProviderError

# 严格按错误码判定，不用子串匹配：InvalidAccessKeyId.NotFound 也含 NotFound，
# 直接匹配会把凭据错误误当成“域名不存在”，一路 continue 后报出误导性的错误。
DOMAIN_MISSING_CODES = {
    "domainnotfound",
    "domainnotexist",
    "domainnamenoexist",
    "invaliddomainname.noexist",
    "alirs.domain.domainnotexists",
}
RECORD_MISSING_CODES = {
    "domainrecordnotexist",
    "domainrecordnotbelongtouser",
    "invalidrecordid.notfound",
    "domainrecordnotfound",
}
DUPLICATE_CODES = {"domainrecordduplicate", "domainrecordexists"}


def _code(err: DnsProviderError) -> str:
    """Lower-cased vendor error code."""
    return (err.code or "").strip().lower()


def _is_domain_missing(err: DnsProviderError) -> bool:
    """Whether the vendor error means this account has no such domain."""
    return _code(err) in DOMAIN_MISSING_CODES


def _is_record_missing(err: DnsProviderError) -> bool:
    """Whether the vendor error means the record is already gone."""
    return _code(err) in RECORD_MISSING_CODES


def _is_duplicate(err: DnsProviderError) -> bool:
    """Whether the vendor error means the record already exists."""
    return _code(err) in DUPLICATE_CODES

_LOGGER = logging.getLogger(__name__)


def _percent_encode(value: str) -> str:
    """Encode a parameter the way the Aliyun RPC signature expects."""
    encoded = quote(value, safe="")
    return encoded.replace("+", "%20").replace("*", "%2A").replace("%7E", "~")


def _timestamp() -> str:
    """UTC timestamp in the format the API expects."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AliyunProvider(DnsProvider):
    """Aliyun DNS provider."""

    key = "aliyun"
    label = "阿里云云解析"

    def __init__(
        self,
        session: aiohttp.ClientSession,
        access_key_id: str,
        access_key_secret: str,
    ) -> None:
        """Store the credentials."""
        super().__init__(session)
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

    async def _async_request(self, action: str, params: dict[str, str]) -> dict[str, Any]:
        """Call one RPC action and return the JSON payload."""
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

        timeout = aiohttp.ClientTimeout(total=ALIYUN_API_TIMEOUT)
        async with self._session.get(url, timeout=timeout) as resp:
            text = await resp.text()
            try:
                payload = json.loads(text)
            except ValueError as err:
                raise DnsProviderError(
                    f"阿里云 DNS 返回非 JSON 响应：HTTP {resp.status}"
                ) from err

        if resp.status >= 400 or payload.get("Code"):
            message = (
                payload.get("Message")
                or payload.get("Recommend")
                or f"HTTP {resp.status}"
            )
            code = str(payload.get("Code") or "")
            raise DnsProviderError(
                f"阿里云 DNS 接口报错（{code or resp.status}）：{message}", payload, code
            )

        return payload

    async def async_find_zone(self, fqdn: str) -> tuple[str, str]:
        """Find the zone by walking up the labels through the API."""
        labels = fqdn.strip().rstrip(".").split(".")
        for index in range(0, len(labels) - 1):
            candidate = ".".join(labels[index:])
            try:
                payload = await self._async_request(
                    "DescribeDomainRecords",
                    {"DomainName": candidate, "PageSize": "1"},
                )
            except DnsProviderError as err:
                # 只有“域名不存在”才继续往上找，签名/凭据/权限错误必须直接暴露
                if _is_domain_missing(err):
                    continue
                raise
            if "TotalCount" in payload or "PageNumber" in payload or "DomainRecords" in payload:
                relative = ".".join(labels[:index]) if index else ""
                return candidate, relative

        raise DnsProviderError(
            f"在阿里云账号里找不到 {fqdn} 所属的域名，请确认 AccessKey 有该域名的解析权限"
        )

    async def async_add_txt(self, zone: str, rr: str, value: str, ttl: int = 600) -> str:
        """Create a TXT record and return its RecordId."""
        try:
            payload = await self._async_request(
                "AddDomainRecord",
                {
                    "DomainName": zone,
                    "RR": rr,
                    "Type": "TXT",
                    "Value": value,
                    "TTL": str(max(600, ttl)),
                },
            )
        except DnsProviderError as err:
            if not _is_duplicate(err):
                raise
            for handle in await self.async_list_txt(zone, rr, value):
                return handle
            raise

        record_id = payload.get("RecordId")
        if not record_id:
            raise DnsProviderError("创建 TXT 记录失败：响应缺少 RecordId", payload)
        return str(record_id)

    async def async_delete_txt(self, handle: str) -> None:
        """Delete a record by id, ignoring already-removed records."""
        try:
            await self._async_request("DeleteDomainRecord", {"RecordId": handle})
        except DnsProviderError as err:
            if _is_record_missing(err):
                _LOGGER.debug("TXT 记录已不存在，无需删除：%s", handle)
                return
            raise

    @staticmethod
    def _apex(rr: str) -> str:
        """Aliyun uses @ for the zone apex."""
        return rr or "@"

    async def async_list_records(
        self, zone: str, rr: str, rtype: str = "A"
    ) -> list[dict[str, Any]]:
        """List records at a relative name with their values."""
        rr_ali = self._apex(rr)
        payload = await self._async_request(
            "DescribeDomainRecords",
            {
                "DomainName": zone,
                "RRKeyWord": rr_ali,
                "TypeKeyWord": rtype,
                "PageSize": "100",
            },
        )
        records = payload.get("DomainRecords", {}).get("Record", [])
        return [
            {
                "value": str(item.get("Value")),
                "handle": str(item.get("RecordId")),
                "ttl": int(item.get("TTL") or 600),
            }
            for item in records
            if str(item.get("RR", "")).lower() == rr_ali.lower()
            and str(item.get("Type", "")).upper() == rtype.upper()
            and item.get("RecordId")
        ]

    async def async_add_record(
        self, zone: str, rr: str, rtype: str, value: str, ttl: int = 600
    ) -> str:
        """Create an A/AAAA record and return its RecordId."""
        payload = await self._async_request(
            "AddDomainRecord",
            {
                "DomainName": zone,
                "RR": self._apex(rr),
                "Type": rtype,
                "Value": value,
                "TTL": str(max(600, ttl)),
            },
        )
        record_id = payload.get("RecordId")
        if not record_id:
            raise DnsProviderError(f"创建 {rtype} 记录失败：响应缺少 RecordId", payload)
        return str(record_id)

    async def async_update_record(
        self,
        zone: str,
        rr: str,
        rtype: str,
        handle: str,
        value: str,
        ttl: int = 600,
    ) -> None:
        """Update an existing record in place."""
        await self._async_request(
            "UpdateDomainRecord",
            {
                "RecordId": handle,
                "RR": self._apex(rr),
                "Type": rtype,
                "Value": value,
                "TTL": str(max(600, ttl)),
            },
        )

    async def async_list_txt(
        self, zone: str, rr: str, value: str | None = None
    ) -> list[str]:
        """List TXT records at a relative name, optionally filtered by value."""
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
        return [
            str(item.get("RecordId"))
            for item in records
            if item.get("RR") == rr
            and item.get("Type", "TXT") == "TXT"
            and item.get("RecordId")
            and (value is None or item.get("Value") == value)
        ]
