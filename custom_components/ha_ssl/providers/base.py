"""Shared contract for DNS providers used by the dns-01 challenge."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)


class DnsProviderError(Exception):
    """Raised when a DNS provider rejects a call or lacks the zone."""

    def __init__(
        self,
        message: str,
        payload: dict[str, Any] | None = None,
        code: str | None = None,
    ) -> None:
        """Store the raw payload and vendor error code for diagnostics."""
        super().__init__(message)
        self.payload = payload or {}
        self.code = code


class DnsProvider(ABC):
    """Everything the certificate manager needs from a DNS provider."""

    key: str = ""
    label: str = ""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        """Keep the Home Assistant shared session."""
        self._session = session

    @abstractmethod
    async def async_find_zone(self, fqdn: str) -> tuple[str, str]:
        """Return (zone, relative prefix) for a fully qualified name.

        The lookup must go through the provider API, never through the host
        resolver: on many Home Assistant installations the local resolver is
        hijacked, which is exactly what breaks the official add-on.
        """

    @abstractmethod
    async def async_add_txt(self, zone: str, rr: str, value: str, ttl: int = 600) -> str:
        """Create a TXT record and return an opaque handle for deletion."""

    @abstractmethod
    async def async_delete_txt(self, handle: str) -> None:
        """Delete a record created earlier in this run."""

    async def async_list_txt(self, zone: str, rr: str) -> list[str]:
        """List TXT record handles at a relative name (best effort)."""
        return []

    async def async_clean_stale(self, zone: str, rr: str) -> None:
        """Remove leftover challenge records before writing a new one."""
        for handle in await self.async_list_txt(zone, rr):
            try:
                await self.async_delete_txt(handle)
            except DnsProviderError as err:
                _LOGGER.debug("清理旧 TXT 记录失败：%s", err)

    async def async_list_records(
        self, zone: str, rr: str, rtype: str = "A"
    ) -> list[dict[str, Any]]:
        """Return existing records at a relative name.

        Each entry is ``{"value": str, "handle": str, "ttl": int}``. An empty
        list means the name has no record of that type at all.
        """
        return []

    async def async_add_record(
        self, zone: str, rr: str, rtype: str, value: str, ttl: int = 600
    ) -> str:
        """Create a record and return an opaque handle."""
        raise DnsProviderError(f"{self.label} 不支持创建 {rtype} 记录")

    async def async_update_record(
        self,
        zone: str,
        rr: str,
        rtype: str,
        handle: str,
        value: str,
        ttl: int = 600,
    ) -> None:
        """Change the value of an existing record."""
        raise DnsProviderError(f"{self.label} 不支持修改 {rtype} 记录")

    async def async_delete_record(self, handle: str) -> None:
        """Delete a record; handles share the TXT helper format."""
        await self.async_delete_txt(handle)

    @staticmethod
    def _apex(rr: str) -> str:
        """Map the empty relative name to the provider's apex placeholder."""
        return rr

    def async_describe(self) -> str:
        """Human readable provider name for entities and logs."""
        return self.label

    @staticmethod
    def _zone_candidates(fqdn: str) -> list[tuple[str, int]]:
        """Split a name into candidate zones with their label offset."""
        labels = fqdn.strip().rstrip(".").split(".")
        return [(".".join(labels[index:]), index) for index in range(len(labels) - 1)]
