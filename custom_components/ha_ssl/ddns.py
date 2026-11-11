"""Dynamic DNS: keep one A record pointed at this installation's public IP."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import aiohttp

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util

from .const import (
    CONF_DDNS_INTERVAL,
    CONF_DDNS_RECORD,
    CONF_PROVIDER,
    DDNS_MAX_INTERVAL,
    DDNS_MIN_INTERVAL,
    DDNS_RECORD_TYPE,
    DDNS_TTL,
    DEFAULT_DDNS_INTERVAL,
    DOMAIN,
    PUBLIC_IP_ENDPOINTS,
    PUBLIC_IP_TIMEOUT,
)
from .providers import DnsProvider, DnsProviderError, async_create_provider

_LOGGER = logging.getLogger(__name__)

IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


class DdnsError(Exception):
    """Raised when the public address cannot be determined."""


@dataclass
class DdnsState:
    """Last known result of the DDNS loop."""

    record: str = ""
    public_ip: str | None = None
    record_value: str | None = None
    zone: str | None = None
    relative: str = ""
    source: str | None = None
    changed: bool = False
    checked_at: datetime | None = None
    last_change_at: datetime | None = None
    last_error: str | None = None


def _octets(value: str) -> list[int] | None:
    """Parse a dotted quad or return None."""
    parts = value.split(".")
    if len(parts) != 4:
        return None
    try:
        numbers = [int(part) for part in parts]
    except ValueError:
        return None
    if any(number < 0 or number > 255 for number in numbers):
        return None
    return numbers


def _is_cgnat(value: str) -> bool:
    """Reserved shared-address range (100.64/10): the carrier NATs you, so no
    inbound port can ever reach this host."""
    numbers = _octets(value)
    return bool(numbers) and numbers[0] == 100 and 64 <= numbers[1] <= 127


def _is_private(value: str) -> bool:
    """Whether the address belongs to a private or reserved range."""
    numbers = _octets(value)
    if not numbers:
        return True
    first, second = numbers[0], numbers[1]
    return (
        first in (0, 10, 127)
        or (first == 172 and 16 <= second <= 31)
        or (first == 192 and second == 168)
        or (first == 169 and second == 254)
        or first >= 224
    )


async def async_get_public_ip(session: aiohttp.ClientSession) -> tuple[str, str]:
    """Ask a few public services which IPv4 address this installation uses."""
    failures: list[str] = []
    timeout = aiohttp.ClientTimeout(total=PUBLIC_IP_TIMEOUT)

    for url in PUBLIC_IP_ENDPOINTS:
        try:
            async with session.get(
                url, timeout=timeout, headers={"User-Agent": "ha-ssl (Home Assistant)"}
            ) as resp:
                text = (await resp.text()).strip()
        except Exception as err:  # noqa: BLE001 - try the next endpoint
            failures.append(f"{url}: {err}")
            continue

        match = IPV4_RE.search(text)
        if match is None:
            failures.append(f"{url}: 响应里没有 IPv4")
            continue

        ip = match.group(1)
        if _is_cgnat(ip):
            raise DdnsError(
                "运营商级 NAT（100.64/10 保留网段）：公网地址不落在你的路由器上，"
                "改 DNS 记录也无法从外网访问，请改用内网穿透或申请公网 IP"
            )
        if _is_private(ip):
            failures.append(f"{url}: 返回的是内网地址 {ip}")
            continue
        return ip, url

    raise DdnsError("拿不到公网 IPv4：" + "；".join(failures))


class DdnsCoordinator(DataUpdateCoordinator[DdnsState]):
    """Every few minutes: read the public IP and fix the A record if it moved."""

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        domain: str,
    ) -> None:
        """Set up the loop from the entry options."""
        try:
            minutes = int(entry.options.get(CONF_DDNS_INTERVAL, DEFAULT_DDNS_INTERVAL))
        except (TypeError, ValueError):
            minutes = DEFAULT_DDNS_INTERVAL
        minutes = max(DDNS_MIN_INTERVAL, min(DDNS_MAX_INTERVAL, minutes))

        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} ddns {domain}",
            update_interval=timedelta(minutes=minutes),
            config_entry=entry,
        )
        self.entry = entry
        self._session = async_get_clientsession(hass)
        self._provider: DnsProvider | None = None
        self._zone: str | None = None
        self._relative: str | None = None

        raw_record = str(entry.options.get(CONF_DDNS_RECORD) or "").strip().lower()
        self.record = (raw_record or domain).rstrip(".")

    def _async_provider(self) -> DnsProvider:
        """Create the provider lazily so a bad entry does not break startup."""
        if self._provider is None:
            self._provider = async_create_provider(
                self._session,
                str(self.entry.data[CONF_PROVIDER]),
                dict(self.entry.data),
            )
        return self._provider

    async def _async_update_data(self) -> DdnsState:
        """Check the record and update it when the address changed."""
        state = self.data if isinstance(self.data, DdnsState) else DdnsState(
            record=self.record
        )
        state.record = self.record
        state.checked_at = dt_util.utcnow()

        try:
            ip, source = await async_get_public_ip(self._session)
            state.source = source

            provider = self._async_provider()
            if self._zone is None or self._relative is None:
                self._zone, self._relative = await provider.async_find_zone(self.record)
            state.zone = self._zone
            state.relative = self._relative

            records = await provider.async_list_records(
                self._zone, self._relative, DDNS_RECORD_TYPE
            )
            if not records:
                await provider.async_add_record(
                    self._zone, self._relative, DDNS_RECORD_TYPE, ip, DDNS_TTL
                )
                _LOGGER.info("DDNS 新建 A 记录：%s → %s", self.record, ip)
                state.changed = True
                state.last_change_at = state.checked_at
            elif all(item["value"] == ip for item in records):
                state.changed = False
                _LOGGER.debug("DDNS 记录未变化：%s = %s", self.record, ip)
            else:
                await provider.async_update_record(
                    self._zone,
                    self._relative,
                    DDNS_RECORD_TYPE,
                    records[0]["handle"],
                    ip,
                    DDNS_TTL,
                )
                _LOGGER.info(
                    "DDNS 更新 A 记录：%s %s → %s",
                    self.record,
                    records[0]["value"],
                    ip,
                )
                state.changed = True
                state.last_change_at = state.checked_at
                if len(records) > 1:
                    _LOGGER.warning(
                        "DDNS 同名 A 记录有 %s 条，只更新了第一条，请清理多余记录",
                        len(records),
                    )

            state.public_ip = ip
            state.record_value = ip
            state.last_error = None
        except (DdnsError, DnsProviderError) as err:
            state.last_error = str(err)
            _LOGGER.warning("DDNS 检查失败：%s", err)
        except Exception as err:  # noqa: BLE001 - keep the loop alive
            state.last_error = f"{type(err).__name__}: {err}"
            _LOGGER.exception("DDNS 循环异常")

        return state

    async def async_update_now(self) -> DdnsState:
        """Force one round and publish the result."""
        data = await self._async_update_data()
        self.async_set_updated_data(data)
        return data

    def as_dict(self) -> dict[str, Any]:
        """Flatten the state for the service response."""
        state: DdnsState = self.data
        return {
            "record": state.record,
            "public_ip": state.public_ip,
            "record_value": state.record_value,
            "zone": state.zone,
            "condition": "updated"
            if state.changed
            else ("unchanged" if state.public_ip else "failed"),
            "checked_at": state.checked_at.isoformat() if state.checked_at else None,
            "last_change_at": state.last_change_at.isoformat()
            if state.last_change_at
            else None,
            "source": state.source,
            "error": state.last_error,
        }
