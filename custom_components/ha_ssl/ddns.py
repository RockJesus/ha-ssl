"""Dynamic DNS: keep A / AAAA / CNAME records pointed at this installation."""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import aiohttp

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util

from .const import (
    CONF_DDNS_CNAME_RECORD,
    CONF_DDNS_CNAME_TARGET,
    CONF_DDNS_INTERVAL,
    CONF_DDNS_RECORD,
    CONF_DDNS_RECORD_TYPES,
    CONF_PROVIDER,
    DDNS_MAX_INTERVAL,
    DDNS_MIN_INTERVAL,
    DDNS_TTL,
    DEFAULT_DDNS_INTERVAL,
    DEFAULT_DDNS_RECORD_TYPES,
    DOMAIN,
    PUBLIC_IP_ENDPOINTS,
    PUBLIC_IP_TIMEOUT,
    PUBLIC_IPV6_ENDPOINTS,
)
from .providers import DnsProvider, DnsProviderError, async_create_provider

_LOGGER = logging.getLogger(__name__)

IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
IPV6_RE = re.compile(r"\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,7})\b")
HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.([a-z0-9]([a-z0-9-]*[a-z0-9])?))+$")


class DdnsError(Exception):
    """Raised when the public address cannot be determined."""


@dataclass
class RecordResult:
    """Outcome of reconciling one DNS record type."""

    rtype: str = "A"
    name: str = ""
    value: str | None = None
    previous: str | None = None
    changed: bool = False
    error: str | None = None


@dataclass
class DdnsState:
    """Last known result of the DDNS loop."""

    record: str = ""
    public_ip: str | None = None
    public_ipv6: str | None = None
    record_value: str | None = None
    zone: str | None = None
    relative: str = ""
    source: str | None = None
    source_v6: str | None = None
    changed: bool = False
    checked_at: datetime | None = None
    last_change_at: datetime | None = None
    last_error: str | None = None
    results: dict[str, RecordResult] = field(default_factory=dict)


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


def _ipv6_usable(value: str) -> bool:
    """Reject loopback, link-local, multicast and unique-local IPv6 addresses."""
    try:
        address = ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return bool(address.is_global) and not address.is_link_local


async def _async_query_ip(
    session: aiohttp.ClientSession,
    endpoints: tuple[str, ...],
    family: int,
) -> tuple[str, str]:
    """Ask a few public services which address this installation uses."""
    failures: list[str] = []
    timeout = aiohttp.ClientTimeout(total=PUBLIC_IP_TIMEOUT)

    for url in endpoints:
        try:
            async with session.get(
                url, timeout=timeout, headers={"User-Agent": "ha-ssl (Home Assistant)"}
            ) as resp:
                text = (await resp.text()).strip()
        except Exception as err:  # noqa: BLE001 - try the next endpoint
            failures.append(f"{url}: {err}")
            continue

        if family == 4:
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

        match = IPV6_RE.search(text)
        if match is None:
            failures.append(f"{url}: 响应里没有 IPv6")
            continue
        if not _ipv6_usable(match.group(1)):
            failures.append(f"{url}: 返回的 {match.group(1)} 不是可路由的公网 IPv6")
            continue
        return match.group(1), url

    raise DdnsError(
        ("拿不到公网 IPv4：" if family == 4 else "拿不到公网 IPv6：")
        + "；".join(failures)
    )


async def async_get_public_ip(
    session: aiohttp.ClientSession, family: int = 4
) -> tuple[str, str]:
    """Ask a few public services which IPv4 (or IPv6) address this host uses."""
    endpoints = PUBLIC_IP_ENDPOINTS if family == 4 else PUBLIC_IPV6_ENDPOINTS
    return await _async_query_ip(session, endpoints, family)


def normalize_record_types(raw: Any) -> list[str]:
    """Return the record types to maintain, newest options first."""
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)) or not raw:
        return list(DEFAULT_DDNS_RECORD_TYPES)
    wanted = {str(item).upper() for item in raw}
    order = [rt for rt in ("A", "AAAA", "CNAME") if rt in wanted]
    return order or list(DEFAULT_DDNS_RECORD_TYPES)


def is_hostname(value: str) -> bool:
    """Whether the value looks like a DNS hostname (CNAME target)."""
    return bool(HOSTNAME_RE.match(value.strip().rstrip(".").lower()))


class DdnsCoordinator(DataUpdateCoordinator[DdnsState]):
    """Every few minutes: read the public address and fix records if they moved."""

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
        self._zones: dict[str, tuple[str, str]] = {}

        raw_record = str(entry.options.get(CONF_DDNS_RECORD) or "").strip().lower()
        self.record = (raw_record or domain).rstrip(".")
        self.record_types = normalize_record_types(
            entry.options.get(CONF_DDNS_RECORD_TYPES)
        )
        self.cname_record = (
            str(entry.options.get(CONF_DDNS_CNAME_RECORD) or "").strip().lower().rstrip(".")
        )
        self.cname_target = (
            str(entry.options.get(CONF_DDNS_CNAME_TARGET) or "").strip().lower().rstrip(".")
        )
        if "CNAME" in self.record_types and not (
            self.cname_record and is_hostname(self.cname_target)
        ):
            _LOGGER.warning("CNAME 缺少记录名或指向，本轮跳过该类型")
            self.record_types = [rt for rt in self.record_types if rt != "CNAME"]

    def _async_provider(self) -> DnsProvider:
        """Create the provider lazily so a bad entry does not break startup."""
        if self._provider is None:
            self._provider = async_create_provider(
                self._session,
                str(self.entry.data[CONF_PROVIDER]),
                dict(self.entry.data),
            )
        return self._provider

    async def _async_zone(self, provider: DnsProvider, name: str) -> tuple[str, str]:
        """Find (zone, relative) once per record name.

        A CNAME may be given as a bare label, in which case it lives in the
        same zone as the address records.
        """
        if "." not in name:
            if self.record not in self._zones:
                self._zones[self.record] = await provider.async_find_zone(self.record)
            name = f"{name}.{self._zones[self.record][0]}"
        if name not in self._zones:
            self._zones[name] = await provider.async_find_zone(name)
        return self._zones[name]

    async def _async_reconcile(
        self,
        provider: DnsProvider,
        rtype: str,
        name: str,
        value: str,
    ) -> RecordResult:
        """Make the record of one type match the desired value."""
        result = RecordResult(rtype=rtype, name=name, value=value)
        zone, relative = await self._async_zone(provider, name)
        records = await provider.async_list_records(zone, relative, rtype)

        if not records:
            await provider.async_add_record(zone, relative, rtype, value, DDNS_TTL)
            _LOGGER.info("DDNS 新建 %s 记录：%s → %s", rtype, name, value)
            result.changed = True
            return result

        expected = value.lower()
        result.previous = records[0]["value"]
        if all(str(item["value"]).lower() == expected for item in records):
            _LOGGER.debug("DDNS 记录未变化：%s %s = %s", name, rtype, value)
            return result

        await provider.async_update_record(
            zone, relative, rtype, records[0]["handle"], value, DDNS_TTL
        )
        _LOGGER.info(
            "DDNS 更新 %s 记录：%s %s → %s", rtype, name, records[0]["value"], value
        )
        result.changed = True
        if len(records) > 1:
            _LOGGER.warning(
                "DDNS 同名 %s 记录有 %s 条，只更新了第一条，请清理多余记录",
                rtype,
                len(records),
            )
        return result

    async def _async_update_data(self) -> DdnsState:
        """Check every configured record and update the ones that drifted."""
        state = self.data if isinstance(self.data, DdnsState) else DdnsState(
            record=self.record
        )
        state.record = self.record
        state.checked_at = dt_util.utcnow()
        state.results = {}
        errors: list[str] = []
        changed = False
        provider = self._async_provider()

        want_v4 = "A" in self.record_types
        want_v6 = "AAAA" in self.record_types

        if want_v4:
            try:
                ip, source = await async_get_public_ip(self._session, 4)
                state.public_ip = ip
                state.source = source
            except DdnsError as err:
                errors.append(f"A {self.record}: {err}")
                state.results["A"] = RecordResult(
                    rtype="A", name=self.record, error=str(err)
                )
        if want_v6:
            try:
                ip6, source6 = await async_get_public_ip(self._session, 6)
                state.public_ipv6 = ip6
                state.source_v6 = source6
            except DdnsError as err:
                errors.append(f"AAAA {self.record}: {err}")
                state.results["AAAA"] = RecordResult(
                    rtype="AAAA", name=self.record, error=str(err)
                )

        targets: list[tuple[str, str, str]] = []
        if want_v4 and state.public_ip:
            targets.append(("A", self.record, state.public_ip))
        if want_v6 and state.public_ipv6:
            targets.append(("AAAA", self.record, state.public_ipv6))
        if "CNAME" in self.record_types:
            targets.append(("CNAME", self.cname_record, self.cname_target))

        for rtype, name, value in targets:
            try:
                result = await self._async_reconcile(provider, rtype, name, value)
            except (DnsProviderError, DdnsError) as err:
                result = RecordResult(
                    rtype=rtype, name=name, value=value, error=str(err)
                )
                errors.append(f"{rtype} {name}: {err}")
                _LOGGER.warning("DDNS 处理 %s 记录失败：%s", rtype, err)
            except Exception as err:  # noqa: BLE001 - keep the loop alive
                result = RecordResult(
                    rtype=rtype, name=name, value=value, error=repr(err)
                )
                errors.append(f"{rtype} {name}: {err}")
                _LOGGER.exception("DDNS 循环异常（%s）", rtype)
            state.results[rtype] = result
            if result.changed:
                changed = True
                state.last_change_at = state.checked_at
            if rtype == "A" and result.value:
                state.record_value = result.value
        if state.results:
            first = state.results.get("A") or next(iter(state.results.values()))
            if first.name == self.record:
                zone, relative = self._zones.get(self.record, (None, ""))
                state.zone = zone
                state.relative = relative

        state.changed = changed
        state.last_error = "；".join(errors) if errors else None
        if errors:
            _LOGGER.warning("DDNS 检查存在失败项：%s", state.last_error)
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
            "record_types": self.record_types,
            "public_ip": state.public_ip,
            "public_ipv6": state.public_ipv6,
            "record_value": state.record_value,
            "zone": state.zone,
            "condition": "updated"
            if state.changed
            else (
                "unchanged"
                if any(not item.error for item in state.results.values())
                else "failed"
            ),
            "checked_at": state.checked_at.isoformat() if state.checked_at else None,
            "last_change_at": state.last_change_at.isoformat()
            if state.last_change_at
            else None,
            "source": state.source,
            "source_v6": state.source_v6,
            "cname": {
                "record": self.cname_record,
                "target": self.cname_target,
            }
            if "CNAME" in self.record_types
            else None,
            "records": {
                rtype: {
                    "name": result.name,
                    "value": result.value,
                    "previous": result.previous,
                    "changed": result.changed,
                    "error": result.error,
                }
                for rtype, result in state.results.items()
            },
            "error": state.last_error,
        }
