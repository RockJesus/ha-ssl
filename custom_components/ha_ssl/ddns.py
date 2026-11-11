"""Dynamic DNS: keep any number of DNS records pointed at this installation."""

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
    CONF_DDNS_NOTIFY,
    CONF_DDNS_RECORD,
    CONF_DDNS_RECORD_TYPES,
    CONF_DDNS_RECORDS,
    CONF_DDNS_TTL,
    CONF_PROVIDER,
    DDNS_HISTORY_LIMIT,
    DDNS_MAX_INTERVAL,
    DDNS_MAX_TTL,
    DDNS_MIN_INTERVAL,
    DDNS_MIN_TTL,
    DEFAULT_DDNS_INTERVAL,
    DEFAULT_DDNS_NOTIFY,
    DEFAULT_DDNS_RECORD_TYPES,
    DEFAULT_DDNS_TTL,
    DOMAIN,
    EVENT_DDNS_CHANGED,
    PUBLIC_IP_ENDPOINTS,
    PUBLIC_IP_TIMEOUT,
    PUBLIC_IPV6_ENDPOINTS,
)
from .providers import DnsProvider, DnsProviderError, async_create_provider

_LOGGER = logging.getLogger(__name__)

IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
IPV6_RE = re.compile(r"\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,7})\b")
HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.([a-z0-9]([a-z0-9-]*[a-z0-9])?))+$"
)
AUTO_VALUES = {"auto", "ip", "本机", "自动", ""}


class DdnsError(Exception):
    """Raised when the public address cannot be determined."""


@dataclass
class RecordSpec:
    """One DNS record the integration keeps in sync."""

    name: str
    rtype: str
    value: str = "auto"

    @property
    def key(self) -> str:
        """Stable identifier used in results and history."""
        return f"{self.rtype} {self.name}"


@dataclass
class RecordResult:
    """Outcome of reconciling one DNS record."""

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
    ipv4_ok: bool | None = None
    ipv6_ok: bool | None = None
    results: dict[str, RecordResult] = field(default_factory=dict)
    history: list[dict[str, Any]] = field(default_factory=list)


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
    order = [rt for rt in ("A", "AAAA", "CNAME", "TXT") if rt in wanted]
    return order or list(DEFAULT_DDNS_RECORD_TYPES)


def is_hostname(value: str) -> bool:
    """Whether the value looks like a DNS hostname."""
    return bool(HOSTNAME_RE.match(value.strip().rstrip(".").lower()))


def normalize_ttl(raw: Any) -> int:
    """Clamp the configured TTL into the range providers accept."""
    try:
        ttl = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_DDNS_TTL
    return max(DDNS_MIN_TTL, min(DDNS_MAX_TTL, ttl))


def _clean_name(raw: str, default: str) -> str:
    """Normalise a record name, falling back to the certificate domain."""
    value = (raw or "").strip().lower().rstrip(".")
    return value or default


def parse_record_lines(raw: str) -> tuple[list[RecordSpec], list[str]]:
    """Parse the multi-line record editor into specs plus human errors.

    Every non-comment line is ``名称 | 类型 | 值``; separators may also be
    commas or whitespace. ``auto`` (or leaving the value empty) means "use this
    host's public address", which only makes sense for A / AAAA.
    """
    specs: list[RecordSpec] = []
    errors: list[str] = []
    seen: dict[tuple[str, str], int] = {}

    for number, line in enumerate((raw or "").splitlines(), start=1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [part.strip() for part in re.split(r"[|,，\t]+", line)]
        if len(parts) < 2:
            parts = line.split()
        if len(parts) < 2:
            errors.append(f"第 {number} 行格式不正确：{line}")
            continue
        name = parts[0].lower().rstrip(".")
        rtype = parts[1].upper()
        value = parts[2].strip() if len(parts) > 2 else ""

        if rtype not in ("A", "AAAA", "CNAME", "TXT"):
            errors.append(f"第 {number} 行类型不支持：{rtype}")
            continue
        if not (is_hostname(name) or re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", name)):
            errors.append(f"第 {number} 行记录名不合法：{name}")
            continue

        if rtype in ("A", "AAAA"):
            if value.lower() in AUTO_VALUES:
                value = "auto"
            else:
                try:
                    parsed = ipaddress.ip_address(value)
                except ValueError:
                    errors.append(f"第 {number} 行 {rtype} 值不是合法地址：{value}")
                    continue
                if parsed.version != (4 if rtype == "A" else 6):
                    errors.append(f"第 {number} 行 {rtype} 与地址版本不匹配：{value}")
                    continue
                value = str(parsed)
        elif rtype == "CNAME":
            value = value.lower().rstrip(".")
            if not is_hostname(value):
                errors.append(f"第 {number} 行 CNAME 指向不合法：{value or '(空)'}")
                continue
        elif not value:
            errors.append(f"第 {number} 行 TXT 缺少内容")
            continue

        key = (name, rtype)
        if key in seen:
            errors.append(f"第 {number} 行与第 {seen[key]} 行重复（{rtype} {name}）")
            continue
        seen[key] = number
        specs.append(RecordSpec(name=name, rtype=rtype, value=value))

    for spec in list(specs):
        if spec.rtype == "CNAME" and any(
            other.name == spec.name and other.rtype in ("A", "AAAA")
            for other in specs
        ):
            errors.append(f"CNAME {spec.name} 与同名 A/AAAA 记录冲突，已忽略")
            specs.remove(spec)
    return specs, errors


def build_record_specs(
    entry: ConfigEntry, default_name: str
) -> tuple[list[RecordSpec], list[str]]:
    """Build the record list from the new editor or the legacy options."""
    raw = str(entry.options.get(CONF_DDNS_RECORDS) or "")
    specs, errors = parse_record_lines(raw)
    if specs or raw.strip():
        return specs, errors

    types = normalize_record_types(entry.options.get(CONF_DDNS_RECORD_TYPES))
    name = _clean_name(str(entry.options.get(CONF_DDNS_RECORD) or ""), default_name)
    specs = [RecordSpec(name=name, rtype=rt, value="auto") for rt in types if rt != "CNAME"]
    if "CNAME" in types:
        cname_name = _clean_name(
            str(entry.options.get(CONF_DDNS_CNAME_RECORD) or ""), ""
        )
        target = str(entry.options.get(CONF_DDNS_CNAME_TARGET) or "").strip().lower()
        if cname_name and is_hostname(target):
            specs.append(
                RecordSpec(name=cname_name, rtype="CNAME", value=target.rstrip("."))
            )
        else:
            errors.append("CNAME 缺少记录名或指向，已跳过")
    return specs, errors


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

        self.specs, self._spec_errors = build_record_specs(entry, domain)
        self.ttl = normalize_ttl(
            entry.options.get(CONF_DDNS_TTL, DEFAULT_DDNS_TTL)
        )
        self.notify = bool(
            entry.options.get(CONF_DDNS_NOTIFY, DEFAULT_DDNS_NOTIFY)
        )
        self.record_types = sorted({spec.rtype for spec in self.specs})
        address_specs = [spec for spec in self.specs if spec.rtype in ("A", "AAAA")]
        self.record = (address_specs[0].name if address_specs else (self.specs[0].name if self.specs else domain))
        self._last_notified_error: str | None = None
        self._history: list[dict[str, Any]] = []

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

        A bare label is expanded into the main record's zone, so short names
        keep working without the user typing the full hostname.
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
        """Make one DNS record match the desired value."""
        result = RecordResult(rtype=rtype, name=name, value=value)
        zone, relative = await self._async_zone(provider, name)
        records = await provider.async_list_records(zone, relative, rtype)

        if not records:
            await provider.async_add_record(zone, relative, rtype, value, self.ttl)
            _LOGGER.info("DDNS 新建 %s 记录：%s → %s", rtype, name, value)
            result.changed = True
            return result

        expected = value if rtype == "TXT" else value.lower()
        result.previous = records[0]["value"]
        if all(
            (str(item["value"]) if rtype == "TXT" else str(item["value"]).lower())
            == expected
            for item in records
        ):
            _LOGGER.debug("DDNS 记录未变化：%s %s = %s", name, rtype, value)
            return result

        await provider.async_update_record(
            zone, relative, rtype, records[0]["handle"], value, self.ttl
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

    def _remember_change(
        self, spec: RecordSpec, result: RecordResult
    ) -> None:
        """Record one change and announce it."""
        entry = {
            "at": dt_util.utcnow().isoformat(),
            "record": spec.key,
            "from": result.previous,
            "to": result.value,
        }
        self._history.append(entry)
        del self._history[:-DDNS_HISTORY_LIMIT]
        self.hass.bus.async_fire(EVENT_DDNS_CHANGED, entry)
        if not self.notify:
            return
        self.hass.async_create_task(
            self.hass.services.async_call(
                "persistent_notification",
                "create",
                {
                    "title": "HA SSL · 动态域名已更新",
                    "notification_id": f"ha_ssl_ddns_{spec.name}_{spec.rtype}",
                    "message": (
                        f"{spec.key}：{result.previous or '(无)'} → {result.value}"
                    ),
                },
                blocking=False,
            )
        )

    async def _async_update_data(self) -> DdnsState:
        """Check every configured record and update the ones that drifted."""
        state = self.data if isinstance(self.data, DdnsState) else DdnsState()
        state.record = self.record
        state.checked_at = dt_util.utcnow()
        state.results = {}
        errors: list[str] = list(self._spec_errors)
        changed = False
        provider = self._async_provider()

        needs_v4 = any(spec.rtype == "A" and spec.value == "auto" for spec in self.specs)
        needs_v6 = any(
            spec.rtype == "AAAA" and spec.value == "auto" for spec in self.specs
        )

        if needs_v4:
            try:
                ip, source = await async_get_public_ip(self._session, 4)
                state.public_ip = ip
                state.source = source
                state.ipv4_ok = True
            except DdnsError as err:
                state.ipv4_ok = False
                errors.append(f"公网 IPv4：{err}")
        if needs_v6:
            try:
                ip6, source6 = await async_get_public_ip(self._session, 6)
                state.public_ipv6 = ip6
                state.source_v6 = source6
                state.ipv6_ok = True
            except DdnsError as err:
                state.ipv6_ok = False
                errors.append(f"公网 IPv6：{err}")

        for spec in self.specs:
            value = spec.value
            if value == "auto":
                value = state.public_ip if spec.rtype == "A" else state.public_ipv6
                if not value:
                    message = (
                        "拿不到公网 IPv4" if spec.rtype == "A" else "拿不到公网 IPv6"
                    )
                    state.results[spec.key] = RecordResult(
                        rtype=spec.rtype, name=spec.name, error=message
                    )
                    continue
            try:
                result = await self._async_reconcile(
                    provider, spec.rtype, spec.name, value
                )
            except (DnsProviderError, DdnsError) as err:
                result = RecordResult(
                    rtype=spec.rtype, name=spec.name, value=value, error=str(err)
                )
                errors.append(f"{spec.key}：{err}")
                _LOGGER.warning("DDNS 处理 %s 失败：%s", spec.key, err)
            except Exception as err:  # noqa: BLE001 - keep the loop alive
                result = RecordResult(
                    rtype=spec.rtype, name=spec.name, value=value, error=repr(err)
                )
                errors.append(f"{spec.key}：{err}")
                _LOGGER.exception("DDNS 循环异常（%s）", spec.key)
            state.results[spec.key] = result
            if result.changed:
                changed = True
                state.last_change_at = state.checked_at
                if spec.rtype in ("A", "AAAA"):
                    state.record_value = result.value
                self._remember_change(spec, result)

        zone, relative = self._zones.get(self.record, (None, ""))
        state.zone = zone
        state.relative = relative
        state.changed = changed
        state.last_error = "；".join(errors) if errors else None
        state.history = list(self._history)
        if errors:
            _LOGGER.warning("DDNS 检查存在失败项：%s", state.last_error)
            self._async_notify_error(state.last_error)
        else:
            self._last_notified_error = None
        return state

    def _async_notify_error(self, message: str) -> None:
        """Announce a new failure once, not every loop."""
        if not self.notify or message == self._last_notified_error:
            return
        self._last_notified_error = message
        self.hass.async_create_task(
            self.hass.services.async_call(
                "persistent_notification",
                "create",
                {
                    "title": "HA SSL · 动态域名更新失败",
                    "notification_id": "ha_ssl_ddns_error",
                    "message": message,
                },
                blocking=False,
            )
        )

    async def async_update_now(self) -> DdnsState:
        """Force one round and publish the result."""
        data = await self._async_update_data()
        self.async_set_updated_data(data)
        return data

    def as_dict(self) -> dict[str, Any]:
        """Flatten the state for the service response."""
        state: DdnsState = self.data
        ok = [item for item in state.results.values() if not item.error]
        return {
            "record": state.record,
            "record_types": self.record_types,
            "records_configured": len(self.specs),
            "ttl": self.ttl,
            "public_ip": state.public_ip,
            "public_ipv6": state.public_ipv6,
            "record_value": state.record_value,
            "zone": state.zone,
            "condition": "updated"
            if state.changed
            else ("unchanged" if ok else "failed"),
            "checked_at": state.checked_at.isoformat() if state.checked_at else None,
            "last_change_at": state.last_change_at.isoformat()
            if state.last_change_at
            else None,
            "source": state.source,
            "source_v6": state.source_v6,
            "dual_stack": {
                "ipv4": state.ipv4_ok,
                "ipv6": state.ipv6_ok,
            },
            "records": {
                key: {
                    "type": result.rtype,
                    "name": result.name,
                    "value": result.value,
                    "previous": result.previous,
                    "changed": result.changed,
                    "error": result.error,
                }
                for key, result in state.results.items()
            },
            "history": state.history,
            "error": state.last_error,
            "spec_errors": list(self._spec_errors),
        }
