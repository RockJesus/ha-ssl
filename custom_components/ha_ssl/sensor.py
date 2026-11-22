"""Sensor entities exposing the certificate state."""

from __future__ import annotations

import re
from datetime import datetime

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .cert_manager import (
    CertInfo,
    async_config_uses_cert,
    async_http_active_port,
)
from .const import (
    CONF_PROVIDER,
    DDNS_ADDRESS_TYPES,
    DOMAIN,
    INTEGRATION_VERSION,
    MANUFACTURER,
)
from .coordinator import AcmeCertCoordinator
from .ddns import DdnsCoordinator, DdnsState, RecordResult, RecordSpec
from .providers import PROVIDER_CLASSES


def _device_info(coordinator: AcmeCertCoordinator) -> DeviceInfo:
    """Shared device for all entities of one certificate entry."""
    provider = str(coordinator.entry.data.get(CONF_PROVIDER) or "")
    provider_label = PROVIDER_CLASSES.get(provider, provider)
    return DeviceInfo(
        identifiers={(DOMAIN, coordinator.entry.entry_id)},
        name=f"HA SSL · {coordinator.manager.domain}",
        manufacturer=MANUFACTURER,
        model=f"DNS-01 · {provider_label}",
        sw_version=INTEGRATION_VERSION,
    )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the certificate sensors."""
    coordinator: AcmeCertCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[SensorEntity] = [
        CertExpirySensor(coordinator),
        CertDaysLeftSensor(coordinator),
    ]
    port = await async_http_active_port(hass)
    scheme = (
        "https"
        if await async_config_uses_cert(hass, coordinator.manager.fullchain_path)
        else "http"
    )
    entities.append(HttpPortSensor(coordinator, port, scheme))

    ddns: DdnsCoordinator | None = getattr(coordinator, "ddns", None)
    if ddns is not None:
        entities.append(PublicIpSensor(coordinator, ddns))
        entities.append(PublicIpv6Sensor(coordinator, ddns))
        entities.extend(
            DdnsRecordSensor(coordinator, ddns, spec, port)
            for spec in ddns.specs
            if spec.rtype in DDNS_ADDRESS_TYPES
        )
    async_add_entities(entities)


class _CertBaseEntity(CoordinatorEntity[AcmeCertCoordinator]):
    """Common device information for the integration entities."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: AcmeCertCoordinator) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        self._domain = coordinator.manager.domain
        self._provider = str(coordinator.entry.data.get(CONF_PROVIDER) or "")
        self._attr_device_info = _device_info(coordinator)

    @property
    def info(self) -> CertInfo:
        """Current certificate information."""
        return self.coordinator.data

    @property
    def extra_state_attributes(self) -> dict[str, object]:
        """Expose useful diagnostics on every entity."""
        info = self.info
        return {
            "domain": self._domain,
            "dns_provider": PROVIDER_CLASSES.get(self._provider, self._provider),
            "cert_file": info.path,
            "issuer": info.issuer or None,
            "subject": info.subject or None,
            "serial_number": info.serial or None,
            "valid_from": info.valid_from.isoformat() if info.valid_from else None,
            "valid_to": info.valid_to.isoformat() if info.valid_to else None,
            "last_issued_at": info.last_issued_at.isoformat()
            if info.last_issued_at
            else None,
            "last_error": info.last_error,
        }


class CertExpirySensor(_CertBaseEntity, SensorEntity):
    """Timestamp of when the certificate stops being valid."""

    _attr_translation_key = "expiry"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(self, coordinator: AcmeCertCoordinator) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.entry.entry_id}_expiry"

    @property
    def native_value(self) -> datetime | None:
        """Return the expiry timestamp."""
        return self.info.valid_to if self.info.exists else None


class CertDaysLeftSensor(_CertBaseEntity, SensorEntity):
    """Number of days left before the certificate expires."""

    _attr_translation_key = "days_left"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "天"
    _attr_icon = "mdi:calendar-clock"

    def __init__(self, coordinator: AcmeCertCoordinator) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.entry.entry_id}_days_left"

    @property
    def native_value(self) -> int | None:
        """Return the remaining days."""
        return self.info.days_left if self.info.exists else None


class _DdnsBaseSensor(CoordinatorEntity[DdnsCoordinator], SensorEntity):
    """Common wiring for the public address sensors."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:ip-network"

    def __init__(
        self, coordinator: AcmeCertCoordinator, ddns: DdnsCoordinator
    ) -> None:
        """Bind to the DDNS loop but share the certificate device."""
        super().__init__(ddns)
        self._cert_coordinator = coordinator
        self._attr_device_info = _device_info(coordinator)

    @property
    def ddns(self) -> DdnsCoordinator:
        """Typed view of the coordinator."""
        return self.coordinator

    @property
    def ddns_state(self) -> DdnsState:
        """Current DDNS state."""
        return self.ddns.data

    @property
    def extra_state_attributes(self) -> dict[str, object]:
        """Expose every configured record plus the last error."""
        state = self.ddns_state
        if state is None:
            return {}
        return {
            "record": state.record,
            "record_types": list(self.ddns.record_types),
            "records_configured": len(self.ddns.specs),
            "ttl": self.ddns.ttl,
            "record_value": state.record_value,
            "zone": state.zone,
            "source": state.source,
            "source_v6": state.source_v6,
            "dual_stack": {
                "ipv4": state.ipv4_ok,
                "ipv6": state.ipv6_ok,
            },
            "changed": state.changed,
            "checked_at": state.checked_at.isoformat()
            if state.checked_at
            else None,
            "last_change_at": state.last_change_at.isoformat()
            if state.last_change_at
            else None,
            "last_error": state.last_error,
            "records": {
                key: {
                    "type": item.rtype,
                    "name": item.name,
                    "value": item.value,
                    "previous": item.previous,
                    "changed": item.changed,
                    "error": item.error,
                }
                for key, item in state.results.items()
            },
            "history": state.history[-5:],
            "update_interval_minutes": self.ddns.update_interval.total_seconds() // 60
            if self.ddns.update_interval
            else None,
        }


FAULT = "故障"


class DdnsRecordSensor(_DdnsBaseSensor):
    """One entity per maintained address record.

    Named ``DDNS-IPv6-<port>`` / ``DDNS-IPv4-<port>``; the state is the URL that
    record serves (``https://<域名>:<端口>`` for AAAA, ``http://<域名>:<端口>``
    for A). When the provider has no such record, the published address does not
    match, or the lookup failed, the state is ``故障``.
    """

    _attr_icon = "mdi:dns"
    _attr_has_entity_name = False

    def __init__(
        self,
        coordinator: AcmeCertCoordinator,
        ddns: DdnsCoordinator,
        spec: RecordSpec,
        port: int,
    ) -> None:
        """Bind to one record of the DDNS loop."""
        super().__init__(coordinator, ddns)
        self._spec = spec
        self._port = port
        # IPv4 走 A 记录（http），IPv6 走 AAAA 记录（https）；一条记录一个实体。
        self._family = "IPv6" if spec.rtype == "AAAA" else "IPv4"
        self._scheme = "https" if spec.rtype == "AAAA" else "http"
        names = {
            item.name for item in ddns.specs if item.rtype in DDNS_ADDRESS_TYPES
        }
        suffix = "" if len(names) <= 1 else f" ({spec.name})"
        self._attr_name = f"DDNS-{self._family}-{port}{suffix}"
        slug = re.sub(r"[^a-z0-9]+", "_", spec.name).strip("_")
        self._attr_unique_id = (
            f"{coordinator.entry.entry_id}_ddns_{slug}_{spec.rtype.lower()}"
        )

    @property
    def _result(self) -> RecordResult | None:
        return self.ddns_state.results.get(self._spec.key) if self.ddns_state else None

    @property
    def url(self) -> str:
        """URL served through this record."""
        return f"{self._scheme}://{self._spec.name}:{self._port}"

    @property
    def fault_reason(self) -> str | None:
        """Why the record cannot be trusted, or None when it is healthy."""
        result = self._result
        if result is None:
            return "还没有同步结果"
        if result.error:
            return result.error
        if result.deleted:
            return "云端没有这条记录"
        if result.pending:
            return (
                "云端没有这条记录"
                if result.previous is None
                else f"云端记录仍是旧值 {result.previous}"
            )
        if result.previous is None and not result.changed:
            return "云端没有这条记录"
        return None

    @property
    def native_value(self) -> str:
        """URL when the record is healthy, ``故障`` otherwise."""
        return FAULT if self.fault_reason else self.url

    @property
    def extra_state_attributes(self) -> dict[str, object]:
        """Per-record details on top of the shared DDNS attributes."""
        base = super().extra_state_attributes
        result = self._result
        state = self.ddns_state
        reason = self.fault_reason
        base.update(
            {
                "record_name": self._spec.name,
                "record_type": self._spec.rtype,
                "ip_version": self._family,
                "url": self.url,
                "port": self._port,
                "scheme": self._scheme,
                "healthy": reason is None,
                "fault_reason": reason,
                "cloud_value": result.previous if result else None,
                "expected_value": result.value if result else None,
                "changed": bool(result and result.changed),
                "pending": bool(result and result.pending),
                "deleted": bool(result and result.deleted),
                "last_error": (
                    result.error if result and result.error else state.last_error
                    if state
                    else None
                ),
            }
        )
        return base


class HttpPortSensor(_CertBaseEntity, SensorEntity):
    """The port Home Assistant itself is serving on."""

    _attr_translation_key = "http_port"
    _attr_icon = "mdi:lan-connect"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "端口"

    def __init__(
        self, coordinator: AcmeCertCoordinator, port: int, scheme: str
    ) -> None:
        """Record the port HA loads with on this start."""
        super().__init__(coordinator)
        self._port = port
        self._scheme = scheme
        self._attr_unique_id = f"{coordinator.entry.entry_id}_http_port"

    @property
    def native_value(self) -> int:
        """Return the active HTTP port."""
        return self._port

    @property
    def extra_state_attributes(self) -> dict[str, object]:
        """Port plus the protocol HA actually serves."""
        base = super().extra_state_attributes
        base.update(
            {
                "port": self._port,
                "scheme": self._scheme,
                "https_enabled": self._scheme == "https",
            }
        )
        return base


class PublicIpSensor(_DdnsBaseSensor):
    """Public IPv4 of this installation, i.e. what the A record should hold."""

    _attr_translation_key = "public_ip"

    def __init__(
        self, coordinator: AcmeCertCoordinator, ddns: DdnsCoordinator
    ) -> None:
        """Name the entity after the integration (has_entity_name is inherited)."""
        super().__init__(coordinator, ddns)
        self._attr_unique_id = f"{coordinator.entry.entry_id}_public_ip"

    @property
    def native_value(self) -> str | None:
        """Return the detected public IPv4."""
        return self.ddns_state.public_ip if self.ddns_state else None


class PublicIpv6Sensor(_DdnsBaseSensor):
    """Public IPv6 of this installation, i.e. what the AAAA record should hold."""

    _attr_translation_key = "public_ipv6"
    _attr_icon = "mdi:ip"

    def __init__(
        self, coordinator: AcmeCertCoordinator, ddns: DdnsCoordinator
    ) -> None:
        """Initialize the IPv6 sensor."""
        super().__init__(coordinator, ddns)
        self._attr_unique_id = f"{coordinator.entry.entry_id}_public_ipv6"

    @property
    def native_value(self) -> str | None:
        """Return the detected public IPv6."""
        return self.ddns_state.public_ipv6 if self.ddns_state else None
