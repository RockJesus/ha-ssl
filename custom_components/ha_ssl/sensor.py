"""Sensor entities exposing the certificate state."""

from __future__ import annotations

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

from .cert_manager import CertInfo
from .const import CONF_PROVIDER, DOMAIN, INTEGRATION_VERSION, MANUFACTURER
from .coordinator import AcmeCertCoordinator
from .ddns import DdnsCoordinator, DdnsState
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
    ddns: DdnsCoordinator | None = getattr(coordinator, "ddns", None)
    if ddns is not None:
        entities.append(PublicIpSensor(coordinator, ddns))
        entities.append(PublicIpv6Sensor(coordinator, ddns))
        entities.append(DdnsRecordCountSensor(coordinator, ddns))
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


class DdnsRecordCountSensor(_DdnsBaseSensor):
    """How many DNS records the integration is maintaining."""

    _attr_translation_key = "ddns_records"
    _attr_icon = "mdi:dns"
    _attr_native_unit_of_measurement = "条"

    def __init__(
        self, coordinator: AcmeCertCoordinator, ddns: DdnsCoordinator
    ) -> None:
        """Initialize the record count sensor."""
        super().__init__(coordinator, ddns)
        self._attr_unique_id = f"{coordinator.entry.entry_id}_ddns_records"

    @property
    def native_value(self) -> int:
        """Number of configured records."""
        return len(self.ddns.specs)


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
