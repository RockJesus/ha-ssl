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
from .const import DOMAIN, MANUFACTURER
from .coordinator import AcmeCertCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the certificate sensors."""
    coordinator: AcmeCertCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            CertExpirySensor(coordinator),
            CertDaysLeftSensor(coordinator),
        ]
    )


class _CertBaseEntity(CoordinatorEntity[AcmeCertCoordinator]):
    """Common device information for the integration entities."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: AcmeCertCoordinator) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)
        self._domain = coordinator.manager.domain
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.entry.entry_id)},
            name=f"ACME 证书 · {self._domain}",
            manufacturer=MANUFACTURER,
            model=f"DNS-01 · {self._domain}",
        )

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
