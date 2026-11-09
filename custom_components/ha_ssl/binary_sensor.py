"""Binary sensor reporting an unhealthy certificate."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import AcmeCertCoordinator
from .sensor import _CertBaseEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the certificate health sensor."""
    coordinator: AcmeCertCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([CertProblemSensor(coordinator)])


class CertProblemSensor(_CertBaseEntity, BinarySensorEntity):
    """On when the certificate is missing or expired."""

    _attr_translation_key = "problem"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    def __init__(self, coordinator: AcmeCertCoordinator) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.entry.entry_id}_problem"

    @property
    def is_on(self) -> bool:
        """Return True when the certificate is missing or expired."""
        info = self.info
        if not info.exists:
            return True
        days = info.days_left
        return days is None or days < 0
