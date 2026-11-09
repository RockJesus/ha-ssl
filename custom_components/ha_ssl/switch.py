"""Switch for the automatic renewal flag."""

from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_AUTO_RENEW, DEFAULT_AUTO_RENEW, DOMAIN
from .coordinator import AcmeCertCoordinator
from .sensor import _CertBaseEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the auto renewal switch."""
    coordinator: AcmeCertCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([AutoRenewSwitch(coordinator)])


class AutoRenewSwitch(_CertBaseEntity, SwitchEntity):
    """Toggle automatic renewal."""

    _attr_translation_key = "auto_renew"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:autorenew"

    def __init__(self, coordinator: AcmeCertCoordinator) -> None:
        """Initialize the switch."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.entry.entry_id}_auto_renew"

    @property
    def is_on(self) -> bool:
        """Return whether automatic renewal is enabled."""
        return bool(
            self.coordinator.entry.options.get(CONF_AUTO_RENEW, DEFAULT_AUTO_RENEW)
        )

    async def _async_set(self, enabled: bool) -> None:
        options = dict(self.coordinator.entry.options)
        options[CONF_AUTO_RENEW] = enabled
        self.hass.config_entries.async_update_entry(
            self.coordinator.entry, options=options
        )

    async def async_turn_on(self, **kwargs: object) -> None:
        """Enable automatic renewal."""
        await self._async_set(True)

    async def async_turn_off(self, **kwargs: object) -> None:
        """Disable automatic renewal."""
        await self._async_set(False)
