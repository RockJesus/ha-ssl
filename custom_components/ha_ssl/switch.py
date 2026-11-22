"""Switch for the automatic renewal flag."""

from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONF_AUTO_RENEW,
    CONF_DDNS_AUTO_SYNC,
    DEFAULT_AUTO_RENEW,
    DEFAULT_DDNS_AUTO_SYNC,
    DOMAIN,
)
from .coordinator import AcmeCertCoordinator
from .sensor import _CertBaseEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the renewal and DDNS switches."""
    coordinator: AcmeCertCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[SwitchEntity] = [AutoRenewSwitch(coordinator)]
    if coordinator.ddns is not None:
        entities.append(DdnsAutoSyncSwitch(coordinator))
    async_add_entities(entities)


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


class DdnsAutoSyncSwitch(_CertBaseEntity, SwitchEntity):
    """Write DDNS changes to the DNS provider as soon as the address moves."""

    _attr_translation_key = "ddns_auto_sync"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:cloud-sync"

    def __init__(self, coordinator: AcmeCertCoordinator) -> None:
        """Initialize the switch."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.entry.entry_id}_ddns_auto_sync"

    @property
    def is_on(self) -> bool:
        """Return whether address changes are pushed to DNS automatically."""
        return bool(
            self.coordinator.entry.options.get(
                CONF_DDNS_AUTO_SYNC, DEFAULT_DDNS_AUTO_SYNC
            )
        )

    async def _async_set(self, enabled: bool) -> None:
        options = dict(self.coordinator.entry.options)
        options[CONF_DDNS_AUTO_SYNC] = enabled
        self.hass.config_entries.async_update_entry(
            self.coordinator.entry, options=options
        )
        ddns = self.coordinator.ddns
        if ddns is not None:
            ddns.auto_sync = enabled

    async def async_turn_on(self, **kwargs: object) -> None:
        """Push changes automatically."""
        await self._async_set(True)

    async def async_turn_off(self, **kwargs: object) -> None:
        """Only detect changes; the button applies them."""
        await self._async_set(False)
