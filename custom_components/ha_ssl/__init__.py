"""Set up the ACME certificate integration."""

from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
)
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_call_later

from .cert_manager import CertManager, apply_http_config
from .const import (
    CONF_RESTART,
    DOMAIN,
    PLATFORMS,
    SERVICE_CONFIGURE_HTTPS,
    SERVICE_PROBE,
    SERVICE_RENEW,
)
from .coordinator import AcmeCertCoordinator
from .probe import async_probe_cas

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up one ACME certificate entry."""
    manager = CertManager(hass, entry)
    coordinator = AcmeCertCoordinator(hass, entry, manager)

    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))

    async def _async_delayed_refresh(_now) -> None:
        """Run a real refresh a couple of minutes after startup."""
        await coordinator.async_request_refresh()

    entry.async_on_unload(
        async_call_later(hass, 120, _async_delayed_refresh)
    )

    _async_register_services(hass)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        coordinator = hass.data[DOMAIN].pop(entry.entry_id, None)
        if coordinator is not None:
            await coordinator.manager.async_close()
    return unload_ok


async def _async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload the entry when its options change."""
    await hass.config_entries.async_reload(entry.entry_id)


def _async_register_services(hass: HomeAssistant) -> None:
    """Register the integration services once."""
    if hass.services.has_service(DOMAIN, SERVICE_RENEW):
        return

    def _first_coordinator() -> AcmeCertCoordinator | None:
        for coordinator in hass.data.get(DOMAIN, {}).values():
            return coordinator
        return None

    async def _async_handle_renew(call: ServiceCall) -> ServiceResponse:
        coordinator = _first_coordinator()
        if coordinator is None:
            raise ValueError("还没有配置任何域名")
        if coordinator.manager.busy:
            return {"message": "已有一签发任务在运行"}
        try:
            info = await coordinator.async_force_issue()
        except Exception as err:  # noqa: BLE001 - surface the reason to the caller
            _LOGGER.error("手动签发失败：%s", err)
            return {"message": f"签发失败：{err}"}
        return {
            "message": "签发成功"
            if info.exists
            else "签发完成，但未读到证书",
            "valid_to": info.valid_to.isoformat() if info.valid_to else None,
            "days_left": info.days_left,
        }

    async def _async_handle_probe(call: ServiceCall) -> ServiceResponse:
        """Probe candidate ACME endpoints from this host (DoH + IPv4)."""
        import aiohttp

        from .doh import DohResolver

        resolver = DohResolver()
        session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(resolver=resolver, ttl_dns_cache=600)
        )
        try:
            results = await async_probe_cas(session)
        finally:
            await session.close()
            await resolver.close()
        for item in results:
            _LOGGER.info("CA 探测：%s", item)
        return {"results": list(results)}

    async def _async_handle_configure_https(call: ServiceCall) -> ServiceResponse:
        coordinator = _first_coordinator()
        if coordinator is None:
            raise ValueError("还没有配置任何域名")

        manager = coordinator.manager
        message = await hass.async_add_executor_job(
            apply_http_config, manager.fullchain_path, manager.key_path
        )
        _LOGGER.info("配置 HTTPS：%s", message)
        hass.bus.async_fire(
            f"{DOMAIN}_configure_https", {"message": message}
        )

        restart = call.data.get(CONF_RESTART, True)
        need_restart = "无需修改" not in message
        if restart and need_restart:
            hass.async_create_task(
                hass.services.async_call(
                    "homeassistant", "restart", {}, blocking=False
                )
            )
        return {"message": message, "restart_triggered": bool(restart and need_restart)}

    hass.services.async_register(
        DOMAIN,
        SERVICE_RENEW,
        _async_handle_renew,
        schema=vol.Schema({}),
        supports_response=SupportsResponse.OPTIONAL,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_PROBE,
        _async_handle_probe,
        schema=vol.Schema({}),
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_CONFIGURE_HTTPS,
        _async_handle_configure_https,
        schema=vol.Schema({vol.Optional(CONF_RESTART, default=True): cv.boolean}),
        supports_response=SupportsResponse.OPTIONAL,
    )
