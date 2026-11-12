"""Set up the ACME certificate integration."""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STARTED
from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
)
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_call_later

from .cert_manager import (
    CertManager,
    async_apply_https_config,
    async_local_tls_ready,
    async_maybe_enable_https,
    async_maybe_promote_https,
    async_promote_https,
    async_sync_external_url,
    async_clear_https_config,
    backup_certificate,
    clear_purge_marker,
    purge_certificate_files,
    restore_certificate,
    verify_installation,
)
from .const import (
    ACCOUNT_KEY_DIR,
    ACCOUNT_KEY_FILE,
    CONF_DDNS_ENABLED,
    CONF_HTTPS_PORT,
    CONF_RESTART,
    CONF_TLS_PROFILE,
    DEFAULT_DDNS_ENABLED,
    DOMAIN,
    PLATFORMS,
    SERVICE_BACKUP_CERT,
    SERVICE_CONFIGURE_HTTPS,
    SERVICE_DIAGNOSE,
    SERVICE_PROMOTE_HTTPS,
    SERVICE_PURGE,
    SERVICE_PROBE,
    SERVICE_RENEW,
    SERVICE_RESTORE_CERT,
    SERVICE_UPDATE_DDNS,
    SERVICE_VERIFY_CERT,
)
from .coordinator import AcmeCertCoordinator
from .ddns import DdnsCoordinator, async_get_public_ip
from .probe import (
    async_probe_cas,
    async_probe_self,
    read_http_section,
    read_http_storage,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up one ACME certificate entry."""
    manager = CertManager(hass, entry)
    coordinator = AcmeCertCoordinator(hass, entry, manager)

    await coordinator.async_config_entry_first_refresh()

    coordinator.ddns = None
    if entry.options.get(CONF_DDNS_ENABLED, DEFAULT_DDNS_ENABLED):
        ddns = DdnsCoordinator(hass, entry, manager.domain)
        await ddns.async_config_entry_first_refresh()
        coordinator.ddns = ddns

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

    manager = coordinator.manager

    async def _async_watch_tls() -> None:
        """等本机 TLS 真能应答：先固化，再把 external_url 切到 https。"""
        for _ in range(24):
            if not await async_local_tls_ready(hass):
                await asyncio.sleep(10)
                continue
            result = await async_maybe_promote_https(hass, manager.fullchain_path)
            if result:
                _LOGGER.info(result)
            message = await async_sync_external_url(
                hass,
                manager.domain,
                entry.options.get(CONF_HTTPS_PORT),
            )
            if message:
                _LOGGER.info(message)
            return

    watch_task: asyncio.Task | None = None
    watch_task = hass.async_create_task(_async_watch_tls())
    entry.async_on_unload(watch_task.cancel)

    enabled = await async_maybe_enable_https(
        hass, manager.fullchain_path, manager.key_path
    )
    if enabled:
        _LOGGER.info(enabled)
        hass.async_create_task(
            hass.services.async_call(
                "persistent_notification",
                "create",
                {
                    "title": "HA SSL 正在启用 HTTPS",
                    "notification_id": "ha_ssl_enabling_https",
                    "message": (
                        "证书已写入 Home Assistant 的 HTTPS 配置，"
                        "Home Assistant 将自动重启一次。\n\n"
                        f"重启后请改用 `https://{manager.domain}:8123` 访问，"
                        "iOS App 里的服务器地址也要同步改成 https。\n\n"
                        "集成会在重启后自动确认配置（无需手动操作）；"
                        "若 5 分钟内 HTTPS 仍不可用，会自动回退到原来的明文配置。"
                    ),
                },
                blocking=False,
            )
        )

        async def _async_restart(_event=None) -> None:
            """setup 阶段 HA 还没 running，restart 会被拒，等启动完成再调。"""
            try:
                await hass.services.async_call(
                    "homeassistant", "restart", {}, blocking=False
                )
            except Exception:  # noqa: BLE001
                _LOGGER.exception("自动重启失败，请手动重启以应用 HTTPS 配置")

        if hass.is_running:
            hass.async_create_task(_async_restart())
        else:
            hass.bus.async_listen_once(
                EVENT_HOMEASSISTANT_STARTED, _async_restart
            )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        coordinator = hass.data[DOMAIN].pop(entry.entry_id, None)
        if coordinator is not None:
            ddns = getattr(coordinator, "ddns", None)
            if ddns is not None:
                await ddns.async_shutdown()
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
        await hass.async_add_executor_job(clear_purge_marker)
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
            try:
                self_results = await async_probe_self(session)
            except Exception:  # noqa: BLE001
                _LOGGER.exception("本机协议自检失败")
                self_results = []
        finally:
            await session.close()
            await resolver.close()
        config_info = await hass.async_add_executor_job(read_http_section)
        storage_info = await hass.async_add_executor_job(read_http_storage)
        for item in results:
            _LOGGER.info("CA 探测：%s", item)
        return {
            "results": list(results),
            "self_probe": list(self_results),
            "http_config": config_info,
            "http_storage": storage_info,
        }

    async def _async_handle_configure_https(call: ServiceCall) -> ServiceResponse:
        coordinator = _first_coordinator()
        if coordinator is None:
            raise ValueError("还没有配置任何域名")

        manager = coordinator.manager
        result = await async_apply_https_config(
            hass,
            manager.fullchain_path,
            manager.key_path,
            port=coordinator.entry.options.get(CONF_HTTPS_PORT),
            tls_profile=coordinator.entry.options.get(CONF_TLS_PROFILE),
        )
        message = str(result["message"])
        if result.get("yaml_cleanup"):
            message = f"{message}；{result['yaml_cleanup']}"
        _LOGGER.info("配置 HTTPS：%s", message)
        try:
            synced = await async_sync_external_url(
                hass,
                manager.domain,
                coordinator.entry.options.get(CONF_HTTPS_PORT),
            )
        except Exception:  # noqa: BLE001
            _LOGGER.exception("同步 external_url 失败")
        else:
            if synced:
                _LOGGER.info(synced)
        hass.bus.async_fire(
            f"{DOMAIN}_configure_https", {"message": message}
        )

        restart = call.data.get(CONF_RESTART, True)
        need_restart = bool(result["needs_restart"])
        if restart and need_restart:
            hass.async_create_task(
                hass.services.async_call(
                    "homeassistant", "restart", {}, blocking=False
                )
            )
        return {
            "message": message,
            "mode": result["mode"],
            "restart_triggered": bool(restart and need_restart),
        }

    async def _async_handle_promote_https(call: ServiceCall) -> ServiceResponse:
        """Confirm the pending HTTP config so it is not auto-reverted."""
        message = await async_promote_https(hass)
        _LOGGER.info("固化 HTTPS 配置：%s", message)
        return {"message": message}

    async def _async_handle_update_ddns(call: ServiceCall) -> ServiceResponse:
        """Refresh the A record right now and report what happened."""
        coordinator = _first_coordinator()
        if coordinator is None:
            raise ValueError("还没有配置任何域名")
        ddns = getattr(coordinator, "ddns", None)
        if ddns is None:
            return {"message": "动态域名未启用，请先在集成选项里打开「动态域名解析」"}
        await ddns.async_update_now()
        result = ddns.as_dict()
        message = {
            "updated": f"已更新为 {result['public_ip']}",
            "unchanged": f"记录已是最新：{result['public_ip']}",
            "failed": f"更新失败：{result['error']}",
        }[result["condition"]]
        _LOGGER.info("手动更新 DDNS：%s", message)
        return {"message": message, **result}

    def _register(name, handler, schema, response=SupportsResponse.OPTIONAL) -> None:
        """Register one service, skipping it if it already exists."""
        if hass.services.has_service(DOMAIN, name):
            return
        hass.services.async_register(
            DOMAIN,
            name,
            handler,
            schema=schema,
            supports_response=response,
        )

    async def _async_handle_diagnose(call: ServiceCall) -> ServiceResponse:
        """Report what this host can reach and what the certificate looks like."""
        from homeassistant.helpers.aiohttp_client import (  # noqa: PLC0415
            async_get_clientsession,
        )

        coordinator = _first_coordinator()
        if coordinator is None:
            raise ValueError("还没有配置任何域名")
        session = async_get_clientsession(hass)
        probe: dict[str, object] = {}
        for family in (4, 6):
            try:
                address, source = await async_get_public_ip(session, family)
                probe[f"ipv{family}"] = {"ok": True, "address": address, "source": source}
            except Exception as err:  # noqa: BLE001 - report the reason
                probe[f"ipv{family}"] = {"ok": False, "error": str(err)}

        manager = coordinator.manager
        verify = await hass.async_add_executor_job(
            verify_installation, manager.fullchain_path, manager.key_path
        )
        try:
            zone, relative = await coordinator.manager.provider_lookup()
        except Exception as err:  # noqa: BLE001 - report the reason
            zone_info: dict[str, object] = {"ok": False, "error": str(err)}
        else:
            zone_info = {"ok": True, "zone": zone, "relative": relative}
        return {
            "network": probe,
            "certificate": verify,
            "domains": manager.domains,
            "zone": zone_info,
        }

    async def _async_handle_verify_cert(call: ServiceCall) -> ServiceResponse:
        """Verify the pair on disk: key match, chain and expiry."""
        coordinator = _first_coordinator()
        if coordinator is None:
            raise ValueError("还没有配置任何域名")
        manager = coordinator.manager
        result = await hass.async_add_executor_job(
            verify_installation, manager.fullchain_path, manager.key_path
        )
        return {"message": "证书自检完成", "path": manager.fullchain_path, **result}

    async def _async_handle_backup_cert(call: ServiceCall) -> ServiceResponse:
        """Zip the certificate pair somewhere the user can download."""
        coordinator = _first_coordinator()
        if coordinator is None:
            raise ValueError("还没有配置任何域名")
        manager = coordinator.manager
        target = str(call.data.get("path") or hass.config.path("ha_ssl_backups"))
        stamp = datetime.now().strftime("%Y%m%d%H%M%S")
        archive = await hass.async_add_executor_job(
            backup_certificate, manager.fullchain_path, manager.key_path, target, stamp
        )
        return {"message": "已备份证书", "archive": archive}

    async def _async_handle_restore_cert(call: ServiceCall) -> ServiceResponse:
        """Restore a pair from a zip backup after validating it."""
        coordinator = _first_coordinator()
        if coordinator is None:
            raise ValueError("还没有配置任何域名")
        manager = coordinator.manager
        archive = str(call.data["path"])
        result = await hass.async_add_executor_job(
            restore_certificate, archive, manager.fullchain_path, manager.key_path
        )
        await coordinator.async_refresh_cert()
        return {
            "message": "已恢复证书，重启 Home Assistant 后生效",
            "archive": archive,
        } | result

    async def _async_handle_purge(call: ServiceCall) -> ServiceResponse:
        """Remove every trace this integration left behind (explicit confirm)."""
        if call.data.get("confirm") is not True:
            return {
                "message": "未执行：purge 是危险操作，必须显式传 confirm: true",
                "purged": False,
            }
        coordinator = _first_coordinator()
        if coordinator is None:
            raise ValueError("还没有配置任何域名")
        manager = coordinator.manager
        http = await async_clear_https_config(
            hass, manager.fullchain_path, manager.key_path
        )
        files = await hass.async_add_executor_job(
            purge_certificate_files,
            manager.fullchain_path,
            manager.key_path,
            os.path.join(ACCOUNT_KEY_DIR, ACCOUNT_KEY_FILE),
            hass.config.path("ha_ssl_backups"),
            bool(call.data.get("remove_backups", True)),
        )
        synced: str | None = None
        external = hass.config.external_url
        if external and external.startswith("https://"):
            from urllib.parse import urlparse  # noqa: PLC0415

            parsed = urlparse(external)
            plain = parsed._replace(
                scheme="http",
                netloc=f"{parsed.hostname}:{parsed.port or 8123}"
                if parsed.port
                else (parsed.hostname or ""),
            ).geturl()
            try:
                await hass.config.async_update(external_url=plain)
                synced = f"external_url 已改回 {plain}"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("purge 后恢复 external_url 失败")
        _LOGGER.warning("purge 已清理：%s；文件：%s", http.get("message"), files)
        hass.bus.async_fire(
            f"{DOMAIN}_purged", {"http": http, "files": files}
        )
        need_restart = bool(http.get("needs_restart"))
        if call.data.get("restart") and need_restart:
            hass.async_create_task(
                hass.services.async_call(
                    "homeassistant", "restart", {}, blocking=False
                )
            )
        return {
            "message": "已清理证书与相关文件，重启后回到纯 HTTP",
            "external_url": synced,
            "purged": True,
            "http": http,
            "files": files,
            "restart_triggered": bool(call.data.get("restart") and need_restart),
        }

    _register(SERVICE_RENEW, _async_handle_renew, vol.Schema({}))
    _register(SERVICE_UPDATE_DDNS, _async_handle_update_ddns, vol.Schema({}))
    _register(
        SERVICE_PROBE,
        _async_handle_probe,
        vol.Schema({}),
        SupportsResponse.ONLY,
    )
    _register(
        SERVICE_CONFIGURE_HTTPS,
        _async_handle_configure_https,
        vol.Schema({vol.Optional(CONF_RESTART, default=True): cv.boolean}),
    )
    _register(SERVICE_PROMOTE_HTTPS, _async_handle_promote_https, vol.Schema({}))
    _register(SERVICE_DIAGNOSE, _async_handle_diagnose, vol.Schema({}))
    _register(SERVICE_VERIFY_CERT, _async_handle_verify_cert, vol.Schema({}))
    _register(
        SERVICE_BACKUP_CERT,
        _async_handle_backup_cert,
        vol.Schema({vol.Optional("path"): cv.string}),
    )
    _register(
        SERVICE_RESTORE_CERT,
        _async_handle_restore_cert,
        vol.Schema({vol.Required("path"): cv.string}),
    )
    _register(
        SERVICE_PURGE,
        _async_handle_purge,
        vol.Schema(
            {
                vol.Required("confirm"): cv.boolean,
                vol.Optional("remove_backups", default=True): cv.boolean,
                vol.Optional("restart", default=False): cv.boolean,
            }
        ),
    )
