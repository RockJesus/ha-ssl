"""Config flow for the HA SSL integration."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.core import HomeAssistant
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .ddns import is_hostname, normalize_record_types, normalize_ttl, parse_record_lines
from .const import (
    ACME_DIRECTORY_PRODUCTION,
    ACME_DIRECTORY_STAGING,
    CONF_ALIYUN_ACCESS_KEY_ID,
    CONF_ALIYUN_ACCESS_KEY_SECRET,
    CONF_AUTO_RENEW,
    CONF_CERT_DIR,
    CONF_CERT_DOMAINS,
    CONF_DDNS_NOTIFY,
    CONF_DDNS_RECORDS,
    CONF_DDNS_TTL,
    CONF_EXPIRY_ALERT_DAYS,
    CONF_HTTPS_PORT,
    CONF_NOTIFY_WEBHOOK,
    CONF_TLS_PROFILE,
    CONF_CLOUDFLARE_API_TOKEN,
    CONF_DDNS_CNAME_RECORD,
    CONF_DDNS_CNAME_TARGET,
    CONF_DDNS_ENABLED,
    CONF_DDNS_INTERVAL,
    CONF_DDNS_RECORD,
    CONF_DDNS_RECORD_TYPES,
    CONF_DNSPOD_TOKEN,
    CONF_DNSPOD_TOKEN_ID,
    CONF_DOMAIN,
    CONF_PROVIDER,
    CONF_RENEW_DAYS,
    CONF_STAGING,
    DEFAULT_AUTO_RENEW,
    DEFAULT_CERT_DIR,
    DEFAULT_DDNS_ENABLED,
    DEFAULT_DDNS_INTERVAL,
    DEFAULT_DDNS_RECORD_TYPES,
    DEFAULT_DDNS_NOTIFY,
    DEFAULT_EXPIRY_ALERT_DAYS,
    DEFAULT_HTTPS_PORT,
    DEFAULT_RENEW_DAYS,
    DEFAULT_TLS_PROFILE,
    DDNS_MAX_TTL,
    DDNS_MIN_TTL,
    DDNS_MAX_INTERVAL,
    DDNS_MIN_INTERVAL,
    DOMAIN,
    PROVIDER_ALIYUN,
    PROVIDER_CLOUDFLARE,
    PROVIDER_DNSPOD,
)
from .providers import PROVIDER_CLASSES, DnsProviderError, async_create_provider

_LOGGER = logging.getLogger(__name__)

PROVIDER_HELP: dict[str, str] = {
    PROVIDER_ALIYUN: (
        "**阿里云云解析**\n"
        "1. 控制台右上角头像 → AccessKey 管理 → 创建 AccessKey（建议用 RAM 子账号）\n"
        "2. 给该子账号授予 `AliyunDNSFullAccess`，或只给这个域名的解析读写权限\n"
        "3. 确认域名已添加在「云解析 DNS」里"
    ),
    PROVIDER_DNSPOD: (
        "**DNSPod / 腾讯云 DNSPod**\n"
        "1. DNSPod 控制台 → 账号设置 → API 密钥 → 创建 Token\n"
        "2. 记下 Token ID 与 Token（Token 只显示一次）\n"
        "3. Token 需要具备该域名的解析读写权限"
    ),
    PROVIDER_CLOUDFLARE: (
        "**Cloudflare**\n"
        "1. 控制台 → My Profile → API Tokens → Create Token\n"
        "2. 用 `Edit zone DNS` 模板，并把 Zone 限定到签发证书用的这一个域名\n"
        "3. 复制 Token（只显示一次）"
    ),
}

CREDENTIAL_FIELDS: dict[str, tuple[str, ...]] = {
    PROVIDER_ALIYUN: (CONF_ALIYUN_ACCESS_KEY_ID, CONF_ALIYUN_ACCESS_KEY_SECRET),
    PROVIDER_DNSPOD: (CONF_DNSPOD_TOKEN_ID, CONF_DNSPOD_TOKEN),
    PROVIDER_CLOUDFLARE: (CONF_CLOUDFLARE_API_TOKEN,),
}


def _normalize_domain(raw: str) -> str:
    """Accept ``https://host:8123`` or ``host`` and return the bare hostname."""
    value = (raw or "").strip().lower()
    if "//" in value:
        value = urlparse(value).hostname or ""
    elif "/" in value:
        value = value.split("/", 1)[0]
    if ":" in value:
        value = value.split(":", 1)[0]
    return value.strip()


def _guess_domain(hass: HomeAssistant) -> str | None:
    """Derive the certificate domain from Home Assistant's own URLs."""
    for url in (hass.config.external_url, hass.config.internal_url):
        if not url:
            continue
        host = urlparse(url).hostname
        if host:
            return host.lower()
    return None

async def _async_validate(
    hass: HomeAssistant, provider: str, data: dict[str, Any], domain: str
) -> None:
    """Check the credentials and the domain ownership at the provider."""
    session = async_get_clientsession(hass)
    client = async_create_provider(session, provider, data)
    await client.async_find_zone(domain)


class HaSslConfigFlow(ConfigFlow, domain=DOMAIN):
    """Collect the domain, then the credentials of the chosen DNS provider."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick the provider and the certificate basics."""
        from .cert_manager import clear_purge_marker  # noqa: PLC0415

        await self.hass.async_add_executor_job(clear_purge_marker)
        guessed = _guess_domain(self.hass)

        if user_input is not None:
            domain = _normalize_domain(str(user_input.get(CONF_DOMAIN) or ""))
            if not domain:
                domain = _normalize_domain(guessed or "")
            if not domain:
                return self.async_show_form(
                    step_id="user",
                    data_schema=self._user_schema(guessed),
                    errors={"base": "domain_required"},
                )
            self._pending = {
                CONF_PROVIDER: str(user_input[CONF_PROVIDER]),
                CONF_DOMAIN: domain,
                CONF_CERT_DIR: str(user_input.get(CONF_CERT_DIR) or DEFAULT_CERT_DIR),
                CONF_STAGING: bool(user_input.get(CONF_STAGING, False)),
            }
            try:
                setup_port = int(user_input.get(CONF_HTTPS_PORT) or DEFAULT_HTTPS_PORT)
            except (TypeError, ValueError):
                setup_port = DEFAULT_HTTPS_PORT
            self._setup_options = {
                CONF_HTTPS_PORT: max(1, min(65535, setup_port))
            }
            return await self.async_step_credentials()

        return self.async_show_form(
            step_id="user",
            data_schema=self._user_schema(guessed),
            description_placeholders={
                "production": ACME_DIRECTORY_PRODUCTION,
                "staging": ACME_DIRECTORY_STAGING,
                "guessed_domain": guessed or "",
            },
        )

    def _user_schema(self, guessed: str | None) -> vol.Schema:
        domain_field = (
            vol.Optional(CONF_DOMAIN, default=guessed)
            if guessed
            else vol.Required(CONF_DOMAIN)
        )
        return vol.Schema(
            {
                vol.Required(
                    CONF_PROVIDER, default=PROVIDER_ALIYUN
                ): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=[
                            selector.SelectOptionDict(value=key, label=label)
                            for key, label in PROVIDER_CLASSES.items()
                        ],
                        mode=selector.SelectSelectorMode.LIST,
                    )
                ),
                domain_field: str,
                vol.Optional(CONF_CERT_DIR, default=DEFAULT_CERT_DIR): str,
                vol.Optional(CONF_STAGING, default=False): bool,
                vol.Optional(
                    CONF_HTTPS_PORT, default=DEFAULT_HTTPS_PORT
                ): selector.NumberSelector(
                    selector.NumberSelectorConfig(
                        min=1,
                        max=65535,
                        mode=selector.NumberSelectorMode.BOX,
                    )
                ),
            }
        )

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask only for the fields the chosen provider needs."""
        pending: dict[str, Any] | None = getattr(self, "_pending", None)
        if not pending:
            return await self.async_step_user()

        provider = str(pending[CONF_PROVIDER])
        domain = str(pending[CONF_DOMAIN])
        errors: dict[str, str] = {}

        if user_input is not None:
            data = {**pending, **user_input}
            try:
                await _async_validate(self.hass, provider, data, domain)
            except DnsProviderError as err:
                _LOGGER.error("校验 %s 凭据失败：%s", provider, err)
                errors["base"] = "invalid_auth"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("校验 %s 凭据时出现异常", provider)
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(domain)
                self._abort_if_unique_id_configured()
                self._entry_data = data
                return await self.async_step_ddns()

        schema: dict[Any, Any] = {
            vol.Required(field): str for field in CREDENTIAL_FIELDS[provider]
        }
        return self.async_show_form(
            step_id="credentials",
            data_schema=vol.Schema(schema),
            errors=errors,
            description_placeholders={
                "provider": PROVIDER_CLASSES[provider],
                "provider_help": PROVIDER_HELP.get(provider, ""),
            },
        )

    async def async_step_ddns(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Offer the dynamic DNS setup right after the credentials are verified."""
        data: dict[str, Any] | None = getattr(self, "_entry_data", None)
        if not data:
            return await self.async_step_user()
        domain = str(data[CONF_DOMAIN])
        errors: dict[str, str] = {}

        if user_input is not None:
            options: dict[str, Any] = dict(getattr(self, "_setup_options", {}))
            if user_input.get(CONF_DDNS_ENABLED, False):
                record = str(user_input.get(CONF_DDNS_RECORD) or domain).strip()
                if not is_hostname(record):
                    errors["base"] = "invalid_record"
                else:
                    try:
                        interval = int(
                            user_input.get(CONF_DDNS_INTERVAL, DEFAULT_DDNS_INTERVAL)
                        )
                    except (TypeError, ValueError):
                        interval = DEFAULT_DDNS_INTERVAL
                    options = {
                        CONF_DDNS_ENABLED: True,
                        CONF_DDNS_RECORD: record,
                        CONF_DDNS_RECORD_TYPES: normalize_record_types(
                            user_input.get(CONF_DDNS_RECORD_TYPES)
                        ),
                        CONF_DDNS_INTERVAL: max(
                            DDNS_MIN_INTERVAL, min(DDNS_MAX_INTERVAL, interval)
                        ),
                        CONF_DDNS_TTL: normalize_ttl(
                            user_input.get(CONF_DDNS_TTL, 600)
                        ),
                        CONF_DDNS_NOTIFY: bool(
                            user_input.get(CONF_DDNS_NOTIFY, DEFAULT_DDNS_NOTIFY)
                        ),
                    }
            if not errors:
                return self.async_create_entry(
                    title=domain, data=data, options=options
                )

        schema = vol.Schema(
            {
                vol.Optional(CONF_DDNS_ENABLED, default=False): bool,
                vol.Optional(CONF_DDNS_RECORD, default=domain): str,
                vol.Optional(
                    CONF_DDNS_RECORD_TYPES, default=list(DEFAULT_DDNS_RECORD_TYPES)
                ): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=["A", "AAAA", "CNAME", "TXT"],
                        multiple=True,
                        mode=selector.SelectSelectorMode.LIST,
                    )
                ),
                vol.Optional(
                    CONF_DDNS_INTERVAL, default=DEFAULT_DDNS_INTERVAL
                ): selector.NumberSelector(
                    selector.NumberSelectorConfig(
                        min=DDNS_MIN_INTERVAL,
                        max=DDNS_MAX_INTERVAL,
                        step=1,
                        mode=selector.NumberSelectorMode.BOX,
                        unit_of_measurement="分钟",
                    )
                ),
                vol.Optional(CONF_DDNS_TTL, default=600): selector.NumberSelector(
                    selector.NumberSelectorConfig(
                        min=DDNS_MIN_TTL,
                        max=DDNS_MAX_TTL,
                        step=1,
                        mode=selector.NumberSelectorMode.BOX,
                        unit_of_measurement="秒",
                    )
                ),
                vol.Optional(
                    CONF_DDNS_NOTIFY, default=DEFAULT_DDNS_NOTIFY
                ): bool,
            }
        )
        return self.async_show_form(
            step_id="ddns",
            data_schema=schema,
            errors=errors,
            description_placeholders={"domain": domain},
        )

    @staticmethod
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Return the options flow."""
        return HaSslOptionsFlow()


class HaSslOptionsFlow(OptionsFlow):
    """Tune renewal behaviour."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the options."""
        errors: dict[str, str] = {}
        if user_input is not None:
            types = normalize_record_types(user_input.get(CONF_DDNS_RECORD_TYPES))
            user_input[CONF_DDNS_RECORD_TYPES] = types
            cname_record = str(user_input.get(CONF_DDNS_CNAME_RECORD) or "").strip()
            cname_target = str(user_input.get(CONF_DDNS_CNAME_TARGET) or "").strip()
            main_record = (
                str(user_input.get(CONF_DDNS_RECORD) or "").strip()
                or str(self.config_entry.data.get(CONF_DOMAIN) or "").strip()
            )
            if "CNAME" in types:
                if not cname_record or not is_hostname(cname_target):
                    errors["base"] = "invalid_cname"
                elif cname_record.rstrip(".").lower() == main_record.rstrip(".").lower() and (
                    "A" in types or "AAAA" in types
                ):
                    errors["base"] = "cname_conflict"

            raw_records = str(user_input.get(CONF_DDNS_RECORDS) or "")
            if raw_records.strip():
                specs, record_errors = parse_record_lines(raw_records)
                if record_errors:
                    errors["base"] = "invalid_records"
                    _LOGGER.warning("动态域名记录清单有问题：%s", record_errors)
                elif not specs:
                    errors["base"] = "invalid_records"
            webhook = str(user_input.get(CONF_NOTIFY_WEBHOOK) or "").strip()
            if webhook and not webhook.startswith(("http://", "https://")):
                errors["base"] = "invalid_webhook"
            cert_domains = str(user_input.get(CONF_CERT_DOMAINS) or "").strip()
            for raw in [item.strip() for item in cert_domains.replace("，", ",").split(",") if item.strip()]:
                clean = raw.lower().rstrip(".")
                if clean.startswith("*."):
                    clean = clean[2:]
                if not is_hostname(clean):
                    errors["base"] = "invalid_domains"
                    break
            if not errors:
                return self.async_create_entry(title="", data=user_input)

        options = {**self.config_entry.options, **(user_input or {})}
        return self.async_show_form(
            step_id="init",
            errors=errors,
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_AUTO_RENEW,
                        default=options.get(CONF_AUTO_RENEW, DEFAULT_AUTO_RENEW),
                    ): bool,
                    vol.Optional(
                        CONF_RENEW_DAYS,
                        default=options.get(CONF_RENEW_DAYS, DEFAULT_RENEW_DAYS),
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=7,
                            max=89,
                            step=1,
                            mode=selector.NumberSelectorMode.BOX,
                            unit_of_measurement="天",
                        )
                    ),
                    vol.Optional(
                        CONF_CERT_DOMAINS,
                        default=str(
                            options.get(CONF_CERT_DOMAINS)
                            or self.config_entry.data.get(CONF_DOMAIN, "")
                        ),
                    ): str,
                    vol.Optional(
                        CONF_EXPIRY_ALERT_DAYS,
                        default=int(
                            options.get(
                                CONF_EXPIRY_ALERT_DAYS, DEFAULT_EXPIRY_ALERT_DAYS
                            )
                        ),
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=1,
                            max=89,
                            step=1,
                            mode=selector.NumberSelectorMode.BOX,
                            unit_of_measurement="天",
                        )
                    ),
                    vol.Optional(
                        CONF_NOTIFY_WEBHOOK,
                        default=str(options.get(CONF_NOTIFY_WEBHOOK) or ""),
                    ): str,
                    vol.Optional(
                        CONF_HTTPS_PORT,
                        default=int(
                            options.get(CONF_HTTPS_PORT, DEFAULT_HTTPS_PORT)
                        ),
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=1024,
                            max=65535,
                            step=1,
                            mode=selector.NumberSelectorMode.BOX,
                        )
                    ),
                    vol.Optional(
                        CONF_TLS_PROFILE,
                        default=str(
                            options.get(CONF_TLS_PROFILE, DEFAULT_TLS_PROFILE)
                        ),
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=[
                                selector.SelectOptionDict(
                                    value="modern", label="Modern（仅 TLS 1.3）"
                                ),
                                selector.SelectOptionDict(
                                    value="intermediate",
                                    label="Intermediate（兼容 TLS 1.2）",
                                ),
                            ],
                            mode=selector.SelectSelectorMode.DROPDOWN,
                        )
                    ),
                    vol.Optional(
                        CONF_DDNS_ENABLED,
                        default=options.get(CONF_DDNS_ENABLED, DEFAULT_DDNS_ENABLED),
                    ): bool,
                    vol.Optional(
                        CONF_DDNS_RECORD,
                        default=str(options.get(CONF_DDNS_RECORD) or ""),
                    ): str,
                    vol.Optional(
                        CONF_DDNS_RECORDS,
                        default=str(options.get(CONF_DDNS_RECORDS) or ""),
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(
                            multiline=True,
                            type=selector.TextSelectorType.TEXT,
                        )
                    ),
                    vol.Optional(
                        CONF_DDNS_TTL,
                        default=normalize_ttl(options.get(CONF_DDNS_TTL)),
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=DDNS_MIN_TTL,
                            max=DDNS_MAX_TTL,
                            step=60,
                            mode=selector.NumberSelectorMode.BOX,
                            unit_of_measurement="秒",
                        )
                    ),
                    vol.Optional(
                        CONF_DDNS_NOTIFY,
                        default=bool(
                            options.get(CONF_DDNS_NOTIFY, DEFAULT_DDNS_NOTIFY)
                        ),
                    ): bool,
                    vol.Optional(
                        CONF_DDNS_RECORD_TYPES,
                        default=normalize_record_types(
                            options.get(
                                CONF_DDNS_RECORD_TYPES, DEFAULT_DDNS_RECORD_TYPES
                            )
                        ),
                    ): selector.SelectSelector(
                        selector.SelectSelectorConfig(
                            options=["A", "AAAA", "CNAME"],
                            multiple=True,
                            mode=selector.SelectSelectorMode.LIST,
                        )
                    ),
                    vol.Optional(
                        CONF_DDNS_CNAME_RECORD,
                        default=str(options.get(CONF_DDNS_CNAME_RECORD) or ""),
                    ): str,
                    vol.Optional(
                        CONF_DDNS_CNAME_TARGET,
                        default=str(options.get(CONF_DDNS_CNAME_TARGET) or ""),
                    ): str,
                    vol.Optional(
                        CONF_DDNS_INTERVAL,
                        default=int(
                            options.get(CONF_DDNS_INTERVAL, DEFAULT_DDNS_INTERVAL)
                        ),
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=DDNS_MIN_INTERVAL,
                            max=DDNS_MAX_INTERVAL,
                            step=1,
                            mode=selector.NumberSelectorMode.BOX,
                            unit_of_measurement="分钟",
                        )
                    ),
                }
            ),
            description_placeholders={
                "domain": self.config_entry.data.get(CONF_DOMAIN, ""),
            },
        )
