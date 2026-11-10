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

from .const import (
    ACME_DIRECTORY_PRODUCTION,
    ACME_DIRECTORY_STAGING,
    CONF_ALIYUN_ACCESS_KEY_ID,
    CONF_ALIYUN_ACCESS_KEY_SECRET,
    CONF_AUTO_RENEW,
    CONF_CERT_DIR,
    CONF_CLOUDFLARE_API_TOKEN,
    CONF_DNSPOD_TOKEN,
    CONF_DNSPOD_TOKEN_ID,
    CONF_DOMAIN,
    CONF_PROVIDER,
    CONF_RENEW_DAYS,
    CONF_RESTART_AFTER_RENEW,
    CONF_STAGING,
    DEFAULT_AUTO_RENEW,
    DEFAULT_CERT_DIR,
    DEFAULT_RENEW_DAYS,
    DEFAULT_RESTART_AFTER_RENEW,
    DOMAIN,
    PROVIDER_ALIYUN,
    PROVIDER_CLOUDFLARE,
    PROVIDER_DNSPOD,
)
from .providers import PROVIDER_CLASSES, DnsProviderError, async_create_provider

_LOGGER = logging.getLogger(__name__)

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
                return self.async_create_entry(title=domain, data=data)

        schema: dict[Any, Any] = {
            vol.Required(field): str for field in CREDENTIAL_FIELDS[provider]
        }
        return self.async_show_form(
            step_id="credentials",
            data_schema=vol.Schema(schema),
            errors=errors,
            description_placeholders={"provider": PROVIDER_CLASSES[provider]},
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
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = self.config_entry.options
        return self.async_show_form(
            step_id="init",
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
                        CONF_RESTART_AFTER_RENEW,
                        default=options.get(
                            CONF_RESTART_AFTER_RENEW, DEFAULT_RESTART_AFTER_RENEW
                        ),
                    ): bool,
                }
            ),
        )
