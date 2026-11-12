"""Issuance / renewal orchestration for the ACME certificate integration."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import pathlib
import re
import shutil
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .acme_client import AcmeClient, AcmeError, load_or_create_account_key
from .doh import DohResolver
from .const import (
    ACCOUNT_KEY_DIR,
    ACCOUNT_KEY_FILE,
    ACME_DIRECTORY_PRODUCTION,
    ACME_DIRECTORY_STAGING,
    CERT_FILE_NAME,
    CONF_CERT_DIR,
    CONF_CERT_DOMAINS,
    CONF_DOMAIN,
    CONF_PROVIDER,
    CONF_STAGING,
    FALLBACK_CERT_DIR,
    DEFAULT_CERT_DIR,
    DEFAULT_WAIT_TIMEOUT,
    DOH_RESOLVERS,
    KEY_FILE_NAME,
    STATE_FILE,
)
from .providers import DnsProviderError, async_create_provider

_LOGGER = logging.getLogger(__name__)

CONFIG_FILE = "/config/configuration.yaml"


class CertIssueError(Exception):
    """Raised when a certificate cannot be issued."""


@dataclass
class CertInfo:
    """Parsed information about the certificate on disk."""

    exists: bool = False
    path: str = ""
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    san: tuple[str, ...] = ()
    chain_length: int = 0
    last_error: str | None = None
    last_issued_at: datetime | None = None

    @property
    def days_left(self) -> int | None:
        """Days until expiry, negative when already expired."""
        if self.valid_to is None:
            return None
        return (self.valid_to - datetime.now(timezone.utc)).days


def _parse_cert_time(cert: x509.Certificate, attr: str) -> datetime:
    """Read a certificate timestamp in a timezone aware form."""
    utc_attr = f"{attr}_utc"
    value = getattr(cert, utc_attr, None)
    if value is not None:
        return value
    legacy = getattr(cert, attr).replace(tzinfo=timezone.utc)
    return legacy


class CertManager:
    """Issue and renew certificates for a single config entry."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the manager."""
        self.hass = hass
        self.entry = entry
        self._lock = asyncio.Lock()
        self._writable_cert_dir: str | None = None
        self.last_error: str | None = None
        self.last_issued_at: datetime | None = None

    def _create_acme_session(self) -> tuple[aiohttp.ClientSession, DohResolver]:
        """Fresh session per issuance: resolve through DoH, IPv4 only."""
        doh = DohResolver()
        session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                resolver=doh,
                ttl_dns_cache=600,
                force_close=True,
                enable_cleanup_closed=True,
            )
        )
        return session, doh

    async def async_close(self) -> None:
        """Nothing to release: sessions are owned by each issuance."""

    @property
    def domain(self) -> str:
        """Configured DNS name."""
        return str(self.entry.data[CONF_DOMAIN])

    async def provider_lookup(self) -> tuple[str, str]:
        """Find (zone, relative) for the primary domain through the provider API."""
        provider = async_create_provider(
            async_get_clientsession(self.hass),
            str(self.entry.data.get(CONF_PROVIDER) or ""),
            dict(self.entry.data),
        )
        return await provider.async_find_zone(self.domain)

    @property
    def domains(self) -> list[str]:
        """Every DNS name this certificate must cover."""
        raw = str(self.entry.options.get(CONF_CERT_DOMAINS) or "").strip()
        if not raw:
            return [self.domain]
        names = [
            item.strip().lower().rstrip(".")
            for item in raw.replace("，", ",").split(",")
            if item.strip()
        ]
        return names or [self.domain]

    @property
    def cert_dir(self) -> str:
        """Directory holding the certificate files."""
        if self._writable_cert_dir is not None:
            return self._writable_cert_dir
        configured = str(self.entry.data.get(CONF_CERT_DIR) or DEFAULT_CERT_DIR)
        if configured != FALLBACK_CERT_DIR:
            configured_file = pathlib.Path(configured) / CERT_FILE_NAME
            fallback_file = pathlib.Path(FALLBACK_CERT_DIR) / CERT_FILE_NAME
            if not configured_file.exists() and fallback_file.exists():
                return FALLBACK_CERT_DIR
        return configured

    @property
    def fullchain_path(self) -> str:
        """Full chain file path."""
        return os.path.join(self.cert_dir, CERT_FILE_NAME)

    @property
    def key_path(self) -> str:
        """Private key file path."""
        return os.path.join(self.cert_dir, KEY_FILE_NAME)

    @property
    def busy(self) -> bool | None:
        """Whether a job is already running."""
        return self._lock.locked()

    # ---------------------------------------------------------------- reading

    def read_cert(self) -> CertInfo:
        """Parse the certificate currently on disk (blocking, use executor)."""
        path = self.fullchain_path
        info = CertInfo(exists=False, path=path)
        if not os.path.exists(path):
            info.last_error = self.last_error
            return info

        try:
            raw = pathlib.Path(path).read_text(encoding="utf-8")
            first_block = raw.split("-----END CERTIFICATE-----")[0]
            pem = first_block + "-----END CERTIFICATE-----\n"
            cert = x509.load_pem_x509_certificate(pem.encode())
        except (OSError, ValueError) as err:
            info.last_error = f"读取证书失败：{err}"
            return info

        common_name = ""
        for attribute in cert.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        ):
            common_name = attribute.value
            break

        issuer_cn = ""
        for attribute in cert.issuer.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        ):
            issuer_cn = attribute.value
            break

        info.exists = True
        info.subject = common_name
        info.issuer = issuer_cn
        info.serial = format(cert.serial_number, "x")
        info.valid_from = _parse_cert_time(cert, "not_valid_before")
        info.valid_to = _parse_cert_time(cert, "not_valid_after")
        try:
            info.san = tuple(
                str(name)
                for name in cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            )
        except x509.ExtensionNotFound:
            info.san = ()
        info.chain_length = len(
            [
                block
                for block in raw.split("-----BEGIN CERTIFICATE-----")
                if block.strip()
            ]
        )
        info.last_error = self.last_error
        info.last_issued_at = self.last_issued_at
        return info

    # --------------------------------------------------------------- issuing

    async def async_issue(self) -> CertInfo:
        """Issue with its own short-lived ACME session.

        The session must not be reused across reloads: unloading an entry
        closes it, and an issuance still running would then fail with
        "Session is closed".
        """
        session, doh = self._create_acme_session()
        try:
            return await self._async_issue_inner(session)
        finally:
            await session.close()
            await doh.close()

    async def _async_issue_inner(self, acme_session: aiohttp.ClientSession) -> CertInfo:
        """Run a full dns-01 issuance and write the files."""
        if self._lock.locked():
            raise CertIssueError("已有一签发任务在运行，请稍后再试")

        async with self._lock:
            domains = self.domains
            provider_key = str(self.entry.data.get(CONF_PROVIDER) or "")
            directory = (
                ACME_DIRECTORY_STAGING
                if self.entry.data.get(CONF_STAGING)
                else ACME_DIRECTORY_PRODUCTION
            )

            await self.hass.async_add_executor_job(self._ensure_dirs)

            session = async_get_clientsession(self.hass)
            account_key_path = os.path.join(ACCOUNT_KEY_DIR, ACCOUNT_KEY_FILE)
            account_key = await self.hass.async_add_executor_job(
                load_or_create_account_key, account_key_path
            )

            client = AcmeClient(acme_session, directory, account_key)
            provider = async_create_provider(session, provider_key, dict(self.entry.data))

            try:
                await client.async_initialize()
            except (AcmeError, DnsProviderError) as err:
                self.last_error = str(err)
                raise CertIssueError(str(err)) from err
            except Exception as err:  # noqa: BLE001
                _LOGGER.exception("初始化 ACME 或定位域名失败")
                self.last_error = f"{type(err).__name__}: {err}"
                raise CertIssueError(self.last_error) from err

            handles: list[str] = []
            challenges: dict[str, tuple[str, str]] = {}

            async def prepare_txt(identifier: str, value: str) -> None:
                """Create the challenge record for one name and wait for it."""
                base = identifier.lower().lstrip("*.").rstrip(".")
                if base not in challenges:
                    zone, relative = await provider.async_find_zone(base)
                    rr = "_acme-challenge"
                    if relative:
                        rr = f"{rr}.{relative}"
                    challenges[base] = (zone, rr)
                zone, rr = challenges[base]
                await provider.async_clean_stale(zone, rr)
                handles.append(await provider.async_add_txt(zone, rr, value))
                await self._async_wait_txt(f"{rr}.{zone}", value)

            async def cleanup_txt() -> None:
                """Remove every challenge record this run created."""
                while handles:
                    current = handles.pop()
                    try:
                        await provider.async_delete_txt(current)
                    except DnsProviderError as err:
                        _LOGGER.warning("删除 TXT 记录失败：%s", err)

            try:
                cert_pem, key_pem = await client.async_issue(
                    domains, prepare_txt, cleanup_txt, DEFAULT_WAIT_TIMEOUT
                )
            except (
                AcmeError,
                DnsProviderError,
                CertIssueError,
                aiohttp.ClientError,
                asyncio.TimeoutError,
            ) as err:
                _LOGGER.exception("签发请求失败")
                message = f"{type(err).__name__}: {err}" if str(err) else type(err).__name__
                self.last_error = message
                raise CertIssueError(message) from err
            finally:
                await cleanup_txt()

            await self.hass.async_add_executor_job(
                self._write_files, cert_pem, key_pem
            )
            self.last_error = None
            self.last_issued_at = datetime.now(timezone.utc)
            _LOGGER.info(
                "证书签发成功：%s（写入 %s）", "、".join(domains), self.cert_dir
            )
            return await self.hass.async_add_executor_job(self.read_cert)

    def _ensure_dirs(self) -> None:
        configured = str(self.entry.data.get(CONF_CERT_DIR) or DEFAULT_CERT_DIR)
        candidates = [configured]
        if configured != FALLBACK_CERT_DIR:
            candidates.append(FALLBACK_CERT_DIR)

        for candidate in candidates:
            try:
                path = pathlib.Path(candidate)
                path.mkdir(parents=True, exist_ok=True)
                probe = path / ".ha_ssl_write_test"
                probe.write_text("ok", encoding="utf-8")
                probe.unlink()
            except OSError as err:
                _LOGGER.warning("证书目录 %s 不可写（%s），尝试下一个", candidate, err)
                continue
            if candidate != configured:
                _LOGGER.warning(
                    "配置的证书目录 %s 不可写，改用 %s；请同步更新 HTTPS 配置里的路径",
                    configured,
                    candidate,
                )
            self._writable_cert_dir = candidate
            pathlib.Path(ACCOUNT_KEY_DIR).mkdir(parents=True, exist_ok=True)
            return

        raise CertIssueError(f"没有可写的证书目录：{', '.join(candidates)}")

    def _write_files(self, cert_pem: str, key_pem: bytes) -> None:
        chain_path = pathlib.Path(self.fullchain_path)
        chain_path.write_text(cert_pem.strip() + "\n", encoding="utf-8")
        key_path = pathlib.Path(self.key_path)
        key_path.write_bytes(key_pem)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            _LOGGER.debug("无法设置私钥权限：%s", key_path)

        state_path = pathlib.Path(ACCOUNT_KEY_DIR) / STATE_FILE
        state_path.write_text(
            json.dumps(
                {
                    "domain": self.domain,
                    "issued_at": datetime.now(timezone.utc).isoformat(),
                    "cert_dir": self.cert_dir,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    # ------------------------------------------------------ dns propagation

    async def _async_lookup_txt(self, fqdn: str, value: str) -> bool:
        """Check the TXT record through public DNS-over-HTTPS resolvers."""
        session = async_get_clientsession(self.hass)
        params = {"name": fqdn, "type": "TXT"}
        headers = {"Accept": "application/dns-json"}
        timeout = aiohttp.ClientTimeout(total=10)

        for resolver in DOH_RESOLVERS:
            try:
                async with session.get(
                    resolver, params=params, headers=headers, timeout=timeout
                ) as resp:
                    if resp.status != 200:
                        continue
                    payload = await resp.json(content_type=None)
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                continue

            for answer in payload.get("Answer") or []:
                if int(answer.get("type", 0)) != 16:
                    continue
                data = str(answer.get("data", "")).strip('"')
                if data == value:
                    return True
        return False

    async def _async_wait_txt(
        self, fqdn: str, value: str, timeout: int = DEFAULT_WAIT_TIMEOUT
    ) -> None:
        """Block until the challenge TXT record is visible through DoH."""
        started = time.monotonic()
        while not await self._async_lookup_txt(fqdn, value):
            if time.monotonic() - started > timeout:
                raise CertIssueError(
                    f"等待 {fqdn} 的 TXT 记录生效超时（{timeout}s）"
                )
            await asyncio.sleep(5)


# --------------------------------------------------------------- http config



def _validate_cert_pair(fullchain: str, key: str) -> None:
    """Load the certificate and key once so a bad pair never reaches a restart."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(fullchain, key)
    except (OSError, ssl.SSLError) as err:
        raise ValueError(f"证书或私钥无法加载：{err}") from err


def _strip_yaml_ssl(fullchain: str, key: str, config_file: str = CONFIG_FILE) -> str:
    """Remove the obsolete ssl lines from configuration.yaml (HA 2026.11+)."""
    path = pathlib.Path(config_file)
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8")
    if "ssl_certificate" not in text:
        return ""
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup = path.with_suffix(path.suffix + f".bak.{stamp}")
    shutil.copy2(path, backup)
    lines = [
        line
        for line in text.splitlines()
        if not (
            line.strip().startswith("ssl_certificate:")
            or line.strip().startswith("ssl_key:")
        )
    ]
    text = "\n".join(lines).rstrip() + "\n"
    # Drop a http: block that became empty.
    text = re.sub(r"^http:\s*\n(?=\S|\Z)", "", text, count=1, flags=re.MULTILINE)
    if text.strip() and not text.endswith("\n"):
        text += "\n"
    path.write_text(text, encoding="utf-8")
    return f"已清理 configuration.yaml 里已失效的 ssl 两行（备份 {backup.name}）"


HTTPS_BOOTSTRAP_FILE = "https_bootstrap.json"


def _cert_fingerprint(fullchain: str) -> str:
    """Return a stable fingerprint of the certificate file."""
    import hashlib

    data = pathlib.Path(fullchain).read_bytes()
    return hashlib.sha256(data).hexdigest()


async def async_local_tls_ready(hass: HomeAssistant) -> bool:
    """Return True when 127.0.0.1:8123 answers over TLS."""
    session = async_get_clientsession(hass)
    try:
        async with session.get(
            "https://127.0.0.1:8123/api/",
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=8),
        ) as resp:
            await resp.read()
            return resp.status in (200, 401)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return False


async def async_config_uses_cert(hass: HomeAssistant, fullchain: str) -> bool:
    """Return True when stable or pending HTTP config points at our certificate."""
    try:
        from homeassistant.components.http.config import (  # noqa: PLC0415
            async_get_and_load_store,
        )
    except ImportError:
        return False
    store = await async_get_and_load_store(hass)
    for slot in (store.stable, store.pending):
        if slot and slot.get("ssl_certificate") == fullchain:
            return True
    return False


async def async_sync_external_url(
    hass: HomeAssistant, domain: str, port: int | None = None
) -> str | None:
    """Point the advertised external URL at the certificate domain over https."""
    from urllib.parse import urlparse  # noqa: PLC0415

    external = hass.config.external_url
    target_port = port or 8123
    if not external:
        new_url = f"https://{domain.lower()}:{target_port}"
        try:
            await hass.config.async_update(external_url=new_url)
        except Exception:  # noqa: BLE001
            _LOGGER.exception("写入 external_url 失败")
            return None
        return f"external_url 原为空，已自动设为 {new_url}"
    parsed = urlparse(external)
    target_port = port or parsed.port or 8123
    if parsed.scheme == "https" and parsed.hostname == domain.lower() and parsed.port == target_port:
        return None
    new_url = parsed._replace(
        scheme="https", netloc=f"{domain.lower()}:{target_port}"
    ).geturl()
    try:
        await hass.config.async_update(external_url=new_url)
    except Exception:  # noqa: BLE001
        _LOGGER.exception("更新 external_url 失败")
        return None
    return f"external_url 已切换为 {new_url}"


async def async_pending_uses_cert(hass: HomeAssistant, fullchain: str) -> bool:
    """Return True when the pending HTTP config points at our certificate."""
    try:
        from homeassistant.components.http.config import (  # noqa: PLC0415
            async_get_and_load_store,
        )
    except ImportError:
        return False
    store = await async_get_and_load_store(hass)
    pending = store.pending
    return bool(pending and pending.get("ssl_certificate") == fullchain)


async def async_maybe_promote_https(hass: HomeAssistant, fullchain: str) -> str | None:
    """Promote our pending HTTP config once TLS is verified locally."""
    try:
        from homeassistant.components.http.config import (  # noqa: PLC0415
            async_get_and_load_store,
        )
    except ImportError:
        return None

    store = await async_get_and_load_store(hass)
    pending = store.pending
    if not pending or pending.get("ssl_certificate") != fullchain:
        return None
    if not await async_local_tls_ready(hass):
        return None
    await store.async_promote_pending()
    return "本机 TLS 已确认可用，已自动固化为正式 HTTP 配置"


async def async_maybe_enable_https(
    hass: HomeAssistant, fullchain: str, key: str
) -> str | None:
    """First-run bootstrap: point HA's HTTP config at our certificate."""
    if not pathlib.Path(fullchain).exists() or not pathlib.Path(key).exists():
        return None
    try:
        from homeassistant.components.http.config import (  # noqa: PLC0415
            async_get_and_load_store,
        )
    except ImportError:
        return None

    store = await async_get_and_load_store(hass)
    current = store.pending or store.stable
    if current.get("ssl_certificate") == fullchain and current.get("ssl_key") == key:
        return None
    if current.get("ssl_certificate"):
        _LOGGER.info(
            "HTTP 配置里已有其他证书（%s），不自动覆盖", current.get("ssl_certificate")
        )
        return None

    fingerprint = await hass.async_add_executor_job(_cert_fingerprint, fullchain)
    marker = pathlib.Path(ACCOUNT_KEY_DIR) / HTTPS_BOOTSTRAP_FILE
    if marker.exists():
        try:
            previous = json.loads(marker.read_text(encoding="utf-8"))
        except ValueError:
            previous = {}
        if previous.get("fingerprint") == fingerprint:
            return None

    await hass.async_add_executor_job(_validate_cert_pair, fullchain, key)

    config = dict(store.stable)
    config["ssl_certificate"] = fullchain
    config["ssl_key"] = key
    await store.async_set_pending(config)

    def _mark() -> None:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(
            json.dumps(
                {
                    "fingerprint": fingerprint,
                    "applied_at": datetime.now(timezone.utc).isoformat(),
                    "fullchain": fullchain,
                    "key": key,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    await hass.async_add_executor_job(_mark)
    return "已把证书写入 HTTP 配置（待重启生效），重启后会自动确认"


async def async_apply_https_config(
    hass: HomeAssistant,
    fullchain: str,
    key: str,
    port: int | None = None,
    tls_profile: str | None = None,
) -> dict[str, Any]:
    """Write the certificate into whatever HTTP config this HA version uses.

    HA 2026.11 moved the HTTP config into a user-managed store
    (``.storage/http``); configuration.yaml is only migrated once and ignored
    afterwards. Newer versions therefore get a pending store config, older
    versions keep the configuration.yaml rewrite.
    """
    await hass.async_add_executor_job(_validate_cert_pair, fullchain, key)

    try:
        from homeassistant.components.http.config import (  # noqa: PLC0415
            async_get_and_load_store,
        )
    except ImportError:
        message = await hass.async_add_executor_job(
            apply_http_config, fullchain, key
        )
        return {
            "mode": "yaml",
            "message": message,
            "needs_restart": "无需修改" not in message,
        }

    store = await async_get_and_load_store(hass)
    def matches(cfg: dict[str, Any] | None) -> bool:
        return bool(cfg) and (
            cfg.get("ssl_certificate") == fullchain
            and cfg.get("ssl_key") == key
        )
    # 只有“当前生效的配置”已经是这套证书才算无需修改；pending 匹配但
    # stable 仍是旧证书时，必须重写 pending 并在重启后生效。
    if matches(store.stable) and (store.pending is None or matches(store.pending)):
        cleanup = await hass.async_add_executor_job(_strip_yaml_ssl, fullchain, key)
        return {
            "mode": "storage",
            "message": "HTTP 配置里已是这套证书，无需修改"
            + (f"；{cleanup}" if cleanup else ""),
            "needs_restart": False,
        }

    config = dict(store.stable)
    config["ssl_certificate"] = fullchain
    config["ssl_key"] = key
    applied: list[str] = []
    ignored: list[str] = []
    for key_name, value in (
        ("server_port", port),
        ("ssl_profile", tls_profile),
    ):
        if value in (None, ""):
            continue
        # 只改当前存储里真实存在的键，避免写入未知键导致 HTTP 集成启动失败。
        if key_name in config:
            config[key_name] = value
            applied.append(f"{key_name}={value}")
        else:
            ignored.append(key_name)
    await store.async_set_pending(config)
    cleanup = await hass.async_add_executor_job(_strip_yaml_ssl, fullchain, key)
    message = (
        "已写入 HA 的 HTTP 配置存储（重启后生效；重启后请在 5 分钟内确认可访问并固化，否则会自动回退）"
    )
    if applied:
        message += "；同时调整 " + "、".join(applied)
    if ignored:
        message += "；当前存储未暴露 " + "、".join(ignored) + "，未改动"
    return {
        "mode": "storage",
        "message": message,
        "needs_restart": True,
        "yaml_cleanup": cleanup,
        "applied": applied,
        "ignored": ignored,
    }


async def async_promote_https(hass: HomeAssistant) -> str:
    """Confirm the pending HTTP config so it does not auto-revert."""
    try:
        from homeassistant.components.http.config import (  # noqa: PLC0415
            async_get_and_load_store,
        )
    except ImportError as err:
        raise ValueError("当前 Home Assistant 版本不需要手动固化 HTTPS 配置") from err

    store = await async_get_and_load_store(hass)
    if store.pending is None:
        return "没有待确认的 HTTP 配置（当前已是固化状态）"
    await store.async_promote_pending()
    return "已固化为正式 HTTP 配置，自动回退已取消"

def apply_http_config(fullchain: str, key: str, config_file: str = CONFIG_FILE) -> str:
    """Insert the ssl_certificate / ssl_key lines into configuration.yaml."""
    path = pathlib.Path(config_file)
    if not path.exists():
        return f"找不到配置文件：{config_file}"

    text = path.read_text(encoding="utf-8")
    if "ssl_certificate" in text:
        return "configuration.yaml 里已经存在 ssl_certificate，无需修改"

    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup = path.with_suffix(path.suffix + f".bak.{stamp}")
    shutil.copy2(path, backup)

    lines = ["  ssl_certificate: " + fullchain, "  ssl_key: " + key]

    if re.search(r"^http:\s*$", text, flags=re.MULTILINE):
        text = re.sub(
            r"(^http:\s*$)",
            lambda match: match.group(1) + "\n" + "\n".join(lines),
            text,
            count=1,
            flags=re.MULTILINE,
        )
        status = f"已在现有 http: 段里插入证书配置（备份 {backup.name}）"
    else:
        block = "\nhttp:\n" + "\n".join(lines) + "\n"
        if not text.endswith("\n"):
            text += "\n"
        text += block
        status = f"已追加 http: 段（备份 {backup.name}）"

    path.write_text(text, encoding="utf-8")
    return status


def _load_chain(fullchain: str) -> list[x509.Certificate]:
    """Parse every certificate in a PEM chain."""
    text = pathlib.Path(fullchain).read_text(encoding="utf-8")
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", text, flags=re.S
    )
    return [x509.load_pem_x509_certificate(block.encode()) for block in blocks]


def verify_installation(fullchain: str, key: str) -> dict[str, Any]:
    """Check the on-disk pair: key match, chain completeness and expiry."""
    result: dict[str, Any] = {
        "exists": pathlib.Path(fullchain).exists() and pathlib.Path(key).exists(),
        "key_match": False,
        "expired": None,
        "days_left": None,
        "chain_length": 0,
        "chain_ok": False,
        "san": [],
        "problems": [],
    }
    if not result["exists"]:
        result["problems"].append("证书或私钥文件不存在")
        return result

    try:
        chain = _load_chain(fullchain)
    except (OSError, ValueError) as err:
        result["problems"].append(f"证书无法解析：{err}")
        return result
    result["chain_length"] = len(chain)
    leaf = chain[0]
    try:
        result["san"] = [
            str(name)
            for name in leaf.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        ]
    except x509.ExtensionNotFound:
        result["san"] = []

    result["days_left"] = (
        leaf.not_valid_after_utc - datetime.now(timezone.utc)
    ).days
    result["expired"] = result["days_left"] < 0

    try:
        key_obj = serialization.load_pem_private_key(
            pathlib.Path(key).read_bytes(), password=None
        )
    except (OSError, ValueError, TypeError) as err:
        result["problems"].append(f"私钥无法解析：{err}")
        key_obj = None
    if key_obj is not None:
        result["key_match"] = (
            key_obj.public_key().public_numbers()
            == leaf.public_key().public_numbers()
        )
        if not result["key_match"]:
            result["problems"].append("私钥与证书不匹配")

    chain_ok = True
    for current, issuer in zip(chain, chain[1:], strict=False):
        if current.issuer != issuer.subject:
            chain_ok = False
            result["problems"].append("证书链顺序或内容不完整")
            break
    result["chain_ok"] = chain_ok and len(chain) >= 2
    if not result["chain_ok"] and chain_ok:
        result["problems"].append("证书链只有叶子证书，缺少中间证书")

    if result["expired"]:
        result["problems"].append("证书已过期")
    return result


def backup_certificate(
    fullchain: str, key: str, target_dir: str, stamp: str
) -> str:
    """Write a zip backup of the certificate pair and return its path."""
    import zipfile  # noqa: PLC0415

    from .const import BACKUP_FILE_PREFIX  # noqa: PLC0415

    pathlib.Path(target_dir).mkdir(parents=True, exist_ok=True)
    archive = os.path.join(target_dir, f"{BACKUP_FILE_PREFIX}_{stamp}.zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(fullchain, "fullchain.pem")
        bundle.write(key, "privkey.pem")
    return archive


def restore_certificate(
    archive: str, fullchain: str, key: str
) -> dict[str, Any]:
    """Restore a certificate pair from a backup zip after validating it."""
    import zipfile  # noqa: PLC0415

    if not os.path.exists(archive):
        raise ValueError(f"备份文件不存在：{archive}")
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        if "fullchain.pem" not in names or "privkey.pem" not in names:
            raise ValueError("备份包里缺少 fullchain.pem 或 privkey.pem")
        cert_pem = bundle.read("fullchain.pem")
        key_pem = bundle.read("privkey.pem")

    tmp_dir = os.path.join(os.path.dirname(fullchain), ".restore")
    pathlib.Path(tmp_dir).mkdir(parents=True, exist_ok=True)
    tmp_cert = os.path.join(tmp_dir, "fullchain.pem")
    tmp_key = os.path.join(tmp_dir, "privkey.pem")
    pathlib.Path(tmp_cert).write_bytes(cert_pem)
    pathlib.Path(tmp_key).write_bytes(key_pem)
    _validate_cert_pair(tmp_cert, tmp_key)

    pathlib.Path(fullchain).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(fullchain).write_bytes(cert_pem)
    pathlib.Path(key).write_bytes(key_pem)
    info = verify_installation(fullchain, key)
    return {"path": fullchain, "verify": info}
