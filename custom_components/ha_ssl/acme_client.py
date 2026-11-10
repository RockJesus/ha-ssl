"""Minimal asyncio ACME v2 (RFC 8555) client.

Only depends on aiohttp and cryptography, both already bundled with Home
Assistant, so the integration installs without pulling any extra package.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import pathlib
from typing import Any

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

_LOGGER = logging.getLogger(__name__)


class AcmeError(Exception):
    """Raised when the ACME server responds with a problem document."""

    def __init__(self, message: str, problem: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.problem = problem or {}

    @property
    def problem_type(self) -> str:
        """Return the ACME problem type."""
        return str(self.problem.get("type", ""))


def b64url(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def load_or_create_account_key(path: str) -> EllipticCurvePrivateKey:
    """Load the ACME account key, creating an EC P-256 key when missing."""
    file_path = pathlib.Path(path)
    if file_path.exists():
        key = serialization.load_pem_private_key(file_path.read_bytes(), password=None)
        if not isinstance(key, EllipticCurvePrivateKey):
            raise AcmeError("账户密钥必须是 EC 私钥")
        return key

    file_path.parent.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    file_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(file_path, 0o600)
    return key


def generate_certificate_key() -> tuple[EllipticCurvePrivateKey, bytes]:
    """Create a fresh leaf key plus its PEM representation."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key, pem


def build_csr_der(domain: str, key: EllipticCurvePrivateKey) -> bytes:
    """Build a DER encoded CSR for a single DNS name."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


class AcmeClient:
    """Tiny ACME v2 client covering the dns-01 flow only."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        directory_url: str,
        account_key: EllipticCurvePrivateKey,
    ) -> None:
        self._session = session
        self._directory_url = directory_url
        self._key = account_key
        self._kid: str | None = None
        self._directory: dict[str, Any] = {}

    @property
    def thumbprint(self) -> str:
        """RFC 7638 JWK thumbprint of the account key."""
        jwk = self._jwk()
        canonical = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
        return b64url(hashlib.sha256(canonical.encode()).digest())

    def _jwk(self) -> dict[str, str]:
        numbers = self._key.public_key().public_numbers()
        return {
            "crv": "P-256",
            "kty": "EC",
            "x": b64url(numbers.x.to_bytes(32, "big")),
            "y": b64url(numbers.y.to_bytes(32, "big")),
        }

    def _sign(self, data: bytes) -> bytes:
        der_signature = self._key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    async def async_initialize(self) -> None:
        """Load the directory and register (or re-fetch) the account."""
        await self._async_load_directory()
        await self._async_register_account()

    async def _async_load_directory(self) -> None:
        timeout = aiohttp.ClientTimeout(total=30)
        async with self._session.get(self._directory_url, timeout=timeout) as resp:
            if resp.status != 200:
                raise AcmeError(f"获取 ACME 目录失败：HTTP {resp.status}")
            self._directory = await resp.json(content_type=None)

    async def _async_fetch_nonce(self) -> str:
        timeout = aiohttp.ClientTimeout(total=30)
        async with self._session.head(
            self._directory["newNonce"], timeout=timeout
        ) as resp:
            nonce = resp.headers.get("Replay-Nonce")
            if not nonce:
                raise AcmeError("ACME 服务器未返回 nonce")
            return nonce

    def _jws_body(self, url: str, nonce: str, payload: dict | None, use_jwk: bool) -> str:
        protected: dict[str, Any] = {"alg": "ES256", "nonce": nonce, "url": url}
        if use_jwk:
            protected["jwk"] = self._jwk()
        else:
            protected["kid"] = self._kid
        protected_b64 = b64url(json.dumps(protected).encode())
        payload_b64 = (
            "" if payload is None else b64url(json.dumps(payload).encode())
        )
        signature = b64url(
            self._sign(f"{protected_b64}.{payload_b64}".encode())
        )
        return json.dumps(
            {
                "protected": protected_b64,
                "payload": payload_b64,
                "signature": signature,
            }
        )

    async def _async_post(
        self,
        url: str,
        payload: dict | None = None,
        *,
        use_jwk: bool = False,
    ) -> tuple[dict[str, Any], Any]:
        """Signed POST (or POST-as-GET when payload is None)."""
        timeout = aiohttp.ClientTimeout(total=60)
        problem: dict[str, Any] = {}

        for attempt in range(3):
            nonce = await self._async_fetch_nonce()
            body = self._jws_body(url, nonce, payload, use_jwk)
            async with self._session.post(
                url,
                data=body,
                headers={"Content-Type": "application/jose+json"},
                timeout=timeout,
            ) as resp:
                text = await resp.text()
                if resp.status < 400:
                    try:
                        return (json.loads(text) if text.strip() else {}), resp.headers
                    except ValueError as err:
                        raise AcmeError("ACME 响应不是合法 JSON") from err

                try:
                    problem = json.loads(text)
                except ValueError:
                    problem = {"detail": text[:300]}

                if str(problem.get("type", "")).endswith(":badNonce") and attempt < 2:
                    continue

                message = (
                    problem.get("detail")
                    or problem.get("title")
                    or f"ACME 请求失败：HTTP {resp.status}"
                )
                raise AcmeError(message, problem)

        raise AcmeError("ACME 请求在重试后仍然失败", problem)

    async def _async_register_account(self) -> None:
        data, headers = await self._async_post(
            self._directory["newAccount"],
            {"termsOfServiceAgreed": True},
            use_jwk=True,
        )
        location = headers.get("Location")
        if not location:
            raise AcmeError("ACME 账户创建失败：响应缺少 Location")
        self._kid = location
        _LOGGER.debug("ACME 账户已就绪：%s", self._kid)

    async def _async_poll(
        self,
        url: str,
        good: tuple[str, ...],
        bad: tuple[str, ...],
        timeout: int,
    ) -> dict[str, Any]:
        waited = 0
        interval = 5
        while True:
            data, _ = await self._async_post(url)
            status = data.get("status", "")
            if status in good or status in bad:
                return data
            if waited >= timeout:
                raise AcmeError(f"等待 ACME 状态超时（当前 {status}）")
            await asyncio.sleep(interval)
            waited += interval

    async def async_issue(
        self,
        domain: str,
        prepare_txt,
        cleanup_txt,
        wait_timeout: int = 300,
    ) -> tuple[str, bytes]:
        """Run a dns-01 order and return (certificate chain PEM, private key PEM)."""
        order, headers = await self._async_post(
            self._directory["newOrder"],
            {"identifiers": [{"type": "dns", "value": domain}]},
        )
        order_url = headers.get("Location") or order.get("url") or ""
        if not order_url:
            raise AcmeError("ACME 订单创建失败：响应缺少 Location")
        authz_url = order["authorizations"][0]

        authz, _ = await self._async_post(authz_url)
        challenge = next(
            (
                item
                for item in authz.get("challenges", [])
                if item.get("type") == "dns-01"
            ),
            None,
        )
        if challenge is None:
            raise AcmeError("ACME 服务器未提供 dns-01 验证方式")

        token = challenge["token"]
        key_auth = f"{token}.{self.thumbprint}"
        txt_value = b64url(hashlib.sha256(key_auth.encode()).digest())

        try:
            await prepare_txt(txt_value)
            await self._async_post(challenge["url"], {})
            authz = await self._async_poll(
                authz_url,
                ("valid",),
                ("invalid", "deactivated", "expired", "revoked"),
                wait_timeout,
            )
        finally:
            await cleanup_txt()

        if authz.get("status") != "valid":
            details: list[str] = []
            for item in authz.get("challenges") or []:
                error = item.get("error") or {}
                if error.get("detail"):
                    details.append(str(error["detail"]))
            raise AcmeError(
                "域名验证未通过" + (f"：{'；'.join(details)}" if details else ""),
                {"status": authz.get("status"), "challenges": authz.get("challenges")},
            )

        key, key_pem = generate_certificate_key()
        csr_der = build_csr_der(domain, key)

        for attempt in range(5):
            try:
                await self._async_post(
                    order["finalize"], {"csr": b64url(csr_der)}
                )
                break
            except AcmeError as err:
                if err.problem_type.endswith(":orderNotReady") and attempt < 4:
                    await asyncio.sleep(3)
                    continue
                raise

        order = await self._async_poll(
            order_url, ("valid",), ("invalid",), wait_timeout
        )
        if order.get("status") != "valid":
            raise AcmeError("订单未能完成签发")

        return await self._async_fetch_certificate(order["certificate"]), key_pem

    async def _async_fetch_certificate(self, url: str) -> str:
        """POST-as-GET the certificate chain."""
        timeout = aiohttp.ClientTimeout(total=60)
        nonce = await self._async_fetch_nonce()
        body = self._jws_body(url, nonce, None, False)
        async with self._session.post(
            url,
            data=body,
            headers={"Content-Type": "application/jose+json"},
            timeout=timeout,
        ) as resp:
            if resp.status >= 400:
                text = await resp.text()
                raise AcmeError(f"下载证书失败：HTTP {resp.status} {text[:200]}")
            return await resp.text()
