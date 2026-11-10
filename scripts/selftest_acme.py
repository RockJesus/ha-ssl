"""ACME 签发链路自检：假服务器跑通 newOrder → authz → dns-01 → finalize → 下载证书。

只依赖 aiohttp 与 cryptography。不做真实网络请求，不会消耗 Let's Encrypt 配额，
专门用来防住「返回值解包/状态机字段」这类编译期发现不了、只有真实签发才炸的回归。
"""
import asyncio
import importlib.util
import json
import pathlib
import sys
from types import SimpleNamespace

HERE = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "acme_client",
    HERE / "custom_components" / "ha_ssl" / "acme_client.py",
)
acme = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acme)

CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

class Resp:
    def __init__(self, status, body="", headers=None, json_body=None):
        self.status = status; self._body = body; self.headers = headers or {}
        self._json = json_body
    async def text(self): return self._body
    async def json(self, content_type=None): return self._json
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False

class FakeAcme:
    def __init__(self):
        self.directory = {
            "newNonce": "https://acme.test/new-nonce",
            "newAccount": "https://acme.test/new-account",
            "newOrder": "https://acme.test/new-order",
        }
        self.calls = []
    def get(self, url, **kw):
        self.calls.append(("GET", url))
        return Resp(200, json_body=self.directory)
    def head(self, url, **kw):
        self.calls.append(("HEAD", url))
        return Resp(200, headers={"Replay-Nonce": "nonce-123"})
    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append(("POST", url))
        if url == self.directory["newAccount"]:
            return Resp(201, "{}", {"Location": "https://acme.test/acct/1"})
        if url == self.directory["newOrder"]:
            return Resp(201, json.dumps({
                "status": "pending",
                "authorizations": ["https://acme.test/authz/1"],
                "finalize": "https://acme.test/order/1/finalize",
            }), {"Location": "https://acme.test/order/1"})
        if url == "https://acme.test/authz/1":
            return Resp(200, json.dumps({
                "status": "valid",
                "challenges": [{"type": "dns-01", "token": "tok",
                                "url": "https://acme.test/chal/1"}],
            }))
        if url == "https://acme.test/chal/1":
            return Resp(200, "{}")
        if url.endswith("/finalize"):
            return Resp(200, "{}")
        if url == "https://acme.test/order/1":
            return Resp(200, json.dumps({"status": "valid",
                                         "certificate": "https://acme.test/cert/1"}))
        if url == "https://acme.test/cert/1":
            return Resp(200, CERT_PEM)
        return Resp(404, json.dumps({"type": "urn:ietf:params:acme:error:malformed",
                                     "detail": "unexpected"}))

async def main():
    session = FakeAcme()
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    client = acme.AcmeClient(session, "https://acme.test/directory", key)
    await client.async_initialize()
    events = []
    async def prepare(value):
        events.append(("prepare", value))
    async def cleanup():
        events.append(("cleanup", None))
    chain, key_pem = await client.async_issue("example.com", prepare, cleanup, 30)
    assert CERT_PEM in chain, chain[:80]
    assert key_pem, "私钥为空"
    assert [e[0] for e in events] == ["prepare", "cleanup"], events
    print("ACME 全链路 OK：下单 → authz → dns-01 → finalize → 轮询 → 下载证书")
    print("调用序列:", [c[0] for c in session.calls])

asyncio.run(main())
