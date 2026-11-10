#!/usr/bin/env python3
"""Scan the repository for personal or secret-looking data.

Runs on the working tree by default and on the whole git history with
``--history``. Output is always masked, because GitHub Actions logs of a
public repository are public as well.

Exit code 1 means at least one finding, which turns the CI job red.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# 允许出现的公开域名（厂商 / 协议 / 文档站点）。只有确属公共服务的域名才加进来；
# 个人域名、自有站点域名一律不加。
ALLOWED_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "ghcr.io",
    "home-assistant.io",
    "developers.home-assistant.io",
    "community.home-assistant.io",
    "hacs.xyz",
    "letsencrypt.org",
    "acme-v02.api.letsencrypt.org",
    "acme-staging-v02.api.letsencrypt.org",
    "aliyuncs.com",
    "dns.aliyuncs.com",
    "alidns.com",
    "dns.alidns.com",
    "dns.google",
    "dnsapi.cn",
    "cloudflare.com",
    "api.cloudflare.com",
    "acme.zerossl.com",
    "zerossl.com",
    "api.buypass.com",
    "buypass.com",
    "dv.acme-v02.api.pki.goog",
    "pki.goog",
    "acme-v02.api.letsencrypt.org",
    "letsencrypt.org",
    "python.org",
    "pypi.org",
    "opensource.org",
    "mit-license.org",
}

ALLOWED_IPS = {
    "223.5.5.5",  # 阿里云公共 DNS
    "1.1.1.1",    # Cloudflare
    "8.8.8.8",    # Google
}

TEXT_SUFFIXES = {
    ".py", ".json", ".yaml", ".yml", ".md", ".txt", ".cfg", ".toml",
    ".sh", ".js", ".ts", ".html", ".ini",
}

BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico", ".zip", ".pem",
    ".key", ".der", ".crt", ".pfx", ".pyc",
}

DOMAIN_RULE = "unexpected-domain"
EMAIL_RULE = "email"
IP_RULE = "public-ip"
JWT_RULE = "jwt"
ACCESS_KEY_RULE = "access-key"
PHONE_RULE = "phone"
VIN_RULE = "vin"

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.(?:[A-Za-z]{2,})")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
ACCESS_KEY_RE = re.compile(r"LTAI[A-Za-z0-9]{8,}")
PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
VIN_RE = re.compile(r"(?<![A-Za-z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-Za-z0-9])")
# TLD 只保留不易与代码标识符（如 self.info、hass.config）撞车的几个
DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:com|org|net|cn|io|tech|top|xyz)(?![\w.-])"
)

PRIVATE_IP_PREFIXES = (
    "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.2", "172.30.", "172.31.", "192.168.", "0.0.0.0", "255.255.",
)


def mask(value: str) -> str:
    """Mask a matched value so that CI logs never carry the raw string."""
    if len(value) <= 4:
        return value[0] + "***"
    return value[:2] + "***" + value[-1]


def is_placeholder_domain(domain: str) -> bool:
    """Hosts that are placeholders or public vendor domains."""
    return (
        domain in ALLOWED_DOMAINS
        or domain.endswith(".example.com")
        or domain.endswith(".example.org")
        or domain.startswith("your-")
    )


def check_line(line: str) -> list[tuple[str, str]]:
    """Return (rule, masked value) pairs for one line of text."""
    findings: list[tuple[str, str]] = []

    for match in EMAIL_RE.finditer(line):
        findings.append((EMAIL_RULE, mask(match.group(0))))

    for match in IPV4_RE.finditer(line):
        value = match.group(0)
        if value.startswith(PRIVATE_IP_PREFIXES) or value in ALLOWED_IPS:
            continue
        parts = value.split(".")
        if any(int(part) > 255 for part in parts):
            continue
        findings.append((IP_RULE, mask(value)))

    for match in JWT_RE.finditer(line):
        findings.append((JWT_RULE, mask(match.group(0))))

    for match in ACCESS_KEY_RE.finditer(line):
        findings.append((ACCESS_KEY_RULE, mask(match.group(0))))

    for match in PHONE_RE.finditer(line):
        findings.append((PHONE_RULE, mask(match.group(0))))

    for match in VIN_RE.finditer(line):
        value = match.group(0)
        digits = sum(char.isdigit() for char in value)
        letters = sum(char.isalpha() for char in value)
        if digits < 4 or letters < 4:
            continue
        findings.append((VIN_RULE, mask(value)))

    for match in DOMAIN_RE.finditer(line):
        value = match.group(0).lower()
        if is_placeholder_domain(value):
            continue
        findings.append((DOMAIN_RULE, mask(value)))

    return findings


def iter_worktree(root: Path):
    """Yield (label, line_no, line) for tracked text files."""
    try:
        tracked = subprocess.run(
            ["git", "ls-files"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        tracked = [
            str(path.relative_to(root))
            for path in root.rglob("*")
            if path.is_file() and ".git" not in path.parts
        ]

    for rel in tracked:
        path = root / rel
        if not path.is_file() or path.suffix.lower() in BINARY_SUFFIXES:
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {
            ".gitignore",
            ".gitattributes",
        }:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            yield rel, number, line


def iter_history(root: Path):
    """Yield (short_commit, line) for every added line in the git history."""
    try:
        log = subprocess.run(
            ["git", "log", "--all", "-p", "--format=@@COMMIT@@%H"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return
    commit = "-"
    for line in log.splitlines():
        if line.startswith("@@COMMIT@@"):
            commit = line[len("@@COMMIT@@"):]
            continue
        if line.startswith("+") and not line.startswith("+++"):
            yield commit[:7], line[1:]


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true", help="also scan the git history")
    parser.add_argument("--root", default=".", help="repository root")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    total = 0

    print("[privacy] 扫描工作区…")
    for rel, number, line in iter_worktree(root):
        for rule, value in check_line(line):
            total += 1
            print(f"  {rel}:{number}  [{rule}]  {value}")

    if args.history:
        print("[privacy] 扫描 git 历史…")
        for commit, line in iter_history(root):
            for rule, value in check_line(line):
                total += 1
                print(f"  history/{commit}  [{rule}]  {value}")

    if total:
        print(f"[privacy] 发现 {total} 处疑似个人信息/密钥，请脱敏后重跑。")
        print("[privacy] 文档里请统一使用 example.com 之类占位域名；历史残留用 git filter-repo 重写。")
        return 1

    print("[privacy] 未发现疑似个人信息/密钥。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
