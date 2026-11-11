# HA SSL

[![Hassfest](https://github.com/RockJesus/ha-ssl/actions/workflows/hassfest.yml/badge.svg)](https://github.com/RockJesus/ha-ssl/actions/workflows/hassfest.yml)
[![HACS Action](https://github.com/RockJesus/ha-ssl/actions/workflows/hacs.yml/badge.svg)](https://github.com/RockJesus/ha-ssl/actions/workflows/hacs.yml)
[![ACME Self Test](https://github.com/RockJesus/ha-ssl/actions/workflows/selftest.yml/badge.svg)](https://github.com/RockJesus/ha-ssl/actions/workflows/selftest.yml)
[![Privacy Scan](https://github.com/RockJesus/ha-ssl/actions/workflows/privacy.yml/badge.svg)](https://github.com/RockJesus/ha-ssl/actions/workflows/privacy.yml)

在 Home Assistant 内部完成 **Let's Encrypt 证书签发、HTTPS 自动启用与自动续期**，
并把 **动态域名（DDNS）** 一起接管——原来交给 Lucky 或路由器的那件事也不用再单独跑了。
只要选一个 DNS 服务商、填它的凭据，其余全自动——不需要加载项，也不需要宿主机能解析 DNS。

> 适合国内环境：官方 Let's Encrypt 加载项常因镜像拉不到而装不上，或卡在 `code=SERVFAIL`——
> 那个加载项靠宿主机 DNS 查 `_acme-challenge.<域名>` 的 SOA 来定位 zone，DNS 被路由器或运营商劫持时查不到。
> 本集成直接用服务商 API 定位 zone 并写 TXT 记录，全程绕开宿主机 DNS。

## 快速开始

1. **装集成**：HACS 添加自定义仓库 `https://github.com/RockJesus/ha-ssl`（类别选 Integration），或把 `custom_components/ha_ssl/` 放进 `config/`，然后重启。
2. **添加集成**：设置 → 设备与服务 → 添加集成 → **HA SSL** → 选 DNS 服务商 → 填凭据。
3. **等它做完**：签发证书 → 写入 HTTPS 配置 → 自动重启一次 → 之后每 6 小时巡检、到期前自动续签。

完成后改用 `https://<域名>:8123` 访问，手机 App 里的服务器地址也要同步改成 https。

## 只填服务商凭据

| 服务商 | 需要填 | 最小权限 |
|---|---|---|
| 阿里云云解析 | AccessKey ID + Secret | RAM 子账号授予 `AliyunDNSFullAccess`，或只给该域名的解析读写 |
| 腾讯云 DNSPod | Token ID + Token | 账号设置 → API 密钥创建，需能管理该域名 |
| Cloudflare | API Token | `Edit zone DNS` 模板，Zone 限定到该域名 |

域名默认取 HA 自己的 `external_url`/`internal_url`，留空即可；没有邮箱字段（ACME 账号本来就不要求联系人）。
凭据只用于调用服务商接口，保存在 HA 本地配置（`.storage`），建议用最小权限子账号并定期轮换。

## 自动完成的事

| 阶段 | 行为 |
|---|---|
| 签发 | dns-01 验证，自动写入再删除 `_acme-challenge` TXT 记录 |
| 启用 HTTPS | 写进当前 HA 版本真正读取的 HTTP 配置（2026.11+ 是 `.storage/http`，旧版是 `configuration.yaml`），并自动重启一次 |
| 确认 | 重启后探测本机 TLS，通了就固化配置（避免 5 分钟自动回退），并把 `external_url` 切成 `https://` |
| 续期 | 每 6 小时检查一次，剩余 ≤30 天自动重签；成功后按选项重启加载新证书 |

签发与启用各发一条持久通知，说明正在做什么、重启后该用哪个地址访问。

## 动态域名（可选）

家宽公网 IP 会变时，打开它就够了，不必再装 Lucky 之类的 DDNS 工具：

设置 → 设备与服务 → HA SSL → **选项** → 打开「启用动态域名解析」。默认每 5 分钟查一次公网地址，和记录比对，变了才改；记录不存在时自动创建。

| 选项 | 说明 |
|---|---|
| 要更新的域名 | A/AAAA 用的记录名。留空 = 证书域名；填别的子域名也可以 |
| 要维护的记录类型 | 多选：`A`（IPv4）、`AAAA`（IPv6）、`CNAME`（别名） |
| CNAME 记录名 / CNAME 指向 | 勾了 CNAME 才需要：别名记录名（如 `home`）+ 目标主机名；不能与 A/AAAA 同名 |
| 检查间隔 | 1–1440 分钟，默认 5 |

- 走的是同一套服务商凭据，不额外配置；阿里云、DNSPod、Cloudflare 都支持这三类记录。
- **A**：查公网 IPv4 并写 A 记录；检测到运营商级 NAT（`100.64/10`）会直接报错，因为那种情况改 DNS 也没用。
- **AAAA**：查公网 IPv6（自动剔除回环、链路本地、ULA 等不可路由地址），本机没有公网 IPv6 时只报该项失败，不影响 A 记录继续维护。
- **CNAME**：把一条别名记录指向你指定的主机名（常用于 `home.example.com → 已有 DDNS 域名`），按目标变化同步；DNS 不允许同名 CNAME 与 A/AAAA 并存，选项里会拦。
- 每类记录独立对账，任一类失败不会拖垮其他类；失败原因汇总在 `last_error`。
- 实体「公网 IP」「公网 IPv6」显示最新检测结果，属性里有各类记录的当前值、上一次值、zone、上次变更时间与失败原因。
- 想立刻验证：调用服务 `ha_ssl.update_ddns`，返回 IPv4/IPv6、CNAME 目标与逐类型结果（updated / unchanged / failed）。

## 实体与服务

| 类型 | 实体 |
|---|---|
| 传感器 | 证书到期时间、剩余天数、公网 IP、公网 IPv6 |
| 二进制传感器 | 证书异常 |
| 按钮 | 立即签发 |
| 开关 | 自动续期 |

| 服务 | 用途 |
|---|---|
| `ha_ssl.renew` | 立刻签发/续期一次 |
| `ha_ssl.update_ddns` | 立刻比对公网地址并改写 A / AAAA / CNAME 记录 |
| `ha_ssl.configure_https` | 写入 HTTPS 配置并重启，`restart: false` 只写不重启 |
| `ha_ssl.promote_https` | 固化待生效的 HTTPS 配置，取消自动回退 |
| `ha_ssl.probe` | 诊断：候选 ACME 目录连通性、本机 http/https 自检、HTTP 配置存储 |

## 注意

- 证书只覆盖配置的那一个域名，不支持泛域名。
- 8123 上 TLS 后明文 `http://` 立刻失效。家里 Wi-Fi 用域名访问需要路由器支持 NAT 回环；不支持就在内网用 `https://<IP>:8123` 并单独处理信任。
- 证书目录默认 `/config/ssl`，**不是** `/ssl`——后者是加载项的挂载路径，HA 本体里没有。
- 选项里可调提前续期天数（7–89），也可关掉自动续期或关掉「续期后重启」。关掉重启后，新证书要等下次手动重启才生效。

## 开发与发布

| 工作流 | 作用 |
|---|---|
| Hassfest | 官方集成校验：manifest 字段与键序、文件结构、翻译、services |
| HACS Action | HACS 发布物校验：仓库结构、`hacs.json`、集成元数据 |
| ACME Self Test | 假 ACME 服务器跑通「下单 → authz → dns-01 → finalize → 下载证书」，并检查包内跨模块导入 |
| Privacy Scan | 脱敏扫描：工作区 + **完整 git 历史**一起查，命中即红 |

本地可跑：

```bash
python3 scripts/check_privacy.py            # 只查工作区
python3 scripts/check_privacy.py --history  # 连 git 历史一起查
python3 scripts/import_check.py             # 包内导入一致性
```

脱敏检查项：邮箱、公网 IP、JWT、云厂商 AccessKey、手机号、VIN、以及白名单外的域名；输出打码（Actions 日志本身也是公开的）。
文档统一用 `example.com` 这类占位域名。历史若发现残留，用 `git filter-repo --replace-text` 重写后 force push。

发布纪律：`manifest.json` 的 `version` 与 tag 同步、按十进制逐位递增（段内不进两位数）、tag 指向最新 main、Release 不放 zip asset、全文件 UTF-8 无 BOM、README 与版本日志同步。

## 版本

<details open>
<summary>v1.2.x</summary>

- **v1.2.3**：DDNS 扩到全部记录类型——新增 AAAA（IPv6）与可选 CNAME 别名，逐类型独立对账；新增「公网 IPv6」传感器
- **v1.2.2**：修复「公网 IP」传感器缺少 `has_entity_name` 导致名字不走翻译、实体 id 退化成设备名
- **v1.2.1**：修正文档里保留网段的写法（`100.64/10`），避免脱敏扫描把它误判成公网 IP；功能无变化
- **v1.2.0**：内置动态域名——定时查询公网 IPv4，A 记录变化时自动改写（也可自动新建），新增「公网 IP」传感器与 `ha_ssl.update_ddns` 服务；三家服务商都补了记录查询/新建/修改；检测到运营商级 NAT 直接给出明确提示

</details>

<details>
<summary>v1.1.x</summary>

- **v1.1.9**：README 精简重写——快速开始、服务商凭据表、自动流程与排障入口按官方结构整理，版本历史折叠
- **v1.1.8**：修复 `__init__.py` 引用已被改名的 `cert_manager` 函数导致整个集成 `ImportError`（v1.1.5–v1.1.7 受影响）；新增包内导入静态检查并接入 CI
- **v1.1.7**：配置向导逐步骤说明（域名自动识别、`/config/ssl` 与 `/ssl` 的区别、staging 不被信任、各家取凭据路径与最小权限）；错误提示补常见原因；首次签发与启用 HTTPS 各发一条持久通知
- **v1.1.6**：域名默认从 HA 自身 URL 带出，除凭据外无需再填；HTTPS 可用后自动把 `external_url` 切成 `https://`
- **v1.1.5**：自动重启改到 `EVENT_HOMEASSISTANT_STARTED`，避免 setup 阶段调重启被拒
- **v1.1.4**：修复服务注册多传位置参数导致的 setup `TypeError`、自动启用 HTTPS 从未执行的问题
- **v1.1.3**：签发后自动启用 HTTPS——写待生效配置、重启、探测成功即固化，同一证书只尝试一次
- **v1.1.2**：manifest 补 `dependencies: ["http"]`
- **v1.1.1**：适配 HA 2026.11 的 HTTP 配置新存储（`.storage/http`，YAML 里的 `http:` 只在首次迁移生效）；新增 `promote_https`
- **v1.1.0**：probe 补本机协议自检；设备补 `sw_version`；版本号进位

</details>

<details>
<summary>v1.0.x</summary>

- **v1.0.20**：`probe` 增加 `http_storage`，直接读 `.storage` 里的 HTTP 设置
- **v1.0.19**：修正 self_probe 对 http 请求误传 `ssl=None`
- **v1.0.18**：`probe` 增加 `self_probe`，从 HA 内部直连本机 8123 的 http/https
- **v1.0.17**：`probe` 输出全部 `http:` 块与证书文件状态
- **v1.0.16**：读取证书也走可写回退目录，避免误判「没有证书」而反复申请
- **v1.0.15**：证书目录默认改 `/config/ssl`；不可写目录自动回退并提示
- **v1.0.14**：ACME 请求改「每次新建连接 + 单请求重试 3 次」，应对家庭出口握手卡死
- **v1.0.13**：新增 `probe`，逐个测候选 ACME 目录连通性
- **v1.0.12**：ACME 流量改走自建 DoH 解析（只取 A、只用 IPv4）
- **v1.0.11**：签发失败时把异常类型与完整堆栈写进日志
- **v1.0.10**：修复 finalize 轮询返回值解包错误；新增假 ACME 服务器自测与工作流
- **v1.0.9**：无证书时自动完成首次签发，不再需要手动点按钮
- **v1.0.8**：按各家 SDK 规范校正 DNSPod / Cloudflare / 阿里云的错误码、分页与幂等
- **v1.0.7**：支持阿里云、DNSPod、Cloudflare；配置改「先选服务商、再填凭据」；去掉邮箱
- **v1.0.6**：补 manifest `categories`、修正 `iot_class`、补齐深色主题品牌图
- **v1.0.5**：补齐 `brand/`、仓库 topics，HACS Action 转绿
- **v1.0.4**：加入 Hassfest / HACS Action / Privacy Scan 与脱敏脚本
- **v1.0.3**：domain 与目录改为 `ha_ssl`，服务名改为 `ha_ssl.*`
- **v1.0.2**：仓库更名为 ha-ssl
- **v1.0.1**：集成显示名改为 HA SSL
- **v1.0.0**：首个版本，阿里云 dns-01 签发 + 自动续期 + 到期实体

</details>

## 许可

MIT
