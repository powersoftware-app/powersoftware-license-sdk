# 授权 SDK 规范（v3）

> 依据：`ps-help/v3/doc/售卖方式与授权购买链路_v3.md`、帮助中心 LICENSE_API_DOC（v3）。
> 目标：Node / Python / Java 三语言 SDK 行为一致（机器码、签名、接口、缓存、错误码、购买页跳转）。

## 1. 机器码算法（跨语言一致）

同一台机器上三语言 SDK 必须生成相同的 `machineCode`。

指纹来源按**优先级**选取，取到有效值即停止：

```text
raw = 持久化 UUID → 硬件序列号 → 系统机器 ID → 硬件信号组合 → hostname | os | arch（兜底）
```

### 优先级 0：本地持久化 UUID（首次计算后写入文件，后续直接读取）

首次运行时，按优先级 1–4 计算 fingerprint，生成 UUID 并写入本地文件；后续调用直接读取该文件，跳过所有硬件采集。

| 字段 | 说明 |
| --- | --- |
| 文件路径 | `$PS_LICENSE_HOME/.machine-id`，未设环境变量时回退 `~/.powersoftware/.machine-id` |
| 生成方式 | SHA-256(fingerprint) 前 32 位 hex，格式化为 UUID 样式 |
| 写入策略 | 仅文件不存在时写入，已有则跳过 |
| 稳定性 | 只要用户目录/磁盘不变，机器码不变（跨重启、跨改名、跨重装） |

### 优先级 1：硬件序列号（BIOS SN，重装系统不变）

| 系统 | 来源 | 获取方式 | 权限 |
| --- | --- | --- | --- |
| Windows | BIOS SerialNumber | `wmic bios get serialnumber`（降级 PowerShell `Get-CimInstance Win32_BIOS`） | 普通用户 |
| macOS | 硬件序列号 | `system_profiler SPHardwareDataType` 提取 `Serial Number` | 普通用户 |
| Linux | 产品序列号 | 读 `/sys/class/dmi/id/product_serial`（降级 `dmidecode -s system-serial-number`） | **需 root** |

### 优先级 2：系统机器 ID（安装时生成，同机不变）

| 系统 | 来源 | 获取方式 | 权限 |
| --- | --- | --- | --- |
| Windows | MachineGuid | 注册表 `HKLM\SOFTWARE\Microsoft\Cryptography` | 普通用户 |
| macOS | IOPlatformUUID | `ioreg -d2 -c IOPlatformPlatformDevice` | 普通用户 |
| Linux | machine-id | 读 `/etc/machine-id`（降级 `/var/lib/dbus/machine-id`） | 所有用户 |

### 优先级 3：硬件信号组合（MAC + 平台 + 架构）

当硬件序列号和系统机器 ID 均获取失败时，组合多个硬件信号生成指纹。单一因素变化（如改名）不会导致整体指纹变化。

| 信号 | Node | Python | Java |
| --- | --- | --- | --- |
| MAC 地址（非随机、非回环） | `getmac /v`（Win）/ `ifconfig`（Mac/Linux） | 同左 | 同左 |
| 平台 | `os.platform()` | `sys.platform` | 映射为 `win32/darwin/linux` |
| 架构 | `os.arch()` | `platform.machine()` | `System.getProperty("os.arch")` |

MAC 采集统一用命令行工具（Windows: `getmac /v`，Mac/Linux: `ifconfig`），确保跨语言结果一致。
MAC 过滤规则：去除全零、回环 (`0x02`)、本地位设置 (`bit1 & 0x02`) 的 MAC 地址。

> 注：不含 CPU/内存信号，因各语言原生 API 取值不同，无法保证跨语言一致。

### 优先级 4：兜底（hostname | os | arch）

当以上全部不可用时使用（极端精简系统、容器等）。

| 字段 | Node | Python | Java |
| --- | --- | --- | --- |
| hostname | `os.hostname()` | `socket.gethostname()` | `InetAddress.getLocalHost().getHostName()` |
| os | `os.platform()` | `sys.platform` | `System.getProperty("os.name")` |
| arch | `os.arch()` | `platform.machine()` | `System.getProperty("os.arch")` |

### 统一处理

- 所有字段去除首尾空白并转小写；
- 过滤厂商占位值（`To be filled by O.E.M.` / `None` / `0` / `Default` / `Not Available` / `Not Specified`）；
- 拼接符统一为 `|`，整体再 `toLowerCase()`。

```text
machineCode = 'M' + base64url( sha256( fingerprint ) ).slice(0, 32)
```

`machineCode` 至少 8 位，全平台唯一，且 SDK 内部缓存（进程内）。

## 2. 签名规则（software/generate、software/upgrade 必须）

签名串按固定顺序、以 `\n` 换行分隔（缺省填空值：`edition` 空串、`expiryDays` 0、`licenseCode` 空串、`billingPeriod` 空串且归一为 trim + 大写）：

```text
productUniqueCode
machineCode
edition
expiryDays
clientOrderId
licenseCode
billingPeriod
timestamp
```

`signature = base64url( HMAC-SHA256( licenseApiSecret, 签名串 ) )`；`timestamp` 为毫秒，平台校验与服务器时间差 ≤ 5 分钟（防重放）。

> **兼容窗口**：`billingPeriod` 已纳入签名（防止升级目标周期被篡改）。服务端在过渡期内仍同时接受不含该段的旧 7 段签名以不打断存量客户端；请尽快升级到含 `billingPeriod` 的新版 SDK，过渡期结束后旧签名将被拒绝。

## 3. 接口清单

前缀：`https://www.powersoftware.app/frontApi`（可通过 `baseUrl` 覆盖）。

| 接口 | 路径 | 鉴权 | SDK 方法 |
| --- | --- | --- | --- |
| 激活 | `POST /license/activate` | 无 | `activate(licenseCode, machineCode)` |
| 校验 | `POST /license/verify` | 无 | `verify(licenseCode, machineCode, activationToken)` |
| 解绑 | `POST /license/deactivate` | 登录（浏览器场景） | `deactivate(licenseCode, machineCode)` |
| 软件内发码 | `POST /license/software/generate` | HMAC 签名 | `generateForSoftware({...})` |
| 软件内升级/续费 | `POST /license/software/upgrade` | HMAC 签名 | `upgradeForSoftware({...})` |
| 领取试用 | `POST /license/trial/claim` | 无 | `claimTrial(machineCode)` |
| 检查版本更新 | `POST /product/updateCheck` | 无 | `checkUpdate(currentVersion)` |

`generateForSoftware` / `upgradeForSoftware` 自动补 `timestamp` + `signature`；`claimTrial` 需产品为先用后付。

### 3.0 软件内升级/续费参数（upgradeForSoftware）

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `productUniqueCode` / `licenseCode` / `machineCode` / `clientOrderId` | ✅ | 产品编码 / 待升级授权码 / 机器码 / 幂等订单号 |
| `edition` | ✅ | 目标版本 |
| `billingPeriod` | ❌ | 目标计费周期（`PERMANENT`/`MONTHLY`/`YEARLY`）：同一版本可配多条计费周期时指定升级到哪条；缺省取该版本配置首行（指定了不存在的周期也回退首行）。周期版按 `base = max(now, 旧到期)` 顺延有效期，永久版保留旧 `expiryDays` 兼容行为。**参与签名**（见 §2）：请求体里的周期不得在签名外被篡改 |
| `expiryDays` | ❌ | 永久版自定义有效天数（周期版忽略该参数） |

### 3.1 检查版本更新（checkUpdate）

请求：

```json
{ "productUniqueCode": "PRO-2026-001", "currentVersion": "1.2.0" }
```

响应（`content` 字段）：

```json
{ "hasUpdate": true, "latestVersion": "1.3.0" }
```

- 匿名可访问，仅返回**已上架**产品的版本信息；产品不存在 / 未上架 / 未填版本统一返回 `{ "hasUpdate": false, "latestVersion": null }`（不报错）。
- 版本号按数字段逐段比较（`1.10.0` > `1.2.0`）；`currentVersion` 格式宽松，非数字段（如 `1.2.0-beta`）按数字段参与比较。
- 服务端长缓存（多级，Cache API + KV）：产品审核通过 / 上下架 / 编辑版本后缓存自动失效，生效延迟约 1 分钟。
- 客户端建议：启动时异步调用、成功后间隔 ≥ 6 小时再查；`hasUpdate=true` 时引导用户到产品详情页下载；网络失败静默降级，不阻塞主流程。

### 3.2 升级策略标识（licenseUpgradeMode）

`activate` / `verify` / `claimTrial` 的成功响应额外返回产品级升级策略：

| 取值 | 含义 |
| --- | --- |
| `SAME_CODE` | 原码不变：升级/续费后授权码不变 |
| `NEW_CODE` | 原码换绑：升级/续费吊销旧码、签发新码 |

客户端据此决定是否展示「绑定授权码」输入框：`SAME_CODE` 下码不变，无需引导用户重新输入；`NEW_CODE` 下升级/续费会签发新码，须以 `software/upgrade` 返回的新 `licenseCode` 覆盖本地存储。产品未配置时返回 `SAME_CODE`；`verify` 结果缓存 60 秒，策略变更最长 60 秒生效。

### 3.3 试用额度周期（trialCountPeriod / trialPeriodKey）

`activate` / `verify` / `claimTrial` 成功响应中，`trialCount`（版本配置的试用额度，未启用为 `null`）附带两个字段：

| 字段 | 含义 |
| --- | --- |
| `trialCountPeriod` | `TOTAL` 累计总额度（默认，扣完即止，与存量行为一致）/ `MONTHLY` 每自然月重置 |
| `trialPeriodKey` | `MONTHLY` 时服务器当前自然月 key（如 `"2026-09"`，UTC）；`TOTAL` / 未启用时为 `null` |

平台仍不记录消耗：`MONTHLY` 模式下客户端按 `{ periodKey, used }` 持久化用量——本地 `periodKey` 与最近一次响应的 `trialPeriodKey` 不一致时清零并按新 key 重新计数。月份边界**以服务器下发的 `trialPeriodKey` 为准，勿用本地时钟判定**（防改表刷额度）；每月额度独立，未用完不结转。

## 4. 本地凭证与校验缓存

- 本地**只存**：`licenseCode`、`activationToken`、最近一次 verify 结果（`{ valid, edition, expiryTime, trialExpiryTime }` + 时间戳）。`trialExpiryTime` 为原试用授权到期时间快照（试用转购买后非 `null`），客户端可据此自行实现高档功能宽限期（详见接入指南 3.6 节）。
- **不存**可解密的完整授权信息（防逆向无意义，只作缓存）。
- 校验缓存 TTL 60s：点击付费功能时先查缓存，未过期直接用；过期或失败再调服务端 `verify`。
- 服务端吊销/退款/升级会主动失效缓存（平台侧已实现），SDK 无需感知。

## 5. 付费功能拦截与购买页跳转

付费菜单按钮点击：

1. `verifyCached(licenseCode, machineCode, activationToken)` 返回有效且未过期 → 放行；
2. 返回无效/过期/未激活 → 弹窗提示"需要购买激活授权"；
3. 生成 `machineCode`，跳转购买页（产品标识为 `productUniqueCode`，携带机器码）：

```text
https://www.powersoftware.app/product/license/purchase?productUniqueCode={productUniqueCode}&machineCode={machineCode}
```

（多语言站点在路径前加语言前缀，如 `/en-US/product/license/purchase`；`productUniqueCode` 由构造器传入。）

### 5.1 计费周期与续费顺延（billingPeriod）

平台版本可配置三种计费周期，购买页价格按周期展示（`/月`、`/年`，永久无后缀）：

| billingPeriod | 含义 | `expiryTime` |
|---|---|---|
| `PERMANENT`（默认） | 永久买断 | `null`（永久有效） |
| `MONTHLY` | 按月授权，一次性购买固定 30 天（非自动续费） | 固定到期日（ISO 8601） |
| `YEARLY` | 按年授权，一次性购买固定 365 天（非自动续费） | 固定到期日（ISO 8601） |

- `verify` / `activate` 的 `expiryTime`：周期版为固定到期日，到期后 verify 返回 `expired` 错误码，客户端按既有过期逻辑弹购买提示即可，无需感知周期类型；
- **续费顺延**：未到期续购（平台购买页或软件内续购）时，新有效期自动在**原到期时间**基础上顺延（`base = max(now, 旧到期)`），不损失剩余时长；过期后续购从当前时间起算；跨版本升级同理，升级到永久版会清空 `expiryTime` 回归永久语义；
- 客户端如需展示「按月/按年」标识，`verify` / `activate` 响应已返回 `billingPeriod` 字段，可直接取用（与购买页版本配置一致）。

**按量额度（licensePricingModel = QUOTA）**：发布页可选「版本分层（`EDITION`，默认）」或「按量额度（`QUOTA`）」两种售卖模式。QUOTA 产品只有单一基本版，以**额度包**出售（如 9.9 元 20 次、20 元 100 次），此时 `billingPeriod` 语义为**额度有效期**；购买时本包 `quotaAmount` 固化到授权码（`license.quota_amount`），`activate` / `verify` 响应随带该字段（EDITION 产品、存量码与试用码恒为 `null`）。额度累加跟随产品「升级策略」：`SAME_CODE`（默认）下平台在同机复购时把新额度**累加到原码**、到期时间叠加顺延（`verify` 返回即当前总额度）；`NEW_CODE` 下每单发独立新码、旧码保持有效，由客户端对同机多张有效码的 `quotaAmount` 求和。QUOTA 强制不抵扣、不拦降级；消耗记账（每次调用扣 1、归零拦截、余额展示）全部在客户端本地实现，平台不记录用量。

### 5.错误码（SDK 抛错统一携带 errorCode）

`codeNotFound`、`revoked`、`expired`、`machineLimit`、`tooManyAttempts`、`signatureInvalid`、`apiSecretMissing`、`productNotEnabled`、`trialNotEnabled`、`trialAlreadyPurchased`、`machineCodeInvalid`、`orderAlreadyUsed`、`editionRequired`、`productNotFound`、`trialFirstRequired`、`alreadyOwned` 等；网络/超时错误统一为 `NETWORK_ERROR`。`trialAlreadyPurchased`：领取试用时该机器在产品下已存在非试用授权（已购买），平台不再发放试用授权码。

## 6. 包结构

```text
ps-sdk/
  node/     @mizhanchengxi/ps-license-sdk（ESM，零依赖）
  python/   ps-license-sdk（py3，零依赖）
  java/     com.powersoftware:sdk（Java 8+，JDK 自带 HTTP/加密）
```

三个包均提供：`machineCode()`、`sign()`、`LicenseClient`（上述 6 方法 + `verifyCached` + `purchaseUrl`）。
