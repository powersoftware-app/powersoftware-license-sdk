# PowerSoftware License SDK Specification (v3)

This document defines the behavior that must be identical across the Node.js, Python and Java SDKs: machine code, signing, endpoints, caching and purchase-page redirect.

## 1. Machine code (cross-language consistent)

All three SDKs must produce the same `machineCode` on the same machine.

Fingerprint sources are selected by **priority** — stop at the first valid value:

```text
raw = persisted UUID → hardware serial → system machine ID → composite hardware signals → hostname | os | arch (last resort)
```

### Priority 0: Persisted UUID (computed once, then read from local file)

On first run, the SDK computes the fingerprint (priority 1–4), generates a UUID, and writes it to a local file. Subsequent calls read the file directly, skipping all hardware collection.

| Field | Description |
| --- | --- |
| File path | `$PS_LICENSE_HOME/.machine-id`, fallback `~/.powersoftware/.machine-id` |
| Generation | SHA-256(fingerprint) first 32 hex chars, formatted as UUID-style |
| Write policy | Write only if file does not exist; skip if already present |
| Stability | Machine code stays the same as long as user home / disk persists (survives rename, OS reinstall) |

### Priority 1: Hardware serial (BIOS SN, survives OS reinstall)

| OS | Source | Method | Privilege |
| --- | --- | --- | --- |
| Windows | BIOS SerialNumber | `wmic bios get serialnumber` (fallback PowerShell `Get-CimInstance Win32_BIOS`) | Standard user |
| macOS | Hardware serial | `system_profiler SPHardwareDataType` extract `Serial Number` | Standard user |
| Linux | Product serial | Read `/sys/class/dmi/id/product_serial` (fallback `dmidecode -s system-serial-number`) | **root required** |

### Priority 2: System machine ID (generated at install, stable per machine)

| OS | Source | Method | Privilege |
| --- | --- | --- | --- |
| Windows | MachineGuid | Registry `HKLM\SOFTWARE\Microsoft\Cryptography` | Standard user |
| macOS | IOPlatformUUID | `ioreg -d2 -c IOPlatformPlatformDevice` | Standard user |
| Linux | machine-id | Read `/etc/machine-id` (fallback `/var/lib/dbus/machine-id`) | All users |

### Priority 3: Composite hardware signals (MAC + platform + arch)

Used when both hardware serial and system machine ID fail. Combines multiple hardware signals so that a change in any single factor (e.g. hostname rename) does not alter the overall fingerprint.

| Signal | Node | Python | Java |
| --- | --- | --- | --- |
| MAC addresses (non-random, non-loopback) | `getmac /v` (Win) / `ifconfig` (Mac/Linux) | Same | Same |
| Platform | `os.platform()` | `sys.platform` | Mapped to `win32/darwin/linux` |
| Architecture | `os.arch()` | `platform.machine()` | `System.getProperty("os.arch")` |

MAC collection uses command-line tools uniformly (Windows: `getmac /v`, Mac/Linux: `ifconfig`) to ensure cross-language consistency.
MAC filtering: exclude all-zero, loopback (`0x02`), and locally-administered (`bit1 & 0x02`) MAC addresses.

> Note: CPU/memory signals are intentionally excluded because native APIs return different values across languages.

### Priority 4: Last resort (hostname | os | arch)

Used only when all above signals are unavailable (minimal containers, stripped systems).

| Field | Node | Python | Java |
| --- | --- | --- | --- |
| hostname | `os.hostname()` | `socket.gethostname()` | `InetAddress.getLocalHost().getHostName()` |
| os | `os.platform()` | `sys.platform` | `System.getProperty("os.name")` |
| arch | `os.arch()` | `platform.machine()` | `System.getProperty("os.arch")` |

### Normalization

- Trim and lowercase all fields;
- Filter vendor placeholder values (`To be filled by O.E.M.` / `None` / `0` / `Default` / `Not Available` / `Not Specified`);
- Join with `|`, then lowercase the whole string.

```text
machineCode = 'M' + base64url( sha256( fingerprint ) ).slice(0, 32)
```

`machineCode` is at least 8 chars, globally unique, and cached in-process by the SDK.

## 2. Signing (software/generate, software/upgrade)

Payload joined by `\n` in fixed order (empty string for missing `edition`/`licenseCode`/`billingPeriod`, `0` for `expiryDays`; `billingPeriod` normalized to trim + UPPERCASE):

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

`signature = base64url( HMAC-SHA256( licenseApiSecret, payload ) )`; `timestamp` in milliseconds, platform rejects drift > 5 minutes.

> **Compatibility window**: `billingPeriod` is now covered by the signature (to prevent tampering with the upgrade target period). During the transition the server still also accepts the legacy 7-field signature that omits it, so existing clients are not broken; please upgrade to the new SDK that includes `billingPeriod` — legacy signatures will be rejected once the window closes.

## 3. Endpoints

Base: `https://www.powersoftware.app/frontApi` (overridable).

| Endpoint | Method | Auth | SDK method |
| --- | --- | --- | --- |
| `/license/activate` | POST | none | `activate` |
| `/license/verify` | POST | none | `verify` |
| `/license/deactivate` | POST | login | `deactivate` |
| `/license/software/generate` | POST | HMAC | `generateForSoftware` |
| `/license/software/upgrade` | POST | HMAC | `upgradeForSoftware` |
| `/license/trial/claim` | POST | none | `claimTrial` |

`generateForSoftware` / `upgradeForSoftware` add `timestamp` + `signature` automatically.

### 3.0 Software upgrade params (upgradeForSoftware)

| Param | Required | Description |
| --- | --- | --- |
| `productUniqueCode` / `licenseCode` / `machineCode` / `clientOrderId` | ✅ | Product code / license code to upgrade / machine code / idempotent order ID |
| `edition` | ✅ | Target edition |
| `billingPeriod` | ❌ | Target billing period (`PERMANENT`/`MONTHLY`/`YEARLY`): when an edition has multiple billing periods, specifies which one to upgrade to; defaults to the edition's first configured row (unknown values also fall back to the first row). Periodic licenses extend expiry by `base = max(now, old expiry)`; perpetual licenses keep the legacy `expiryDays` behavior. **Included in the signature** (see §2) — the period in the request body must not be tampered with outside the signature |
| `expiryDays` | ❌ | Custom validity days for perpetual licenses (ignored for periodic ones) |

### 3.1 Upgrade policy flag (licenseUpgradeMode)

`activate` / `verify` / `claimTrial` success responses also return the product-level upgrade policy:

| Value | Meaning |
| --- | --- |
| `SAME_CODE` | The license code stays the same after upgrade/renewal |
| `NEW_CODE` | Upgrade/renewal revokes the old code and issues a new one |

Clients use it to decide whether to show a "bind license code" input: with `SAME_CODE` the code never changes, so do not prompt users to re-enter it; with `NEW_CODE` a new code is issued on upgrade/renewal — the `licenseCode` returned by `software/upgrade` must overwrite local storage. Defaults to `SAME_CODE` when the product has no setting; `verify` results are cached for 60s, so policy changes take effect within 60s.

### 3.2 Trial-quota period (trialCountPeriod / trialPeriodKey)

Alongside `trialCount` (the edition's trial quota; `null` when disabled), `activate` / `verify` / `claimTrial` success responses carry two fields:

| Field | Meaning |
| --- | --- |
| `trialCountPeriod` | `TOTAL` — one cumulative quota, over once used up (default, matches legacy behavior) / `MONTHLY` — refreshed every calendar month |
| `trialPeriodKey` | Server's current calendar-month key (e.g. `"2026-09"`, UTC) when `MONTHLY`; `null` for `TOTAL` / disabled |

The platform still records no usage: in `MONTHLY` mode persist the local counter as `{ periodKey, used }` — whenever the stored `periodKey` differs from the latest response's `trialPeriodKey`, reset `used` to 0 and store the new key. Month boundaries must be taken from the server-issued `trialPeriodKey`, **never from the local clock** (a rewound clock must not inflate the quota). Each month's quota is independent and never rolls over.

## 4. Local credential & verification cache

- Store only: `licenseCode`, `activationToken`, latest verify result (`{ valid, edition, expiryTime, trialExpiryTime }`) with a timestamp. `trialExpiryTime` is a snapshot of the original trial expiry (non-`null` after trial-to-purchase conversion); clients may use it to implement their own grace period for higher-tier features (see the integration guide, section 3.6).
- Do **not** store decryptable full license info locally (reverse engineering cannot be prevented anyway).
- Verification cache TTL 60s: check cache before each paid-feature click; on expiry or failure call the server.

## 5. Paid-feature gate & purchase page

1. `verifyCached(...)` returns valid & not expired → allow.
2. Invalid/expired/not activated → prompt "purchase & activate required".
3. Redirect with machine code (product identified by `productUniqueCode`):

```text
https://www.powersoftware.app/product/license/purchase?productUniqueCode={productUniqueCode}&machineCode={machineCode}
https://www.powersoftware.cn/product/license/purchase?productUniqueCode={productUniqueCode}&machineCode={machineCode}
```

(Multi-language sites prepend the locale prefix, e.g. `/en-US/product/license/purchase`; for the China site pass `base=https://www.powersoftware.cn`. All three SDKs implement `purchaseUrl(machineCode, { base })` consistently — `productUniqueCode` is passed to the constructor.)

### 5.1 Billing period & renewal extension (billingPeriod)

Editions can be configured with one of three billing periods; the purchase page shows prices with the period suffix (`/mo`, `/yr`; none for lifetime):

| billingPeriod | Meaning | `expiryTime` |
|---|---|---|
| `PERMANENT` (default) | Lifetime buyout | `null` (never expires) |
| `MONTHLY` | Monthly authorization — one-time purchase for a fixed 30 days (no auto-renewal) | Fixed expiry date (ISO 8601) |
| `YEARLY` | Yearly authorization — one-time purchase for a fixed 365 days (no auto-renewal) | Fixed expiry date (ISO 8601) |

- `expiryTime` in `verify` / `activate`: for periodic editions it is a fixed expiry date; once passed, verify returns the `expired` error code — handle it with your existing expiry prompt, no need to know the period type.
- **Renewal extension**: renewing before expiry (purchase page or in-app renewal) automatically extends from the **original expiry date** (`base = max(now, old expiry)`), so no remaining time is lost; renewing after expiry starts from the current time. Edition upgrades follow the same rule; upgrading to a lifetime edition clears `expiryTime`.
- If the client needs to display a "monthly/yearly" badge, the `verify`/`activate` responses now return a `billingPeriod` field you can read directly (consistent with the purchase page's edition configuration).

**Usage-based quota (licensePricingModel = QUOTA)**: on the publish page a product can be sold by **edition tiers** (`EDITION`, default) or by **usage quota** (`QUOTA`). A QUOTA product has a single Basic edition and sells **quota packs** (e.g. $9.9 for 20 uses, $20 for 100 uses); here `billingPeriod` means the **quota's valid window**. At purchase the pack's `quotaAmount` is frozen onto the license code (`license.quota_amount`) and returned by `activate` / `verify` (always `null` for EDITION products, legacy codes, and trial codes). Accumulation follows the product's **upgrade strategy**: under `SAME_CODE` (default) the platform **adds the new quota onto the existing code** when repurchasing on the same machine and stacks the expiry onto the latest end (`verify` already returns the current total); under `NEW_CODE` each order gets an independent new code while old codes stay valid, and the client sums the `quotaAmount` of all valid codes on the machine. QUOTA forces no-deduction / no-downgrade-block; usage accounting (deduct 1 per call, block at zero, balance display) is entirely client-side — the platform records no usage.

## 6. Error codes

`codeNotFound`, `revoked`, `expired`, `machineLimit`, `tooManyAttempts`, `signatureInvalid`, `apiSecretMissing`, `productNotEnabled`, `trialNotEnabled`, `trialAlreadyPurchased`, `machineCodeInvalid`, `orderAlreadyUsed`, `editionRequired`, `productNotFound`, `trialFirstRequired`, `alreadyOwned`; network/timeout errors are `NETWORK_ERROR`. `trialAlreadyPurchased`: when claiming a trial, the machine already holds a non-trial license for the product (already purchased); the platform will not issue another trial license.
