import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { execSync } from 'node:child_process';
import fs from 'node:fs';

const DEFAULT_BASE_URL = 'https://www.powersoftware.app/frontApi';
const VERIFY_CACHE_TTL_MS = 60 * 1000;

function toBase64Url(buf) {
  return Buffer.from(buf).toString('base64url');
}

/**
 * 机器码：跨语言一致算法（见 powersoftware-license-sdk/docs/授权SDK规范_v3.md）
 * fingerprint 优先级：
 * 0. 本地持久化 UUID（首次计算后写入文件，后续直接读取，跨重启稳定）
 * 1. 硬件序列号（BIOS SN，重装系统不变）
 * 2. 系统机器 ID（MachineGuid / machine-id / IOPlatformUUID）
 * 3. 硬件信号组合（MAC + CPU + 内存 + 平台，改名/重装系统不变）
 * 4. 兜底 hostname | os | arch（仅当以上全部不可用时）
 */
export function machineCode() {
  const raw = resolveRaw();
  const digest = crypto.createHash('sha256').update(raw).digest();
  return 'M' + toBase64Url(digest).slice(0, 32);
}

function resolveRaw() {
  const persisted = readPersistedUuid();
  if (persisted) return persisted;
  const fp = getFingerprint();
  const uid = crypto.createHash('sha256').update(fp).digest('hex')
    .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12}).*/, '$1-$2-$3-$4-$5');
  writePersistedUuid(uid);
  return uid;
}

function getFingerprint() {
  const platform = os.platform();
  const isWin = platform === 'win32';
  const isMac = platform === 'darwin';
  const isLinux = platform === 'linux';

  // 1. 硬件序列号
  let hw = null;
  if (isWin) hw = readWindowsBiosSerial();
  else if (isMac) hw = readMacSerial();
  else if (isLinux) hw = readLinuxHardwareSerial();
  if (isMeaningful(hw)) return hw.toLowerCase();

  // 2. 系统机器 ID
  let sysId = null;
  if (isWin) sysId = readWindowsMachineGuid();
  else if (isMac) sysId = readMacPlatformUUID();
  else if (isLinux) sysId = readLinuxMachineId();
  if (isMeaningful(sysId)) return sysId.toLowerCase();

  // 3. 硬件信号组合（MAC + CPU + 内存 + 平台 + 架构）
  const composite = compositeFingerprint();
  if (composite) return composite;

  // 4. 兜底
  return [os.hostname(), platform, os.arch()].join('|').toLowerCase();
}

function compositeFingerprint() {
  // 仅使用跨语言采集一致的信号（MAC + 平台 + 架构），不含 CPU/内存（各语言取值不同）
  const parts = [];
  const macs = getStableMacAddresses();
  if (macs.length > 0) parts.push('mac:' + macs.sort().join(','));
  parts.push('plat:' + os.platform());
  parts.push('arch:' + os.arch());
  return parts.length > 2 ? parts.join('|').toLowerCase() : '';
}

/** 过滤厂商占位值（"To be filled by O.E.M." / "None" / "0" 等） */
function isMeaningful(value) {
  if (!value) return false;
  const s = value.trim().toLowerCase();
  if (!s || s === 'none' || s === '0' || s === 'default') return false;
  if (s.includes('to be filled') || s.includes('o.e.m')) return false;
  if (s.includes('system serial') || s.includes('not available') || s.includes('not specified')) return false;
  return true;
}

// ---- 持久化 UUID ----

function persistPath() {
  const base = process.env.PS_LICENSE_HOME || path.join(os.homedir(), '.powersoftware');
  return path.join(base, '.machine-id');
}

function readPersistedUuid() {
  try {
    const val = fs.readFileSync(persistPath(), 'utf8').trim();
    if (val && val.length >= 8) return val;
  } catch { /* 文件不存在或读取失败 */ }
  return null;
}

function writePersistedUuid(uid) {
  try {
    const p = persistPath();
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, uid, 'utf8');
  } catch { /* 写入失败静默忽略 */ }
}

// ---- MAC 地址采集 ----

function getStableMacAddresses() {
  // 统一用命令行采集，确保跨语言一致。
  // Windows: getmac /v（MAC 格式不受系统语言影响）
  // Mac/Linux: ifconfig（输出通常为英文）
  const macs = [];
  const platform = os.platform();
  let out = null;
  if (platform === 'win32') {
    try { out = execSync('getmac /v', { timeout: 5000, encoding: 'utf8' }); } catch {}
    if (out) {
      const re = /([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}/g;
      let m;
      while ((m = re.exec(out)) !== null) {
        const mac = m[0].replace(/-/g, ':').toLowerCase();
        if (isStableMac(mac)) macs.push(mac);
      }
    }
  } else {
    try { out = execSync('ifconfig', { timeout: 5000, encoding: 'utf8' }); } catch {}
    if (out) {
      const re = /ether\s+([0-9a-fA-F:]{17})/g;
      let m;
      while ((m = re.exec(out)) !== null) {
        const mac = m[1].toLowerCase();
        if (isStableMac(mac)) macs.push(mac);
      }
    }
  }
  return [...new Set(macs)];
}

function isStableMac(mac) {
  const s = mac.replace(/:/g, '').replace(/-/g, '');
  if (s.length < 12 || s === '0'.repeat(12)) return false;
  const firstByte = parseInt(s.slice(0, 2), 16);
  // 回环
  if (firstByte === 0x02) return false;
  // 本地管理位：第二低位为 1 表示随机/本地分配
  if (firstByte & 0x02) return false;
  return true;
}

// ---- Windows ----

function readWindowsBiosSerial() {
  try {
    const out = execSync('wmic bios get serialnumber', { timeout: 5000, encoding: 'utf8' });
    for (const line of out.split(/\r?\n/)) {
      const t = line.trim();
      if (t && t.toLowerCase() !== 'serialnumber' && isMeaningful(t)) return t;
    }
  } catch { /* wmic 可能在新版 Windows 已移除 */ }
  try {
    const out = execSync('powershell -NoProfile -Command "(Get-CimInstance Win32_BIOS).SerialNumber"', { timeout: 10000, encoding: 'utf8' });
    const t = out.trim();
    if (isMeaningful(t)) return t;
  } catch { /* fall through */ }
  return null;
}

function readWindowsMachineGuid() {
  try {
    const out = execSync('reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', { timeout: 5000, encoding: 'utf8' });
    const m = out.match(/MachineGuid\s+REG_SZ\s+(.+)/);
    if (m) return m[1].trim();
  } catch { /* fall through */ }
  return null;
}

// ---- macOS ----

function readMacSerial() {
  try {
    const out = execSync('system_profiler SPHardwareDataType', { timeout: 10000, encoding: 'utf8' });
    const m = out.match(/Serial Number.*?:\s*(.+)/);
    if (m) return m[1].trim();
  } catch { /* fall through */ }
  return null;
}

function readMacPlatformUUID() {
  try {
    const out = execSync('ioreg -d2 -c IOPlatformPlatformDevice', { timeout: 10000, encoding: 'utf8' });
    const m = out.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
    if (m) return m[1].trim();
  } catch { /* fall through */ }
  return null;
}

// ---- Linux ----

function readLinuxHardwareSerial() {
  const paths = ['/sys/class/dmi/id/product_serial', '/sys/class/dmi/id/board_serial'];
  for (const p of paths) {
    try {
      const content = fs.readFileSync(p, 'utf8').trim();
      if (isMeaningful(content)) return content;
    } catch { /* 非root通常读不到 */ }
  }
  try {
    const out = execSync('dmidecode -s system-serial-number', { timeout: 5000, encoding: 'utf8' });
    const t = out.trim();
    if (isMeaningful(t)) return t;
  } catch { /* fall through */ }
  return null;
}

function readLinuxMachineId() {
  const paths = ['/etc/machine-id', '/var/lib/dbus/machine-id'];
  for (const p of paths) {
    try {
      const content = fs.readFileSync(p, 'utf8').trim();
      if (content) return content;
    } catch { /* fall through */ }
  }
  return null;
}

/**
 * HMAC 签名（software/generate、software/upgrade 必须）
 * 签名串字段以换行分隔：productUniqueCode, machineCode, edition, expiryDays, clientOrderId, licenseCode, billingPeriod, timestamp
 * billingPeriod 归一为 trim + 大写（缺省/generate 为空串）；服务端兼容窗口期内仍接受未含该段的旧 7 段签名
 */
export function sign(apiSecret, params) {
  const payload = [
    params.productUniqueCode ?? '',
    params.machineCode ?? '',
    params.edition ?? '',
    params.expiryDays ?? 0,
    params.clientOrderId ?? '',
    params.licenseCode ?? '',
    String(params.billingPeriod ?? '').trim().toUpperCase(),
    params.timestamp ?? '',
  ].join('\n');
  return toBase64Url(crypto.createHmac('sha256', apiSecret).update(payload).digest());
}

/**
 * 软件 /license/software/addQuota 专用 HMAC 签名（与 generate/upgrade 的 sign() 互不影响）。
 * 签名串换行分隔：productUniqueCode, licenseCode, addAmount, quotaType, clientOrderId, edition, timestamp
 * quotaType 归一 trim+大写（缺省 quota）；edition 缺省空串；与服务端 buildSoftwareAddQuotaSignPayload 逐字节一致。
 */
export function signAddQuota(apiSecret, params) {
  const payload = [
    params.productUniqueCode ?? '',
    params.licenseCode ?? '',
    params.addAmount ?? 0,
    String(params.quotaType ?? 'quota').trim().toUpperCase(),
    params.clientOrderId ?? '',
    String(params.edition ?? '').trim(),
    params.timestamp ?? '',
  ].join('\n');
  return toBase64Url(crypto.createHmac('sha256', apiSecret).update(payload).digest());
}

/** 校验缓存条目：60s 内复用服务端 verify 结果，过期/失败再联网 */
function cacheHit(cache, now) {
  return cache && now - cache.at < VERIFY_CACHE_TTL_MS ? cache.data : null;
}

export class LicenseClient {
  constructor({ baseUrl = DEFAULT_BASE_URL, apiSecret = '', productUniqueCode, fetchImpl = fetch, cacheTtlMs = VERIFY_CACHE_TTL_MS } = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiSecret = apiSecret;
    this.productUniqueCode = productUniqueCode;
    this.fetchImpl = fetchImpl;
    this.cacheTtlMs = cacheTtlMs;
    this.verifyCache = null;
  }

  async request(path, body, { signed = false, headers = {} } = {}) {
    let payload = body ?? {};
    if (signed) {
      payload = { ...body, timestamp: Date.now() };
      payload.signature = sign(this.apiSecret, payload);
    }
    const resp = await this.fetchImpl(this.baseUrl + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(payload),
    });
    const json = await resp.json().catch(() => ({}));
    if (!resp.ok || json.success !== true) {
      const err = new Error(json?.tip || `request failed: ${resp.status}`);
      err.errorCode = json?.content?.errorCode || json?.code || 'REQUEST_FAILED';
      throw err;
    }
    return json.content;
  }

  /** 激活：授权码 + 机器码 → licenseCode + activationToken */
  activate(licenseCode, machineCodeValue) {
    return this.request('/license/activate', { licenseCode, machineCode: machineCodeValue });
  }

  /** 校验：有效返回 { valid, edition, expiryTime } */
  verify(licenseCode, machineCodeValue, activationToken) {
    return this.request('/license/verify', { licenseCode, machineCode: machineCodeValue, activationToken });
  }

  /** 解绑（换机）：通常需登录态，浏览器场景由个人中心调用 */
  deactivate(licenseCode, machineCodeValue) {
    return this.request('/license/deactivate', { licenseCode, machineCode: machineCodeValue });
  }

  /** 先用后付：领取试用授权（产品须 TRIAL_FIRST） */
  claimTrial(machineCodeValue) {
    if (!this.productUniqueCode) throw new Error('productUniqueCode required');
    return this.request('/license/trial/claim', { productUniqueCode: this.productUniqueCode, machineCode: machineCodeValue });
  }

  /**
   * 检查版本更新：返回 { hasUpdate, latestVersion }。
   * hasUpdate=true 时自行引导用户到产品详情页下载新版本；网络失败由调用方静默降级。
   */
  checkUpdate(currentVersion) {
    if (!this.productUniqueCode) throw new Error('productUniqueCode required');
    return this.request('/product/updateCheck', { productUniqueCode: this.productUniqueCode, currentVersion });
  }

  /** 软件内支付后发码（HMAC 签名，幂等：clientOrderId）；billingPeriod：目标计费周期（同版本多周期产品指定发哪条，缺省取该版本配置首行；QUOTA/周期产品据此固化额度/周期）*/
  generateForSoftware(params) {
    const body = {
      productUniqueCode: params.productUniqueCode ?? this.productUniqueCode,
      machineCode: params.machineCode,
      edition: params.edition,
      expiryDays: params.expiryDays ?? 0,
      billingPeriod: params.billingPeriod,
      clientOrderId: params.clientOrderId,
    };
    return this.request('/license/software/generate', body, { signed: true });
  }

  /** 软件内升级/续费（HMAC 签名，幂等：clientOrderId）；billingPeriod：目标计费周期（同版本多周期产品指定升级到哪条，缺省取该版本配置首行）*/
  upgradeForSoftware(params) {
    const body = {
      productUniqueCode: params.productUniqueCode ?? this.productUniqueCode,
      licenseCode: params.licenseCode,
      machineCode: params.machineCode,
      edition: params.edition,
      expiryDays: params.expiryDays ?? 0,
      billingPeriod: params.billingPeriod,
      clientOrderId: params.clientOrderId,
    };
    return this.request('/license/software/upgrade', body, { signed: true });
  }
  
  /**
   * 非平台代收：给 QUOTA 额度码累加额度（HMAC 签名，走 addQuota 专用签名串）。
   * quotaType: 'trial' 累加试用额度 trialCount（不改版本）| 'quota'（默认）累加付费额度 quotaAmount。
   * edition（仅 quota）：加额度同时把码转到该付费版本；clientOrderId：审计/追溯（平台不做订单级幂等，重复发放由调用方去重）。
   */
  addQuotaForSoftware(params) {
    const body = {
      productUniqueCode: params.productUniqueCode ?? this.productUniqueCode,
      licenseCode: params.licenseCode,
      addAmount: params.addAmount,
      quotaType: params.quotaType ?? 'quota',
      timestamp: Date.now(),
    };
    if (params.edition != null) body.edition = params.edition;
    if (params.clientOrderId != null) body.clientOrderId = params.clientOrderId;
    body.signature = signAddQuota(this.apiSecret, body);
    return this.request('/license/software/addQuota', body);
  }

  /** 带 60s 缓存的校验：付费功能点击前调用 */
  async verifyCached(licenseCode, machineCodeValue, activationToken) {
    const now = Date.now();
    const hit = cacheHit(this.verifyCache, now);
    if (hit) return hit;
    const data = await this.verify(licenseCode, machineCodeValue, activationToken);
    this.verifyCache = { at: now, data };
    return data;
  }

  /**
   * 付费功能未授权时的购买页跳转 URL。
   * 产品标识：构造器 productUniqueCode（开发者中心唯一编码）。
   */
  purchaseUrl(machineCodeValue, { base = 'https://www.powersoftware.app' } = {}) {
    if (!this.productUniqueCode) throw new Error('productUniqueCode required');
    const u = new URL(`${base}/product/license/purchase`);
    u.searchParams.set('productUniqueCode', String(this.productUniqueCode));
    u.searchParams.set('machineCode', machineCodeValue);
    return u.toString();
  }
}

export default { machineCode, sign, signAddQuota, LicenseClient };
