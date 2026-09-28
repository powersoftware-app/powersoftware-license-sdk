/**
 * WebExtension（浏览器插件 MV3）适配层 —— 自包含单文件，零依赖
 *
 * 浏览器沙箱拿不到硬件指纹，"机器码"降级为插件 Install ID：
 * - 生成：'EXT-' + 随机 UUID（服务端按 EXT- 前缀识别为插件类型 machineType=PLUGIN）
 * - 持久化：chrome.storage.local 保底；chrome.storage.sync 跟随用户浏览器账号，
 *   同一账号跨设备拿到同一 ID（sync 优先读取，local 冲突时以 sync 为准）
 * - 接口：activate / verify / verifyCached / claimTrial / purchaseUrl 等与 index.js 完全一致，
 *   仅 machineCode 获取方式变为异步；sign 使用 Web Crypto（不依赖 node:crypto，
 *   因此不复用 index.js——其顶部静态 node 导入在插件打包环境无法解析）
 *
 * 用法（background service worker，manifest 需声明 "storage" 权限）：
 *   import { LicenseClient, machineCode } from './webextension.js';
 *   const client = new LicenseClient({ productUniqueCode: 'PRO-2026-001' });
 *   const mc = await machineCode();                 // 异步，返回 EXT-xxxxxxxx-...
 *   await client.activate(licenseCode, mc);
 */

const DEFAULT_BASE_URL = 'https://www.powersoftware.app/frontApi';
const VERIFY_CACHE_TTL_MS = 60 * 1000;

/** 插件 Install ID 前缀（与 ps-common MACHINE_CODE_PLUGIN_PREFIX 约定一致，服务端据此推导 machine_type） */
const EXT_PREFIX = 'EXT-';

// ---- Install ID ----

/** 判定 WebExtension storage 可用（适配 Chrome 与 Firefox 命名空间） */
function getStorageArea() {
  const api = globalThis.chrome ?? globalThis.browser;
  if (api?.storage?.local && api?.storage?.sync) return api.storage;
  return null;
}

function randomUuid() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  // 老版本浏览器兜底：getRandomValues 拼装 v4 UUID
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * 生成并持久化插件 Install ID（异步）。
 * 读取顺序：storage.sync → storage.local → 新生成（双写 local + sync）。
 * sync 与 local 冲突时以 sync 为准（跟随用户账号），并回写 local 修正。
 * storage 不可用（非插件环境）时抛错——非插件场景请用 index.js 的硬件指纹 machineCode。
 */
export async function machineCode() {
  const storage = getStorageArea();
  if (!storage) {
    throw new Error('WebExtension storage unavailable: use machineCode() from index.js in non-extension environments');
  }

  const read = (area, key) =>
    new Promise((resolve) => {
      try {
        const r = area.get([key]);
        if (r && typeof r.then === 'function') r.then((v) => resolve(v?.[key] ?? null), () => resolve(null));
        else area.get([key], (v) => resolve(v?.[key] ?? null));
      } catch {
        resolve(null);
      }
    });

  const [syncId, localId] = await Promise.all([
    read(storage.sync, 'psInstallId'),
    read(storage.local, 'psInstallId'),
  ]);

  let id = syncId || localId;
  if (!id || !String(id).startsWith(EXT_PREFIX)) {
    id = EXT_PREFIX + randomUuid();
  }

  // 双写持久化；sync 写失败（配额/未登录）时 local 保底，不影响返回
  const write = (area) => {
    try {
      const r = area.set({ psInstallId: id });
      if (r && typeof r.then === 'function') r.catch(() => { /* 静默，下次重试 */ });
    } catch { /* 配额满/不可写时静默，下次重试 */ }
  };
  write(storage.local);
  write(storage.sync);

  return id;
}

// ---- HMAC 签名（Web Crypto 版，与 index.js sign 字段序一致） ----

function toBase64Url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * HMAC 签名（software/generate、software/upgrade 必须）
 * 签名串字段以换行分隔：productUniqueCode, machineCode, edition, expiryDays, clientOrderId, licenseCode, billingPeriod, timestamp
 * billingPeriod 归一为 trim + 大写（缺省/generate 为空串），与 index.js 及服务端逐字节一致
 */
export async function sign(apiSecret, params) {
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
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(apiSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return toBase64Url(new Uint8Array(mac));
}

// ---- 校验缓存条目：60s 内复用服务端 verify 结果，过期/失败再联网 ----

function cacheHit(cache, now) {
  return cache && now - cache.at < VERIFY_CACHE_TTL_MS ? cache.data : null;
}

/** 接口与 index.js 的 LicenseClient 一致（含方法签名），仅 sign 为内部异步实现 */
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
      payload.signature = await sign(this.apiSecret, payload);
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

  /** 检查版本更新：返回 { hasUpdate, latestVersion } */
  checkUpdate(currentVersion) {
    if (!this.productUniqueCode) throw new Error('productUniqueCode required');
    return this.request('/product/updateCheck', { productUniqueCode: this.productUniqueCode, currentVersion });
  }

  /** 软件内支付后发码（HMAC 签名，幂等：clientOrderId） */
  generateForSoftware(params) {
    const body = {
      productUniqueCode: params.productUniqueCode ?? this.productUniqueCode,
      machineCode: params.machineCode,
      edition: params.edition,
      expiryDays: params.expiryDays ?? 0,
      clientOrderId: params.clientOrderId,
    };
    return this.request('/license/software/generate', body, { signed: true });
  }

  /** 软件内升级/续费（HMAC 签名，幂等：clientOrderId）；billingPeriod：目标计费周期（同版本多周期产品指定升级到哪条，缺省取该版本配置首行） */
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

  /** 带 60s 缓存的校验：付费功能点击前调用 */
  async verifyCached(licenseCode, machineCodeValue, activationToken) {
    const now = Date.now();
    const hit = cacheHit(this.verifyCache, now);
    if (hit) return hit;
    const data = await this.verify(licenseCode, machineCodeValue, activationToken);
    this.verifyCache = { at: now, data };
    return data;
  }

  /** 付费功能未授权时的购买页跳转 URL */
  purchaseUrl(machineCodeValue, { base = 'https://www.powersoftware.app' } = {}) {
    if (!this.productUniqueCode) throw new Error('productUniqueCode required');
    const u = new URL(`${base}/product/license/purchase`);
    u.searchParams.set('productUniqueCode', String(this.productUniqueCode));
    u.searchParams.set('machineCode', machineCodeValue);
    return u.toString();
  }
}

export default { machineCode, sign, LicenseClient };
