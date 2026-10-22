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

/** 设备标识前缀（与服务端试用闸门 deviceId 白名单正则 ^DID-[A-Za-z0-9_-]{6,64}$ 一致） */
const DID_PREFIX = 'DID-';

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

// ---- 设备标识（试用防刷闸门信号）----

/**
 * 生成并持久化设备标识（异步），供 claimTrial 以 x-device-id 请求头上报。
 * 服务端据此区分「同机重装」与「多机各一装」做试用防刷审查：machineCode 按「产品+机器」幂等，
 * 设备标识再补一层跨重装的去重维度。缺失时不报错，服务端退回按网段维度判定。
 * 持久化：仅存 storage.local——设备标识须绑物理浏览器，进 sync 会复制到其它设备、
 * 把「多机领取」记到同一设备名下反而误触防刷。storage 不可用（非插件环境）时抛错。
 * 若要活过卸载（与官方插件 ps_did 第一方 cookie 同效），开发者可自行在 API 域设 cookie（需 host_permissions），见接入指南。
 */
export async function deviceId() {
  const storage = getStorageArea();
  if (!storage) {
    throw new Error('WebExtension storage unavailable: deviceId() requires an extension environment');
  }
  const id = await new Promise((resolve) => {
    try {
      const r = storage.local.get(['psDeviceId']);
      if (r && typeof r.then === 'function') r.then((v) => resolve(v?.psDeviceId ?? null), () => resolve(null));
      else storage.local.get(['psDeviceId'], (v) => resolve(v?.psDeviceId ?? null));
    } catch {
      resolve(null);
    }
  });
  if (id && String(id).startsWith(DID_PREFIX)) return id;
  const fresh = DID_PREFIX + randomUuid();
  try {
    const w = storage.local.set({ psDeviceId: fresh });
    if (w && typeof w.then === 'function') w.catch(() => { /* 静默，下次重试 */ });
  } catch { /* 不可写时静默，仍返回本次生成的 id */ }
  return fresh;
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

  /**
   * 激活：授权码 + 机器码 → licenseCode + activationToken
   * 返回字段按计费模型分组（不适用的恒 null）：通用 {licenseCode, activationToken, status, edition, expiryTime, billingPeriod}；
   * EDITION 专属 {softwareMajorVersion, trialDays, trialExpiryTime, licenseDeductionEnabled}；QUOTA 专属 {quotaAmount, quotaUsed, quotaRemaining, quotaNextExpiry, trialCount, trialUsed, trialRemaining, trialNextResetTime}
   */
  activate(licenseCode, machineCodeValue) {
    return this.request('/license/activate', { licenseCode, machineCode: machineCodeValue });
  }

  /**
   * 校验：有效返回 { valid, edition, expiryTime }
   * 字段×模型：EDITION 看 edition/expiryTime/billingPeriod(订阅周期)；QUOTA 看 quotaRemaining(额度门禁)/quotaNextExpiry(额度有效期)，且码不因额度耗尽 expired
   */
  verify(licenseCode, machineCodeValue, activationToken) {
    return this.request('/license/verify', { licenseCode, machineCode: machineCodeValue, activationToken });
  }

  /**
   * 额度消耗（仅 QUOTA 产品，服务端记账；EDITION 产品不调用）：插件本地 storage 拦不住跨浏览器/跨笔记本多倍消耗，
   * 改由平台在 license_usage 按票扣减并回余额（付费票 FIFO 各自有效期 / 试用周期桶）；requestId 幂等防重试重复扣，不传则本地生成。
   * @param {'quota'|'trial'} [kind] 消耗类型，默认 'quota'；'trial' 扣试用周期桶
   * @returns {Promise<{ consumed, kind, quotaUsed, quotaRemaining, quotaNextExpiry, trialUsed, trialRemaining, trialNextResetTime }>} 服务端按票聚合的双钱包余额 + 额度有效期
   */
  consume(licenseCode, machineCodeValue, activationToken, amount, requestId, kind) {
    return this.request('/license/quota/consume', {
      licenseCode,
      machineCode: machineCodeValue,
      activationToken,
      amount,
      requestId: requestId || randomUuid(),
      kind: kind || 'quota',
    });
  }

  /**
   * 消耗流水查询（仅 QUOTA 产品，只读回读；EDITION 不适用）：把 consume 落在服务端 license_quota_txn 的逐笔扣减明细读回，供用量页 / 订阅卡展示「最近消耗」，接入方无需再本地自算累计用量。鉴权与 consume 同族（凭 activationToken），只回本授权码自身的行，跨码越权直接拒绝；只读无副作用，可安全分页 / 轮询。
   * @param {number} [page=1] 页码，从 1 起
   * @param {number} [pageSize=10] 每页条数，服务端夹到 1-50
   * @returns {Promise<{ count, page, pageSize, totalPage, content: Array<{ createTime, kind, requestId, amount, pending }> }>} 分页信封 + 新→旧排序的流水行
   */
  getQuotaTxn(licenseCode, machineCodeValue, activationToken, page = 1, pageSize = 10) {
    return this.request('/license/quota/txn', {
      licenseCode,
      machineCode: machineCodeValue,
      activationToken,
      page,
      pageSize,
    });
  }

  /** 解绑（换机）：通常需登录态，浏览器场景由个人中心调用 */
  deactivate(licenseCode, machineCodeValue) {
    return this.request('/license/deactivate', { licenseCode, machineCode: machineCodeValue });
  }

  /**
   * 先用后付：领取试用授权（产品须 TRIAL_FIRST）
   * 可选第二参 deviceIdValue（由 deviceId() 生成，格式 DID-<uuid>）以 x-device-id 请求头上报，
   * 服务端试用防刷设备闸门据此跨重装去重；缺省或格式不符 ^DID-[A-Za-z0-9_-]{6,64}$ 视同未上报（仍按网段维度判定）。
   */
  claimTrial(machineCodeValue, deviceIdValue) {
    if (!this.productUniqueCode) throw new Error('productUniqueCode required');
    const did = typeof deviceIdValue === 'string' && /^DID-[A-Za-z0-9_-]{6,64}$/.test(deviceIdValue.trim()) ? deviceIdValue.trim() : undefined;
    return this.request('/license/trial/claim',
      { productUniqueCode: this.productUniqueCode, machineCode: machineCodeValue },
      { headers: did ? { 'x-device-id': did } : {} });
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

export default { machineCode, deviceId, sign, LicenseClient };
