import { test } from 'node:test';
import assert from 'node:assert/strict';
import { machineCode, deviceId, LicenseClient } from '../src/webextension.js';

/** 模拟 chrome.storage（Promise 风格，MV3 行为） */
function memArea() {
  const data = new Map();
  return {
    data,
    async get(keys) {
      const r = {};
      for (const k of keys) if (data.has(k)) r[k] = data.get(k);
      return r;
    },
    async set(obj) {
      for (const [k, v] of Object.entries(obj)) data.set(k, v);
    },
  };
}

function mockChrome() {
  const storage = { local: memArea(), sync: memArea() };
  globalThis.chrome = { storage };
  return storage;
}

test('machineCode returns EXT- prefixed id and persists to local + sync', async () => {
  const storage = mockChrome();
  const id = await machineCode();
  assert.match(id, /^EXT-/);
  assert.ok(id.length >= 8);
  assert.equal(await machineCode(), id, 'stable across calls');
  assert.equal(storage.local.data.get('psInstallId'), id);
  assert.equal(storage.sync.data.get('psInstallId'), id);
});

test('sync id wins over conflicting local id (follows browser account)', async () => {
  const storage = mockChrome();
  storage.sync.data.set('psInstallId', 'EXT-sync-user-id');
  storage.local.data.set('psInstallId', 'EXT-local-device-id');
  const id = await machineCode();
  assert.equal(id, 'EXT-sync-user-id');
});

test('regenerates when stored id lacks EXT- prefix', async () => {
  const storage = mockChrome();
  storage.local.data.set('psInstallId', 'not-a-plugin-id');
  const id = await machineCode();
  assert.match(id, /^EXT-/);
});

test('storage unavailable throws with guidance', async () => {
  delete globalThis.chrome;
  await assert.rejects(() => machineCode(), /WebExtension storage unavailable/);
});

test('LicenseClient (webextension) purchaseUrl carries params', () => {
  mockChrome();
  const c = new LicenseClient({ productUniqueCode: 'PRO-2026-001' });
  const url = c.purchaseUrl('EXT-abc', { base: 'https://www.powersoftware.app' });
  assert.match(url, /productUniqueCode=PRO-2026-001/);
  assert.match(url, /machineCode=EXT-abc/);
});

// ---- 设备标识 deviceId ----

test('deviceId returns DID- prefixed id, persists to local only (must not sync across devices)', async () => {
  const storage = mockChrome();
  const id = await deviceId();
  assert.match(id, /^DID-[A-Za-z0-9_-]{6,64}$/);
  assert.equal(await deviceId(), id, 'stable across calls');
  assert.equal(storage.local.data.get('psDeviceId'), id);
  assert.equal(storage.sync.data.get('psDeviceId'), undefined, 'device id must not follow browser account to other machines');
});

test('deviceId regenerates when stored id lacks DID- prefix', async () => {
  const storage = mockChrome();
  storage.local.data.set('psDeviceId', 'not-a-device-id');
  const id = await deviceId();
  assert.match(id, /^DID-/);
});

test('deviceId throws without extension env', async () => {
  delete globalThis.chrome;
  await assert.rejects(() => deviceId(), /WebExtension storage unavailable/);
});

// ---- claimTrial 透传 x-device-id 头 ----

/** 捕获 fetch 入参的 mock，返回合法成功信封以走通 request() */
function captureFetch() {
  const box = {};
  const fetchImpl = async (url, init) => {
    box.url = url;
    box.headers = init.headers;
    return { ok: true, status: 200, json: async () => ({ success: true, content: { licenseCode: 'L-1', activationToken: 'tok' } }) };
  };
  return { box, fetchImpl };
}

test('claimTrial sends x-device-id header when a valid deviceId is provided', async () => {
  mockChrome();
  const { box, fetchImpl } = captureFetch();
  const c = new LicenseClient({ productUniqueCode: 'PRO-2026-001', fetchImpl });
  await c.claimTrial('EXT-abc', 'DID-0f3a123456');
  assert.equal(box.headers['x-device-id'], 'DID-0f3a123456');
});

test('claimTrial omits x-device-id for invalid or absent deviceId', async () => {
  mockChrome();
  const { box, fetchImpl } = captureFetch();
  const c = new LicenseClient({ productUniqueCode: 'PRO-2026-001', fetchImpl });
  await c.claimTrial('EXT-abc', 'garbage-not-DID-prefixed');
  assert.equal(box.headers['x-device-id'], undefined);
  await c.claimTrial('EXT-abc');
  assert.equal(box.headers['x-device-id'], undefined);
});
