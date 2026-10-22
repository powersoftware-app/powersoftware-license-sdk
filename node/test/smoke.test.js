import { test } from 'node:test';
import assert from 'node:assert/strict';
import { machineCode, sign, LicenseClient } from '../src/index.js';

test('machineCode stable & long enough', () => {
  assert.equal(machineCode(), machineCode());
  assert.ok(machineCode().length >= 8);
});

test('sign deterministic', () => {
  const params = { productUniqueCode: 'PRO-2026-001', machineCode: 'M123', edition: 'PRO', expiryDays: 0, clientOrderId: 'x', licenseCode: '', timestamp: 1000 };
  assert.equal(sign('secret', params), sign('secret', params));
});

test('sign binds billingPeriod', () => {
  const base = { productUniqueCode: 'PRO-2026-001', machineCode: 'M123', edition: 'PRO', expiryDays: 0, clientOrderId: 'x', licenseCode: 'LIC', timestamp: 1000 };
  const monthly = sign('secret', { ...base, billingPeriod: 'MONTHLY' });
  const permanent = sign('secret', { ...base, billingPeriod: 'PERMANENT' });
  // billingPeriod 必须进入签名串：仅周期不同 → 签名不同（防升级目标周期被篡改）
  assert.notEqual(monthly, permanent);
  // 归一：trim + 大写，与 selectByBusinessKey/pickLicenseEditionRow 同口径
  assert.equal(sign('secret', { ...base, billingPeriod: ' monthly ' }), monthly);
});

test('purchaseUrl carries params', () => {
  const c = new LicenseClient({ productUniqueCode: 'PRO-2026-001' });
  const url = c.purchaseUrl('MABC', { base: 'https://www.powersoftware.app' });
  assert.match(url, /productUniqueCode=PRO-2026-001/);
  assert.match(url, /machineCode=MABC/);
  assert.doesNotMatch(url, /productId=/);
});

test('checkUpdate posts updateCheck and parses content', async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, body: JSON.parse(init.body) };
    return new Response(JSON.stringify({ success: true, content: { hasUpdate: true, latestVersion: '1.3.0' } }), { status: 200 });
  };
  const c = new LicenseClient({ productUniqueCode: 'PRO-2026-001', fetchImpl });
  const result = await c.checkUpdate('1.2.0');
  assert.match(captured.url, /\/product\/updateCheck$/);
  assert.equal(captured.body.productUniqueCode, 'PRO-2026-001');
  assert.equal(captured.body.currentVersion, '1.2.0');
  assert.deepEqual(result, { hasUpdate: true, latestVersion: '1.3.0' });
});

test('getQuotaTxn posts txn and parses content', async () => {
  let captured;
  const fetchImpl = async (url, init) => {
    captured = { url, body: JSON.parse(init.body) };
    return new Response(JSON.stringify({ success: true, content: { count: 1, page: 1, pageSize: 10, totalPage: 1, content: [{ createTime: '2026-10-22T00:00:00.000Z', kind: 'quota', requestId: 'r1', amount: 0.5, pending: false }] } }), { status: 200 });
  };
  const c = new LicenseClient({ productUniqueCode: 'PRO-2026-001', fetchImpl });
  const result = await c.getQuotaTxn('LIC', 'MABC', 'tok', 2, 20);
  assert.match(captured.url, /\/license\/quota\/txn$/);
  assert.equal(captured.body.licenseCode, 'LIC');
  assert.equal(captured.body.machineCode, 'MABC');
  assert.equal(captured.body.activationToken, 'tok');
  assert.equal(captured.body.page, 2);
  assert.equal(captured.body.pageSize, 20);
  assert.equal(result.content[0].kind, 'quota');
});

test('checkUpdate requires productUniqueCode', () => {
  const c = new LicenseClient({});
  assert.throws(() => c.checkUpdate('1.2.0'), /productUniqueCode required/);
});
