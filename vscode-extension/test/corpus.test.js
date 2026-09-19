const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { loadContext, redact, redactUrl, redactString } = require('../src/corpus');

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'burpnexus-test-'));
  t.after(async () => { assert.equal(path.dirname(root), os.tmpdir()); await fs.rm(root, { recursive: true, force: true }); });
  await fs.writeFile(path.join(root, 'attack-surface-index.json'), JSON.stringify({ summary: { total_items: 1 } }));
  await fs.mkdir(path.join(root, 'example.test'));
  await fs.writeFile(path.join(root, 'example.test', '0001_GET_users.json'), JSON.stringify({
    metadata: { url: 'https://u:pwd@example.test/?access%5Ftoken=urlsecret', method: 'GET', path: '/users' },
    request: { headers: { Authorization: 'Bearer headersecret', Cookie: 'sid=cookiesecret' }, body: '{"password":"bodysecret"}' },
    response: { headers: {}, body: '<script>window.bad=true</script>' }
  }));
  return root;
}
test('redacts nested secrets without destroying nonsensitive data', () => {
  assert.deepEqual(redact({ a: [{ token: 123, keep: 'ok' }] }), { a: [{ token: '[REDACTED]', keep: 'ok' }] });
});
test('redacts URL encoded keys and user info', () => {
  const url = redactUrl('https://a:pwd@example.test/x?access%5Ftoken=secret&q=keep');
  assert.ok(!url.includes('pwd')); assert.ok(!url.includes('secret')); assert.ok(url.includes('q=keep'));
});
test('redacts form and raw authorization', () => {
  assert.ok(!redactString('password=secret&x=ok').includes('secret'));
  assert.ok(!redactString('Authorization: Basic secret\r\n').includes('secret'));
});
test('loads both Java and Python corpus schema and redacts', async t => {
  const root = await fixture(t); const result = await loadContext(root);
  assert.equal(result.included, 1); assert.equal(result.total, 1);
  for (const secret of ['urlsecret', 'headersecret', 'cookiesecret', 'bodysecret']) assert.ok(!result.text.includes(secret));
  assert.ok(result.text.includes('0001_GET_users.json'));
});
test('requires a BurpNexus summary marker', async t => {
  const root = await fixture(t); await fs.writeFile(path.join(root, 'attack-surface-index.json'), '{}');
  await assert.rejects(loadContext(root), /export directory/);
});
test('enforces total context budget', async t => {
  const root = await fixture(t); const result = await loadContext(root, 150);
  assert.ok(result.text.length <= 150); assert.equal(result.included, 0); assert.ok(result.warnings.length);
});
test('reports oversized files rather than loading them', async t => {
  const root = await fixture(t); await fs.writeFile(path.join(root, 'example.test', '0002_GET_big.json'), 'x'.repeat(1000001));
  const result = await loadContext(root); assert.ok(result.warnings.some(w => w.includes('oversized')));
});
test('caps sampling at 50 items', async t => {
  const root = await fixture(t);
  for (let i = 2; i < 80; i++) await fs.writeFile(path.join(root, `${String(i).padStart(4,'0')}_GET_x.json`), JSON.stringify({ metadata: {}, request: {}, response: {} }));
  const result = await loadContext(root); assert.equal(result.included, 50);
});
