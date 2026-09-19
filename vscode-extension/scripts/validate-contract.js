'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const { indexSource } = require('../src/source');
const { loadTraffic, mapTraffic } = require('../src/mapping');
const { buildReview } = require('../src/review');
(async () => {
  const folder = process.argv[2]; if (!folder) throw new Error('Pass the Java or Python export directory.');
  const source = await indexSource(path.resolve(__dirname, '../../examples/source-review/repo'));
  const traffic = await loadTraffic(folder), map = mapTraffic(traffic, source);
  assert.equal(traffic.included, 3); assert.equal(map.counts.candidate, 3); assert.equal(map.counts.unmapped, 0);
  assert.ok(map.unobserved.some(r => r.path === '/admin/audit'));
  const user = map.endpoints.find(e => e.path === '/api/users/12');
  const context = buildReview(user, source, 'authorization');
  assert.ok(context.evidence.some(e => e.file === 'users.js' && e.kind === 'route'));
  assert.ok(context.evidence.some(e => e.file === 'app.js' && e.kind === 'mount'));
  assert.ok(!context.text.includes('headersecret'));
  console.log(JSON.stringify({ result: 'CONTRACT_PASS', captures: traffic.included, ...map.counts, evidenceRecords: context.evidence.length }));
})().catch(e => { console.error(e); process.exitCode = 1; });
