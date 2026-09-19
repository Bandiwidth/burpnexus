'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { indexSource } = require('../src/source');
const { loadTraffic, mapTraffic } = require('../src/mapping');
const { buildReview } = require('../src/review');
(async () => {
  const folder = process.argv[2]; if (!folder) throw new Error('Pass the Java or Python export directory.');
  const sourceRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'burpnexus-contract-'));
  try {
    await Promise.all([
      fs.writeFile(path.join(sourceRoot, 'app.js'), `import express from 'express';
import users from './users.js';
const app = express();
app.use('/api', authenticate, users);
app.get('/search', search);
app.post('/api/orders', createOrder);
app.get('/admin/audit', requireAdmin, audit);
function authenticate(req, res, next) { next(); }
function search(req, res) { res.json({ query: req.query.q }); }
function createOrder(req, res) { return orderService.create(req.body); }
`),
      fs.writeFile(path.join(sourceRoot, 'users.js'), `import express from 'express';
const router = express.Router();
router.get('/users/:id', getUser);
export default router;
function getUser(req, res) { return userService.findById(req.params.id); }
`)
    ]);
    const source = await indexSource(sourceRoot);
    const traffic = await loadTraffic(folder), map = mapTraffic(traffic, source);
    assert.equal(traffic.included, 3); assert.equal(map.counts.candidate, 3); assert.equal(map.counts.unmapped, 0);
    assert.ok(map.unobserved.some(r => r.path === '/admin/audit'));
    const user = map.endpoints.find(e => e.path === '/api/users/12');
    const context = buildReview(user, source, 'authorization');
    assert.ok(context.evidence.some(e => e.file === 'users.js' && e.kind === 'route'));
    assert.ok(context.evidence.some(e => e.file === 'app.js' && e.kind === 'mount'));
    assert.ok(!context.text.includes('headersecret'));
    console.log(JSON.stringify({ result: 'CONTRACT_PASS', captures: traffic.included, ...map.counts, evidenceRecords: context.evidence.length }));
  } finally {
    await fs.rm(sourceRoot, { recursive: true, force: true });
  }
})().catch(e => { console.error(e); process.exitCode = 1; });
