'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const SECRET = /password|passwd|token|secret|api[-_]?key|authorization|cookie|session|csrf|xsrf|private[-_]?key|credential|ssn|credit[-_]?card/i;
const MASK = '[REDACTED]';

function redactString(value) {
  if (/^[\s]*[\[{]/.test(value)) {
    try { return JSON.stringify(redact(JSON.parse(value))); } catch { /* non-JSON body */ }
  }
  return value.replace(/^(authorization|proxy-authorization|cookie|set-cookie|x-[\w-]*(?:token|key|auth)):[^\r\n]*/gim, '$1: ' + MASK)
    .replace(/((?:password|passwd|[\w-]*token|[\w-]*secret|api[_-]?key|session(?:_?id)?|csrf|xsrf|credential)\s*[=:]\s*)([^&\s;<>]+)/gi, '$1' + MASK)
    .replace(/\bBearer\s+[^\s"'<>]+|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]+|sk-[A-Za-z0-9_-]{16,})/gi, MASK);
}
function redactUrl(value) {
  try {
    const absolute = /^https?:\/\//i.test(value);
    const url = new URL(value, 'https://placeholder.invalid');
    url.username = ''; url.password = ''; url.hash = '';
    for (const k of [...new Set(url.searchParams.keys())]) {
      if (SECRET.test(k) || /^(key|auth)$/i.test(k)) url.searchParams.set(k, MASK);
    }
    return redactString(absolute ? url.href : url.pathname + url.search);
  } catch { return redactString(value); }
}
function redact(value, key = '') {
  if (SECRET.test(key)) return MASK;
  if (Array.isArray(value)) return value.map(v => redact(v));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k, redact(v,k)]));
  if (typeof value === 'string') return /^(url|path)$/i.test(key) ? redactUrl(value) : redactString(value);
  return value;
}
async function readJson(root, relative) {
  const filename = path.resolve(root, relative);
  const real = await fs.realpath(filename);
  const rel = path.relative(root, real);
  if (rel.startsWith('..') || path.isAbsolute(rel)) throw new Error('Corpus file leaves the selected directory');
  const stat = await fs.lstat(filename);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 1_000_000) throw new Error('File is linked, oversized or not a regular file');
  const handle = await fs.open(filename, 'r');
  try {
    const bytes = Buffer.alloc(1_000_001);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    if (bytesRead > 1_000_000) throw new Error('File exceeds size limit');
    return JSON.parse(bytes.subarray(0, bytesRead).toString('utf8'));
  } finally { await handle.close(); }
}
async function loadContext(folder, budget = 48000) {
  const root = await fs.realpath(folder);
  const summary = await readJson(root, 'attack-surface-index.json');
  if (!summary.summary || !Number.isInteger(summary.summary.total_items)) throw new Error('Choose a BurpNexus export directory');
  const records = []; const warnings = []; let remaining = budget; let included = 0; let visited = 0;
  function add(file, data) {
    const block = JSON.stringify({ file, data: redact(data) });
    if (block.length + 1 > remaining) { warnings.push(`${file}: omitted by context limit`); return false; }
    records.push(block); remaining -= block.length + 1; return true;
  }
  add('attack-surface-index.json', summary);
  try {
    const findings = await readJson(root, 'security-findings.json');
    add('security-findings.json', Array.isArray(findings) ? findings.slice(0, 50) : findings);
  } catch (e) { if (e.code !== 'ENOENT') warnings.push('security-findings.json: ' + e.message); }
  async function walk(dir, depth = 0) {
    if (depth > 20 || included >= 50 || visited >= 5000 || remaining < 500) return;
    const entries = (await fs.readdir(dir, { withFileTypes: true })).sort((a,b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (++visited > 5000 || included >= 50 || remaining < 500) break;
      if (entry.isSymbolicLink() || entry.name.startsWith('.')) continue;
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) { await walk(file, depth + 1); continue; }
      if (!/^\d+_.+\.json$/.test(entry.name)) continue;
      const rel = path.relative(root, file).split(path.sep).join('/');
      try {
        const item = await readJson(root, rel);
        if (!item.metadata || !item.request || !item.response) throw new Error('Invalid item schema');
        const data = { metadata: item.metadata,
          request: { headers: item.request.headers, body: redactString(String(item.request.body || '')).slice(0, 1200) },
          response: { headers: item.response.headers, body: redactString(String(item.response.body || '')).slice(0, 1200) } };
        if (add(rel, data)) included++;
      } catch (e) { warnings.push(rel + ': ' + e.message); }
    }
  }
  await walk(root);
  if (included < summary.summary.total_items) warnings.push('Bounded sample: some items are omitted (file, depth, item or context limits).');
  return { text: records.join('\n'), included, total: summary.summary.total_items, warnings, root };
}
module.exports = { redact, redactString, redactUrl, readJson, loadContext };
