'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const { readJson, redact, redactUrl } = require('./corpus');
const { hash, METHODS } = require('./source');

async function loadTraffic(folder, { cancelled = () => false, maxItems = 5000 } = {}) {
  const root = await fs.realpath(folder), index = await readJson(root, 'attack-surface-index.json');
  const total = index?.summary?.total_items;
  if (!Number.isInteger(total) || total < 0) throw new Error('Choose a BurpNexus JSON export with attack-surface-index.json.');
  const endpoints = new Map(), sessionGroups = new Map(), warnings = []; let visited = 0, included = 0, attempts = 0, bytes = 0;
  async function walk(dir, depth = 0) {
    if (depth > 20) { warnings.push('Traffic depth limit reached.'); return; }
    const entries = (await fs.readdir(dir, { withFileTypes: true })).sort((a,b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      if (cancelled()) throw new Error('Indexing cancelled');
      if (++visited > 30000 || attempts >= maxItems || endpoints.size >= 2000 || bytes >= 50_000_000) { warnings.push('Traffic indexing limit reached.'); return; }
      if (e.isSymbolicLink() || e.name.startsWith('.')) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { await walk(full, depth + 1); continue; }
      if (!e.isFile() || !/^\d+_.+\.json$/.test(e.name)) continue;
      const file = path.relative(root, full).split(path.sep).join('/'); attempts++;
      try {
        const stat = await fs.stat(full); bytes += stat.size;
        if (bytes > 50_000_000) throw new Error('Traffic byte limit reached.');
        const raw = await readJson(root, file), meta = raw.metadata;
        if (!meta || !raw.request || !raw.response || !METHODS.includes(String(meta.method).toUpperCase())) throw new Error('Unsupported item schema or method');
        if (typeof meta.url !== 'string' || meta.url.length > 8192) throw new Error('Traffic URL exceeds the 8192-character limit or is invalid');
        const url = new URL(meta.url); if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Non-HTTP URL');
        const method = meta.method.toUpperCase(), key = method + ' ' + url.origin + url.pathname;
        const endpoint = endpoints.get(key) || { id: 'E' + (endpoints.size + 1), method, origin: url.origin, path: url.pathname, count: 0, samples: [], variants: new Set() };
        endpoint.count++; included++;
        const sessionTag = String(meta.session_tag || '');
        if (sessionTag && !sessionGroups.has(sessionTag)) sessionGroups.set(sessionTag, 'session-group-' + (sessionGroups.size + 1));
        const sessionGroup = sessionGroups.get(sessionTag) || 'unknown';
        const variant = String(meta.status) + '/' + sessionGroup;
        if (endpoint.samples.length < 3 && (!endpoint.variants.has(variant) || endpoint.samples.length === 0)) {
          const clean = redact({ metadata: { method, url: meta.url, status: meta.status, session_tag: meta.session_tag || 'unknown' }, request: { headers: raw.request.headers, body: raw.request.body || '' }, response: { headers: raw.response.headers, body: raw.response.body || '' } });
          // Keep comparable anonymous buckets without exposing original session labels.
          clean.metadata.session_tag = sessionGroup;
          for (const side of ['request','response']) {
            clean[side].body = String(clean[side].body).slice(0, 2400);
            clean[side].headers = JSON.stringify(clean[side].headers || {}).slice(0, 4000);
          }
          endpoint.samples.push({ id: 'T' + hash(file).slice(0, 12), file, hash: hash(JSON.stringify(raw)), data: clean });
        }
        endpoint.variants.add(variant); endpoints.set(key, endpoint);
      } catch (e) { if (warnings.length < 200) warnings.push(file + ': ' + e.message); }
    }
  }
  await walk(root);
  if (included !== total) warnings.push(`${included}/${total} exported items indexed. Limits, invalid files or Markdown-only exports may leave gaps.`);
  return { root, total, included, endpoints: [...endpoints.values()].map(e => ({ ...e, variants: e.variants.size })), warnings: [...new Set(warnings)] };
}

function matchRoute(pattern, observed) {
  // Segment matching avoids executing regexes supplied by repositories.
  const a = Array.isArray(pattern) ? pattern : pattern.split('/').filter(Boolean), b = Array.isArray(observed) ? observed : observed.split('/').filter(Boolean);
  let literalCount = 0, parameters = 0, uncertain = false;
  for (let i = 0, j = 0; i < a.length || j < b.length; i++, j++) {
    const token = a[i], value = b[j];
    if (!token) return null;
    if (/^\*\w+\??$/.test(token) || token === '**' || /^<path:\w+>$/.test(token)) {
      if (i !== a.length - 1 || (!value && !token.endsWith('?'))) return null;
      return { literalCount, parameters: parameters + 1, uncertain: true };
    }
    if (/^:\w+\??$/.test(token) || /^\{\w+\}$/.test(token) || /^<(?:\w+:)?\w+>$/.test(token)) {
      if (!value && !token.endsWith('?')) return null;
      if (value && /^<int:/.test(token) && !/^\d+$/.test(value)) return null;
      if (value && /^<uuid:/.test(token) && !/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i.test(value)) return null;
      parameters++; continue;
    }
    if (/[{}:*<>()[\]?]/.test(token)) return null; // Unsupported dynamic/constrained patterns.
    if (token !== value) return null;
    literalCount++;
  }
  return { literalCount, parameters, uncertain };
}
function validateRewrites(rewrites) {
  if (!Array.isArray(rewrites) || rewrites.length > 30) throw new Error('pathRewrites must be an array of at most 30 rules.');
  const seen = new Set();
  return rewrites.map(r => {
    if (!r || !['origin','from','to'].every(k => typeof r[k] === 'string')) throw new Error('Each rewrite needs origin, from and to strings.');
    const u = new URL(r.origin);
    if (!['http:', 'https:'].includes(u.protocol) || u.origin !== r.origin || !/^\/[^?#]*$/.test(r.from) || !/^\/[^?#]*$/.test(r.to) || r.from.includes('..') || r.to.includes('..')) throw new Error('Rewrite origins must be exact HTTP origins and prefixes must be absolute URL paths.');
    const key = r.origin + r.from.replace(/\/$/, ''); if (seen.has(key)) throw new Error('Duplicate rewrite origin/prefix.'); seen.add(key);
    return r;
  }).sort((a,b) => b.from.length - a.from.length);
}
function mapTraffic(traffic, source, rewrites = []) {
  const rules = validateRewrites(rewrites), seen = new Set();
  const routeSegments = new Map(source.routes.map(r => [r.id, r.path.split('/').filter(Boolean)]));
  const endpoints = traffic.endpoints.map(e => {
    const rule = rules.find(r => r.origin === e.origin && (r.from === '/' || e.path === r.from.replace(/\/$/, '') || e.path.startsWith(r.from.replace(/\/$/, '') + '/')));
    const effectivePath = rule ? ('/' + rule.to + '/' + e.path.slice(rule.from === '/' ? 0 : rule.from.replace(/\/$/, '').length)).replace(/\/{2,}/g, '/') : e.path;
    const observedSegments = effectivePath.split('/').filter(Boolean);
    const matches = []; let matchCount = 0;
    for (const r of source.routes) {
      if (r.method !== 'ANY' && r.method !== e.method && !(e.method === 'HEAD' && r.method === 'GET' && ['express','Router','express.Router','Flask','Blueprint'].includes(r.framework))) continue;
      const match = matchRoute(routeSegments.get(r.id), observedSegments);
      if (match) { matchCount++; if (matches.length < 30) matches.push({ ...r, match }); seen.add(r.id); }
    }
    matches.sort((a,b) => b.match.literalCount - a.match.literalCount || a.file.localeCompare(b.file) || a.line - b.line);
    return { ...e, display: `${e.method} ${redactUrl(e.origin + e.path)}`, effectivePath, rewrite: rule, matches, matchCount, state: matchCount === 0 ? 'unmapped' : matchCount === 1 ? 'candidate' : 'ambiguous' };
  });
  return { endpoints, unobserved: source.routes.filter(r => !seen.has(r.id)), counts: { endpoints: endpoints.length, candidate: endpoints.filter(e => e.state === 'candidate').length, ambiguous: endpoints.filter(e => e.state === 'ambiguous').length, unmapped: endpoints.filter(e => e.state === 'unmapped').length, unobservedRoutes: source.routes.filter(r => !seen.has(r.id)).length } };
}
module.exports = { loadTraffic, matchRoute, validateRewrites, mapTraffic };
