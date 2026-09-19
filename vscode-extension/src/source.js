'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const SKIP = new Set(['node_modules', 'vendor', 'build', 'dist', 'target', 'coverage', '__pycache__', 'venv', 'env', 'test', 'tests', '__tests__', 'fixtures', 'generated']);
const EXT = /\.(?:[cm]?[jt]sx?|py|java)$/i;
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const hash = text => crypto.createHash('sha256').update(text).digest('hex');
const slash = value => value.split(path.sep).join('/');
const inside = (root, file) => { const rel = path.relative(root, file); return rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel); };

// Small static lexer: strings/comments are never interpreted as route declarations.
// Expressions and runtime registration are deliberately not evaluated.
function lex(text, python = false, limit = 40000) {
  const out = []; let i = 0, line = 1;
  while (i < text.length) {
    if (out.length >= limit) { out.truncated = true; break; }
    const start = i, at = line, c = text[i];
    if (/\s/.test(c)) { if (c === '\n') line++; i++; continue; }
    if ((python && c === '#') || (!python && text.slice(i, i + 2) === '//')) { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (!python && text.slice(i, i + 2) === '/*') { i += 2; while (i < text.length && text.slice(i, i + 2) !== '*/') { if (text[i++] === '\n') line++; } i += 2; continue; }
    if (!python && c === '/' && ['=', '(', '[', ',', ':', 'return', '=>', '!'].includes(out.at(-1)?.v)) {
      i++; let bracket = false;
      while (i < text.length && text[i] !== '\n') {
        if (text[i] === '\\') { i += 2; continue; }
        if (text[i] === '[') bracket = true;
        if (text[i] === ']') bracket = false;
        if (text[i++] === '/' && !bracket) break;
      }
      while (/[a-z]/i.test(text[i] || '') && i < text.length) i++;
      out.push({ v: '<regex>', start, end: i, line: at }); continue;
    }
    if ('\'"`'.includes(c)) {
      const triple = python && text.slice(i, i + 3) === c.repeat(3), end = triple ? c.repeat(3) : c; i += end.length;
      let value = '', dynamic = false, closed = false;
      while (i < text.length) {
        if (text.slice(i, i + end.length) === end) { i += end.length; closed = true; break; }
        if (text[i] === '\\') { dynamic = true; value += text.slice(i, i + 2); i += 2; continue; }
        if (text[i] === '\n') line++;
        if (text.slice(i, i + 2) === '${') dynamic = true;
        value += text[i++];
      }
      out.push({ v: value, str: true, literal: closed && !triple && !dynamic, start, end: i, line: at }); continue;
    }
    if (/[A-Za-z_$\d]/.test(c)) { while (i < text.length && /[\w$]/.test(text[i])) i++; }
    else i++;
    out.push({ v: text.slice(start, i), start, end: i, line: at });
  }
  return out;
}
function args(tokens, open) {
  const result = [[]]; const stack = []; const pairs = { '(': ')', '[': ']', '{': '}' };
  for (let j = open + 1; j < tokens.length; j++) {
    const t = tokens[j];
    if (!t.str && t.v === ')' && !stack.length) return { parts: result, end: j };
    if (!t.str && t.v === ',' && !stack.length) { result.push([]); continue; }
    result.at(-1).push(t);
    if (!t.str && pairs[t.v]) stack.push(pairs[t.v]);
    else if (!t.str && t.v === stack.at(-1)) stack.pop();
  }
  return { parts: [], end: open };
}
const literal = tokens => tokens?.length === 1 && tokens[0].str && tokens[0].literal ? tokens[0].v : undefined;
const ident = tokens => tokens?.length && tokens.every(t => !t.str && /^[\w$.]+$/.test(t.v)) ? tokens.map(t => t.v).join('') : undefined;
const named = (parts, name) => parts.find(p => p[0]?.v === name && p[1]?.v === '=')?.slice(2);
const joinRoute = (a, b) => ('/' + a + '/' + b).replace(/\/{2,}/g, '/').replace(/\/$/, '') || '/';
function resolveModule(file, spec, files, python) {
  let base;
  if (python) {
    const dots = spec.match(/^\.+/)?.[0].length || 0;
    const dir = dots ? path.posix.dirname(file).split('/').slice(0, Math.max(0, path.posix.dirname(file).split('/').length - dots + 1)).join('/') : '';
    base = path.posix.join(dir, spec.slice(dots).replace(/\./g, '/'));
  } else {
    if (!spec.startsWith('.')) return undefined;
    base = path.posix.normalize(path.posix.join(path.posix.dirname(file), spec));
  }
  return [base, base + '.js', base + '.ts', base + '.mjs', base + '.cjs', base + '.py', base + '/index.js', base + '/index.ts', base + '/__init__.py'].find(p => files.has(p));
}

function extractRoutes(files) {
  const nodes = new Map(), raw = [], warnings = [], moduleInfo = new Map();
  let remainingTokens = 500000, routeLimit = false;
  const addRaw = route => {
    if (typeof route.path !== 'string' || route.path.length > 1024) { warnings.push(route.file + ': oversized route pattern omitted.'); return; }
    if (raw.length < 5000) raw.push(route); else routeLimit = true;
  };
  const key = (f, n) => f + '#' + n;
  for (const [file, data] of files) {
    if (remainingTokens <= 0) { warnings.push('Source token budget reached; some files were not parsed for routes.'); break; }
    const py = file.endsWith('.py'), t = lex(data.text, py, Math.min(40000, remainingTokens));
    remainingTokens -= t.length;
    if (t.truncated) warnings.push(file + ': source token limit reached; route parsing is partial.');
    const info = { imports: new Map(), exports: new Map(), tokens: t, py }; moduleInfo.set(file, info);
    // Token-based imports cannot be spoofed by comments, docstrings or examples.
    for (let i = 0; i < t.length; i++) {
      if (t[i].str) continue;
      if (t[i].v === 'export' && t[i + 1]?.v === 'default' && !t[i + 2]?.str) info.exports.set('default', t[i + 2]?.v);
      if (t.slice(i, i + 4).map(x => x.v).join('') === 'module.exports=') info.exports.set('default', t[i + 4]?.v);
      if (['const','let','var'].includes(t[i].v) && t[i + 2]?.v === '=' && t[i + 3]?.v === 'require' && t[i + 4]?.v === '(' && t[i + 5]?.literal) info.imports.set(t[i + 1].v, { spec: t[i + 5].v, name: 'default' });
      if (!py && t[i].v === 'import') {
        let j = i + 1; while (j < t.length && j < i + 60 && !t[j].str && t[j].v !== 'from' && t[j].v !== ';') j++;
        if (t[j]?.v !== 'from' || !t[j + 1]?.literal) continue;
        const spec = t[j + 1].v;
        if (/^\w+$/.test(t[i + 1]?.v)) info.imports.set(t[i + 1].v, { spec, name: 'default' });
        if (t[i + 1]?.v === '{') for (let k = i + 2; k < j - 1; k++) {
          if (!/^\w+$/.test(t[k].v)) continue;
          const name = t[k].v, alias = t[k + 1]?.v === 'as' ? t[k + 2]?.v : name;
          info.imports.set(alias, { spec, name }); if (alias !== name) k += 2;
        }
      }
      if (py && t[i].v === 'from') {
        let j = i + 1; while (j < t.length && t[j].line === t[i].line && !t[j].str && t[j].v !== 'import') j++;
        if (t[j]?.v !== 'import') continue;
        const spec = t.slice(i + 1, j).map(x => x.v).join('');
        for (let k = j + 1; k < t.length && t[k].line === t[j].line; k++) {
          if (!/^\w+$/.test(t[k].v)) continue;
          const name = t[k].v, alias = t[k + 1]?.v === 'as' ? t[k + 2]?.v : name;
          info.imports.set(alias, { spec, name }); if (alias !== name) k += 2;
        }
      }
    }
    for (let i = 0; i < t.length; i++) {
      if (t[i].str || t[i + 1]?.v !== '=' || t[i + 1].str) continue;
      const name = t[i].v; let j = i + 2; const constructor = [];
      while (t[j] && !t[j].str && /^[\w$.]+$/.test(t[j].v)) constructor.push(t[j++].v);
      if (t[j]?.v !== '(') continue;
      const type = constructor.join('');
      if (!['express', 'express.Router', 'Router', 'Flask', 'Blueprint', 'FastAPI', 'APIRouter'].includes(type)) continue;
      const call = args(t, j), prefixName = type === 'Blueprint' ? 'url_prefix' : 'prefix';
      const prefixTokens = named(call.parts, prefixName); let prefix = prefixTokens ? literal(prefixTokens) : '';
      if (prefix?.length > 1024) prefix = undefined;
      if (nodes.size < 5000) nodes.set(key(file, name), { file, name, type, prefix, mounts: [], root: ['express', 'Flask', 'FastAPI'].includes(type), line: t[i].line });
      else warnings.push('Router node limit reached.');
    }
    // Next.js app router uses file-based routes, with method-specific exports.
    const next = file.match(/(?:^|\/)(?:src\/)?app\/(.*)\/route\.[jt]s$/) || file.match(/(?:^|\/)(?:src\/)?app\/route\.[jt]s$/);
    if (next) {
      const segments = (next[1] || '').split('/').filter(s => s && !/^\(.*\)$/.test(s) && !s.startsWith('@'));
      if (!segments.some(s => s.includes('('))) {
        const route = '/' + segments.map(s => s.replace(/^\[\[\.\.\.(\w+)\]\]$/, '*$1?').replace(/^\[\.\.\.(\w+)\]$/, '*$1').replace(/^\[(\w+)\]$/, ':$1')).join('/');
        for (let i = 0; i < t.length; i++) if (!t[i].str && t[i].v === 'export') {
          const tail = t.slice(i + 1, i + 5).filter(x => !x.str).map(x => x.v); const method = tail.find(x => METHODS.includes(x));
          if (method && (tail.includes('function') || tail.includes('const'))) addRaw({ file, line: t[i].line, method, path: route, framework: 'Next.js app', confidence: 'candidate', reason: 'File route and exported HTTP method; deployment basePath is not inferred.' });
        }
      }
    }
    if (file.endsWith('.java')) {
      // Bind class prefixes by brace nesting, avoiding leakage between controllers.
      const classes = []; let pending = [], depth = 0;
      for (let i = 0; i < t.length; i++) {
        if (t[i].str) continue;
        if (t[i].v === '{') depth++;
        if (t[i].v === '}') { depth--; while (classes.at(-1)?.depth > depth) classes.pop(); }
        if (t[i].v === '@' && /^(?:Request|Get|Post|Put|Patch|Delete|Head|Options)Mapping$/.test(t[i + 1]?.v || '')) {
          const name = t[i + 1].v, call = t[i + 2]?.v === '(' ? args(t, i + 2) : { parts: [], end: i + 1 };
          const p = named(call.parts, 'path') || named(call.parts, 'value') || (call.parts[0]?.[1]?.v === '=' ? undefined : call.parts[0]);
          let paths = [''];
          if (p?.length) { const one = literal(p); paths = one !== undefined ? [one] : p[0]?.v === '{' && p.at(-1)?.v === '}' && p.slice(1,-1).every(x => x.str && x.literal || x.v === ',') ? p.filter(x => x.str).map(x => x.v) : []; }
          const methodTokens = named(call.parts, 'method');
          const methods = name === 'RequestMapping' ? (methodTokens ? methodTokens.filter(x => METHODS.includes(x.v)).map(x => x.v) : ['ANY']) : [name.replace('Mapping', '').toUpperCase()];
          pending.push({ paths, methods, line: t[i].line }); i = call.end; continue;
        }
        if (t[i].v === '@') {
          if (t[i + 2]?.v === '(') i = args(t, i + 2).end;
          else i++;
          continue;
        }
        if (t[i].v === 'class' || t[i].v === 'interface') {
          const prefix = pending.length ? pending.at(-1).paths : ['']; pending = [];
          let j = i; while (j < t.length && t[j].v !== '{') j++;
          classes.push({ depth: depth + 1, prefix }); i = j - 1; continue;
        }
        if (pending.length && t[i].v === '(' && t[i - 1]?.v && classes.length) {
          for (const p of pending) for (const prefix of classes.at(-1).prefix) for (const route of p.paths) for (const method of p.methods)
            addRaw({ file, line: p.line, method, path: joinRoute(prefix, route), framework: 'Spring MVC', confidence: 'candidate', reason: 'Literal class and method mapping; security filters, inheritance and deployment context are not resolved.' });
          pending = [];
        }
      }
    }
  }
  function resolve(file, ref) {
    if (nodes.has(key(file, ref))) return key(file, ref);
    const info = moduleInfo.get(file), [head, tail] = ref.split('.'), imported = info.imports.get(head);
    if (!imported) return undefined;
    const target = resolveModule(file, imported.spec, files, info.py);
    if (target && (!tail || imported.name === '*')) { const name = tail || moduleInfo.get(target)?.exports.get(imported.name) || imported.name; if (nodes.has(key(target, name))) return key(target, name); }
    if (info.py) { const mod = resolveModule(file, imported.spec + (imported.spec.endsWith('.') ? '' : '.') + imported.name, files, true); if (mod && tail && nodes.has(key(mod, tail))) return key(mod, tail); }
    return undefined;
  }
  for (const [file, info] of moduleInfo) {
    const t = info.tokens;
    for (let i = 0; i < t.length - 3; i++) {
      if (t[i].str || t[i + 1]?.v !== '.' || t[i + 2]?.str || t[i + 3]?.v !== '(') continue;
      const receiver = resolve(file, t[i].v), node = nodes.get(receiver), verb = t[i + 2].v;
      if (!node) continue;
      const call = args(t, i + 3), route = literal(call.parts[0]);
      if (['use', 'include_router', 'register_blueprint'].includes(verb)) {
        const pt = named(call.parts, verb === 'register_blueprint' ? 'url_prefix' : 'prefix');
        const firstRef = ident(call.parts[0]);
        let prefix = verb === 'use' ? (route === undefined ? (firstRef && resolve(file, firstRef) ? '' : undefined) : route) : pt ? literal(pt) : '';
        if (prefix?.length > 1024) prefix = undefined;
        const children = verb === 'use' ? call.parts.slice(route === undefined ? 0 : 1) : call.parts.slice(0, 1);
        for (const arg of children) {
          const ref = ident(arg), child = ref && resolve(file, ref);
          if (nodes.has(child)) {
            if (nodes.get(child).mounts.length < 50) nodes.get(child).mounts.push({ parent: receiver, prefix, file, line: t[i].line, override: verb === 'register_blueprint' && !!pt });
            else warnings.push('Router mount limit reached.');
          }
        }
      }
      if (route !== undefined && verb === 'route' && !info.py) {
        let end = call.end;
        while (t[end + 1]?.v === '.' && METHODS.includes(t[end + 2]?.v.toUpperCase()) && t[end + 3]?.v === '(') {
          addRaw({ file, line: t[end + 2].line, method: t[end + 2].v.toUpperCase(), path: route, node: receiver, framework: node.type, confidence: 'candidate' });
          const next = args(t, end + 3); if (next.end <= end) break; end = next.end;
        }
      }
      if (route === undefined || !route.startsWith('/') || !(METHODS.includes(verb.toUpperCase()) || ['all', 'route'].includes(verb))) continue;
      if (info.py && t[i - 1]?.v !== '@') continue;
      const mt = named(call.parts, 'methods');
      const methods = verb === 'route' ? (info.py ? (mt ? mt.filter(x => x.str && METHODS.includes(x.v)).map(x => x.v) : ['GET']) : []) : verb === 'all' ? ['ANY'] : [verb.toUpperCase()];
      for (const method of methods) addRaw({ file, line: t[i].line, method, path: route, node: receiver, framework: node.type, confidence: 'candidate' });
    }
  }
  function prefixes(id, seen = new Set()) {
    const n = nodes.get(id); if (!n || seen.has(id) || seen.size > 12 || n.prefix === undefined) return [];
    if (n.root) return [{ prefix: n.prefix, evidence: [] }];
    const next = new Set([...seen, id]), result = [];
    for (const mount of n.mounts.slice(0, 50)) {
      if (mount.prefix === undefined) continue;
      for (const parent of prefixes(mount.parent, next)) {
        const combined = joinRoute(parent.prefix, joinRoute(mount.prefix, mount.override ? '' : n.prefix));
        if (combined.length > 1024) continue;
        result.push({ prefix: combined, evidence: [...parent.evidence, { file: mount.file, line: mount.line }] });
        if (result.length >= 50) return result;
      }
    }
    return result;
  }
  const routes = [];
  for (const route of raw) {
    if (routes.length >= 5000) { routeLimit = true; break; }
    if (!route.node) { routes.push(route); continue; }
    const resolved = prefixes(route.node);
    if (!resolved.length) { warnings.push(`${route.file}:${route.line}: router mount/prefix is unresolved; excluded from matching.`); continue; }
    for (const p of resolved) {
      if (routes.length >= 5000) { routeLimit = true; break; }
      const fullPath = joinRoute(p.prefix, route.path);
      if (fullPath.length > 1024) { warnings.push(route.file + ': oversized composed route omitted.'); continue; }
      routes.push({ ...route, path: fullPath, mounts: p.evidence, reason: 'Literal method/path and statically resolved router mounts. Candidate linkage, not runtime reachability.' });
    }
  }
  if (routeLimit) warnings.push('Route declaration limit reached; coverage is partial.');
  return { routes: routes.map((r, i) => ({ ...r, id: 'R' + (i + 1) })), warnings };
}

async function indexSource(folder, { excludes = [], cancelled = () => false, maxFiles = 4000, maxBytes = 20_000_000 } = {}) {
  const root = await fs.realpath(folder), files = new Map(), warnings = []; let bytes = 0, visited = 0, skipped = 0;
  const excluded = excludes.filter(x => typeof x === 'string').map(x => x.replace(/\\/g, '/').replace(/\/$/, ''));
  async function walk(dir, depth = 0) {
    if (depth > 20) { warnings.push('Source directory depth limit reached.'); return; }
    const entries = (await fs.readdir(dir, { withFileTypes: true })).sort((a,b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      if (cancelled()) throw new Error('Indexing cancelled');
      if (++visited > 30000 || files.size >= maxFiles || bytes >= maxBytes) { warnings.push('Source indexing limit reached; coverage is partial.'); return; }
      const full = path.join(dir, e.name), rel = slash(path.relative(root, full));
      if (e.isSymbolicLink() || e.name.startsWith('.') || SKIP.has(e.name.toLowerCase()) || excluded.some(x => rel === x || rel.startsWith(x + '/'))) { skipped++; continue; }
      if (e.isDirectory()) { await walk(full, depth + 1); continue; }
      if (!e.isFile() || !EXT.test(e.name) || /(?:\.min\.|\.test\.|\.spec\.|(?:^|[._-])(?:secrets?|credentials?)(?:[._-]|$))/i.test(e.name)) { skipped++; continue; }
      try {
        if (!inside(root, await fs.realpath(full))) throw new Error('Path leaves source repository');
        const handle = await fs.open(full, 'r'); let content;
        try {
          const stat = await handle.stat(); if (stat.size > 300_000 || stat.size + bytes > maxBytes) throw new Error('Source byte limit');
          const buffer = Buffer.alloc(300_001); const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
          if (bytesRead > 300_000 || bytes + bytesRead > maxBytes) throw new Error('Source byte limit');
          content = buffer.subarray(0, bytesRead); bytes += bytesRead;
        } finally { await handle.close(); }
        if (content.includes(0)) throw new Error('Binary source omitted');
        const text = content.toString('utf8'); files.set(rel, { text, hash: hash(text), lines: text.split(/\r?\n/) });
      } catch (e) { warnings.push(rel + ': ' + e.message); }
    }
  }
  await walk(root);
  const parsed = extractRoutes(files);
  if (parsed.routes.length > 5000) warnings.push('Only the first 5000 route declarations are indexed.');
  return { root, files, routes: parsed.routes.slice(0, 5000), warnings: [...new Set([...warnings, ...parsed.warnings])], bytes, skipped };
}
module.exports = { lex, extractRoutes, indexSource, hash, inside, METHODS };
