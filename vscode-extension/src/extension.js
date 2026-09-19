'use strict';
const vscode = require('vscode');
const path = require('node:path');
const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { indexSource, inside, hash } = require('./source');
const { loadTraffic, mapTraffic } = require('./mapping');
const { readJson } = require('./corpus');
const { CHECKLISTS, buildReview, parseReview } = require('./review');
const { html } = require('./webview');
const { allPlaybooks, buildTestPlan } = require('./playbooks');
const { getPublicReference } = require('./public-bounty');

function abortable(promise, token) {
  return new Promise((resolve, reject) => {
    if (token.isCancellationRequested) { Promise.resolve(promise).catch(() => {}); reject(new Error('Analysis cancelled or timed out.')); return; }
    const subscription = token.onCancellationRequested(() => reject(new Error('Analysis cancelled or timed out.')));
    Promise.resolve(promise).then(resolve, reject).finally(() => subscription.dispose());
  });
}
async function checkSnapshot(review, session) {
  const checked = new Set();
  for (const e of review.evidence) {
    if (checked.has(e.kind + e.file)) continue; checked.add(e.kind + e.file);
    const root = e.kind === 'traffic' ? session.traffic.root : session.source.root;
    const file = path.resolve(root, e.file), real = await fs.realpath(file);
    if (!inside(root, real) || (await fs.lstat(file)).isSymbolicLink()) throw new Error('Evidence path changed. Refresh the map.');
    if (e.kind === 'traffic') {
      if (hash(JSON.stringify(await readJson(root, e.file))) !== e.hash) throw new Error('Traffic changed since preview. Refresh the map.');
    } else {
      if ((await fs.stat(file)).size > 300000 || hash(await fs.readFile(file, 'utf8')) !== e.sourceHash) throw new Error('Source changed since preview. Refresh the map.');
    }
  }
}
function activate(context) {
  let activePanel;
  context.subscriptions.push({ dispose() { activePanel?.dispose(); } });
  const trusted = () => { if (vscode.workspace.isTrusted) return true; vscode.window.showErrorMessage('Trust the workspace before using BurpNexus.'); return false; };
  const config = () => vscode.workspace.getConfiguration('burpnexus');
  async function chooseFolder(label, initial) {
    const result = await vscode.window.showOpenDialog({ defaultUri: initial ? vscode.Uri.file(initial) : undefined, canSelectFolders: true, canSelectFiles: false, canSelectMany: false, openLabel: label });
    return result?.[0].fsPath;
  }
  async function connect() {
    const previous = context.workspaceState.get('connection');
    const workspace = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    const corpus = await chooseFolder('Select BurpNexus JSON export', previous?.corpus || (workspace && path.resolve(workspace, config().get('corpusPath', '.'))));
    if (!corpus) return;
    const source = await chooseFolder('Select target application source repository', previous?.source || workspace);
    if (!source) return;
    return { corpus, source };
  }
  async function start(reconnect = false) {
    if (!trusted()) return;
    try {
      const connection = reconnect ? await connect() : context.workspaceState.get('connection') || await connect();
      if (!connection) return;
      const session = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'BurpNexus: indexing traffic and source locally', cancellable: true }, async (_, token) => {
        const cancelled = () => token.isCancellationRequested;
        const [traffic, source] = await Promise.all([loadTraffic(connection.corpus, { cancelled }), indexSource(connection.source, { cancelled, excludes: config().get('sourceExcludes', []) })]);
        if (cancelled()) throw new Error('Indexing cancelled');
        return { traffic, source, map: mapTraffic(traffic, source, config().get('pathRewrites', [])) };
      });
      await context.workspaceState.update('connection', connection);
      activePanel?.dispose();
      const panel = vscode.window.createWebviewPanel('burpnexus.analysis', 'BurpNexus · Source review', vscode.ViewColumn.One, { enableScripts: true, localResourceRoots: [] });
      activePanel = panel;
      let cancellation, busy = false, disposed = false, preview, report;
      const additional = new Map();
      panel.onDidDispose(() => { disposed = true; cancellation?.cancel(); if (activePanel === panel) activePanel = undefined; });
      const post = data => { if (!disposed) void panel.webview.postMessage(data); };
      panel.webview.html = html(crypto.randomBytes(24).toString('base64'));
      const state = () => post({ type: 'state', counts: session.map.counts, corpus: connection.corpus, source: connection.source, playbooks: allPlaybooks(),
        coverage: `${session.traffic.included}/${session.traffic.total} captures · ${session.source.files.size} source files · ${session.source.routes.length} route declarations`,
        warnings: [...session.traffic.warnings, ...session.source.warnings],
        endpoints: session.map.endpoints.map(e => ({ id: e.id, label: e.display, origin: e.origin, state: e.state, count: e.count, matchCount: e.matchCount, matches: e.matches.map(r => ({ id: r.id, file: r.file, line: r.line, path: r.path, method: r.method, framework: r.framework })) })),
        unobserved: session.map.unobserved.map(r => ({ id: r.id, file: r.file, line: r.line, method: r.method, path: r.path })) });
      async function save(data, title, name, markdown = false) {
        const uri = await vscode.window.showSaveDialog({ title, defaultUri: vscode.Uri.file(path.join(session.traffic.root, name)), filters: markdown ? { Markdown: ['md'] } : { JSON: ['json'] } });
        if (uri) { await fs.writeFile(uri.fsPath, markdown ? data : JSON.stringify(data, null, 2) + '\n', 'utf8'); post({ type: 'status', text: 'Saved ' + uri.fsPath }); }
      }
      panel.webview.onDidReceiveMessage(async message => {
        if (!trusted() || !message || typeof message.type !== 'string') return;
        try {
          if (message.type === 'ready') return state();
          if (message.type === 'cancel') return cancellation?.cancel();
          if (busy) return;
          if (message.type === 'openReference') {
            const reference = getPublicReference(message.id);
            if (reference) await vscode.env.openExternal(vscode.Uri.parse(reference.url));
            return;
          }
          if (message.type === 'connect') return start(true);
          if (message.type === 'refresh') return start();
          if (message.type === 'savePlan') {
            const endpoint = session.map.endpoints.find(e => e.id === message.endpoint);
            if (endpoint && Object.hasOwn(CHECKLISTS, message.checklist)) return save(buildTestPlan(endpoint, message.checklist), 'Save built-in manual test plan', 'burpnexus-test-plan.json');
            return;
          }
          if (message.type === 'preview' || message.type === 'addSource') {
            const endpoint = session.map.endpoints.find(e => e.id === message.endpoint);
            if (!endpoint || !Object.hasOwn(CHECKLISTS, message.checklist) || typeof message.question !== 'string' || message.question.length > 8000) return;
            const extras = additional.get(endpoint.id) || [];
            if (message.type === 'addSource') {
              if (extras.length >= 5) throw new Error('Five additional excerpts are already attached. Refresh the map to reset them.');
              busy = true; post({ type: 'busy', value: true });
              try {
                const choice = await vscode.window.showQuickPick([...session.source.files.keys()].map(file => ({ label: file, file })), { title: 'Add missing authorization policy, middleware or service context from indexed source' });
                if (!choice || disposed) return;
                const value = await vscode.window.showInputBox({ title: 'Starting evidence line', value: '1', prompt: 'Choose a line near the relevant policy or function. A bounded excerpt around it will appear in the preview.', validateInput: input => /^\d+$/.test(input) && Number(input) >= 1 && Number(input) <= session.source.files.get(choice.file).lines.length ? undefined : 'Enter an existing positive line number.' });
                if (!value || disposed) return;
                const line = Number(value);
                if (!Number.isInteger(line) || line < 1 || line > session.source.files.get(choice.file).lines.length) return;
                extras.push({ file: choice.file, line }); additional.set(endpoint.id, extras);
              } finally { busy = false; post({ type: 'busy', value: false }); }
            }
            preview = buildReview(endpoint, session.source, message.checklist, message.question, extras); report = undefined;
            return post({ type: 'preview', text: preview.text, hash: preview.hash, evidence: preview.evidence.map(e => ({ id: e.id, file: e.file, line: e.line || 1, kind: e.kind })) });
          }
          if (message.type === 'open') {
            const evidence = preview?.evidence.find(e => e.id === message.id);
            const route = session.source.routes.find(r => r.id === message.id);
            const target = evidence || route; if (!target) return;
            const root = evidence?.kind === 'traffic' ? session.traffic.root : session.source.root;
            const file = path.resolve(root, target.file);
            if (!inside(root, await fs.realpath(file)) || (await fs.lstat(file)).isSymbolicLink()) throw new Error('Evidence path leaves the selected repository.');
            const document = await vscode.workspace.openTextDocument(vscode.Uri.file(file));
            const line = Math.min(Math.max(0, (target.line || 1) - 1), Math.max(0, document.lineCount - 1));
            return vscode.window.showTextDocument(document, { selection: new vscode.Range(line, 0, line, 0), preview: true });
          }
          if (message.type === 'saveMap') return save({ format: 'burpnexus-source-map-v1', created: new Date().toISOString(), counts: session.map.counts, captures: { included: session.traffic.included, total: session.traffic.total }, warnings: [...session.traffic.warnings, ...session.source.warnings], endpoints: session.map.endpoints.map(({ samples, ...e }) => ({ ...e, samples: samples.map(s => ({ id: s.id, file: s.file, hash: s.hash })) })), unobserved: session.map.unobserved }, 'Save traffic/source map', 'burpnexus-source-map.json');
          if (message.type === 'saveReport') { if (report) return save(report, 'Save cited security review', 'burpnexus-review.json'); return; }
          if (message.type === 'savePack') {
            if (preview && message.hash === preview.hash) return save('# BurpNexus review pack\n\nContext SHA-256: ' + preview.hash + '\nCreated: ' + preview.created + '\n\n' + preview.text + '\n', 'Save exact preview for another assistant', 'burpnexus-review-pack.md', true);
            return;
          }
          if (message.type !== 'ask' || !preview || message.hash !== preview.hash) return;
          const sending = preview; busy = true; post({ type: 'busy', value: true }); report = undefined;
          const cancel = new vscode.CancellationTokenSource(); cancellation = cancel;
          const timer = setTimeout(() => cancel.cancel(), 120000);
          try {
            await checkSnapshot(sending, session);
            const models = await abortable(vscode.lm.selectChatModels({}), cancel.token);
            if (!models.length) throw new Error('No VS Code models available. Enable a language model provider, or save the review pack for your assistant.');
            const selected = await abortable(vscode.window.showQuickPick(models.map(model => ({ label: model.name, description: model.vendor + ' / ' + model.id, model })), { title: 'Send the previewed traffic AND source excerpts to this model' }), cancel.token);
            if (!selected || disposed) return;
            const prompt = vscode.LanguageModelChatMessage.User(sending.text);
            const count = await abortable(selected.model.countTokens(prompt, cancel.token), cancel.token);
            if (!Number.isFinite(selected.model.maxInputTokens) || count > selected.model.maxInputTokens - 2000) throw new Error('Preview exceeds this model’s input budget. Choose a model with a larger context window.');
            const response = await abortable(selected.model.sendRequest([prompt], {}, cancel.token), cancel.token);
            const iterator = response.text[Symbol.asyncIterator](); let answer = '', last = 0;
            while (true) {
              const part = await abortable(iterator.next(), cancel.token); if (part.done) break;
              answer += part.value;
              if (answer.length > 160000) { cancel.cancel(); throw new Error('Model response exceeds the review limit.'); }
              if (Date.now() - last > 150) { post({ type: 'draft', text: answer }); last = Date.now(); }
            }
            report = { ...parseReview(answer, sending), model: { id: selected.model.id, vendor: selected.model.vendor }, limitations: [...session.traffic.warnings, ...session.source.warnings] };
            post({ type: 'report', report });
          } catch (e) { post({ type: 'error', text: e.message || 'AI analysis failed.' }); }
          finally { clearTimeout(timer); cancel.dispose(); cancellation = undefined; busy = false; post({ type: 'busy', value: false }); }
        } catch (e) { post({ type: 'error', text: e.message || 'BurpNexus operation failed.' }); }
      });
    } catch (e) { vscode.window.showErrorMessage('BurpNexus: ' + e.message + ' Use Connect Export to Source Repository to change folders.'); }
  }
  for (const [name, action] of [['burpnexus.connect', () => start(true)], ['burpnexus.openAnalysis', () => start()], ['burpnexus.mapTraffic', () => start()]]) context.subscriptions.push(vscode.commands.registerCommand(name, action));
  context.subscriptions.push(vscode.commands.registerCommand('burpnexus.importXml', async () => {
    if (!trusted()) return;
    const files = await vscode.window.showOpenDialog({ canSelectMany: true, filters: { 'Burp XML': ['xml'] } }); if (!files?.length) return;
    const destination = await chooseFolder('Choose parent for a new export'); if (!destination) return;
    const output = path.join(destination, 'burpnexus-' + Date.now()), python = config().get('pythonPath', 'python');
    await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Importing Burp XML', cancellable: true }, (_, token) => new Promise(resolve => {
      const child = spawn(python, ['-m', 'burpmd', ...files.map(f => f.fsPath), '-o', output, '--sitemap', '--full-analysis', '--redact-secrets', '--vscode'], { shell: false, windowsHide: true });
      let error = '', completed = false;
      const cancel = token.onCancellationRequested(() => child.kill()); if (token.isCancellationRequested) child.kill();
      const finish = async err => {
        if (completed) return; completed = true; cancel.dispose();
        try {
          if (err) vscode.window.showErrorMessage(err);
          else if (!token.isCancellationRequested) {
            const source = context.workspaceState.get('connection')?.source || await chooseFolder('Select target application source repository', vscode.workspace.workspaceFolders?.[0]?.uri.fsPath);
            if (source) { await context.workspaceState.update('connection', { corpus: output, source }); await start(); }
          }
        } catch (e) { vscode.window.showErrorMessage('Import connection failed: ' + e.message); }
        finally { resolve(); }
      };
      child.stderr.on('data', chunk => { error = (error + chunk.toString()).slice(-4000); }); child.stdout.resume();
      child.on('error', () => finish('Could not run Python. Set burpnexus.pythonPath and install burpmd-parser.'));
      child.on('close', code => finish(code === 0 || token.isCancellationRequested ? null : 'Import failed: ' + error));
    }));
  }));
}
module.exports = { activate, html, abortable, checkSnapshot };
