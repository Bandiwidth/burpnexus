'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
function load(vscode) {
  const original=Module._load; delete require.cache[require.resolve('../src/extension')];
  Module._load=function(name,...args){return name==='vscode'?vscode:original.call(this,name,...args);};
  try{return require('../src/extension');}finally{Module._load=original;}
}
class Cancellation {
  constructor(){this.callbacks=new Set();const self=this;this.token={isCancellationRequested:false,onCancellationRequested(fn){self.callbacks.add(fn);return{dispose(){self.callbacks.delete(fn);}};}};}
  cancel(){this.token.isCancellationRequested=true;for(const fn of this.callbacks)fn();}
  dispose(){this.callbacks.clear();}
}
test('all entry points enforce workspace trust; webview has strict CSP and safe rendering',async()=>{
  const commands=new Map(),errors=[];
  const extension=load({workspace:{isTrusted:false},window:{showErrorMessage:message=>errors.push(message)},commands:{registerCommand:(name,callback)=>{commands.set(name,callback);return{dispose(){}};}}});
  extension.activate({subscriptions:[]});assert.equal(commands.size,4);
  for(const fn of commands.values())await fn();assert.equal(errors.length,4);
  const html=extension.html('test-nonce');assert.ok(html.includes("default-src 'none'"));assert.ok(html.includes("script-src 'nonce-test-nonce'"));assert.ok(!html.includes('innerHTML'));assert.ok(html.includes('textContent'));
  new vm.Script(html.match(/<script nonce="test-nonce">([\s\S]*?)<\/script>/)[1]);
});

for(const scenario of ['stream','bounty-stream','manual-context','no-model','token-limit','cancel-selection','invalid-citation','stale-source','cancel-hung-provider','cancel-disposed-panel']) {
  test('review lifecycle: '+scenario,async t=>{
    const root=await fs.mkdtemp(path.join(os.tmpdir(),'nexus-host-mock-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
    const corpus=path.join(root,'corpus'),source=path.join(root,'source');await fs.mkdir(corpus);await fs.mkdir(source);
    await fs.writeFile(path.join(source,'policy.js'),'function enforceOwner(user, object) { return user.id === object.owner; }');
    const app=path.join(source,'app.js');await fs.writeFile(app,"const app = express();\napp.get('/users/:id', user);\nfunction user(req) { return db.get(req.params.id); }");
    await fs.writeFile(path.join(corpus,'attack-surface-index.json'),JSON.stringify({summary:{total_items:1}}));
    await fs.writeFile(path.join(corpus,'1_GET_user.json'),JSON.stringify({metadata:{method:'GET',url:'https://app.test/users/1',status:200},request:{body:'',headers:{Authorization:'Bearer topsecret'}},response:{body:'{"id":1}'}}));
    const commands=new Map(),messages=[],errors=[],external=[];let receive,disposePanel,sent=0,opened=0;const state=new Map([['connection',{corpus,source}]]);
    const profile=scenario==='bounty-stream'?'bounty':'authorization';
    const model={name:'Test',vendor:'test',id:'fixture',maxInputTokens:32000,countTokens:async()=>scenario==='token-limit'?40000:100,
      sendRequest:async prompts=>{sent++;const content=prompts[0].content;assert.ok(content.includes('UNTRUSTED EVIDENCE'));assert.ok(content.includes('app.js'));assert.ok(!content.includes('topsecret'));
        if(profile==='bounty'){assert.ok(content.includes('H1-582349'));assert.ok(content.includes('BOUNTY-08'));assert.ok(content.includes('historical report'))};
        if(scenario==='cancel-hung-provider'||scenario==='cancel-disposed-panel')return new Promise(()=>{});
        const traffic=content.match(/"id":"(T[a-f\d]+)"/)[1],src=content.match(/"id":"(S[a-f\d]+)"/)[1];
        const response=JSON.stringify({summary:'Ownership policy needs validation.',findings:[{title:'Ownership check',severity:'medium',confidence:'low',evidenceIds:scenario==='invalid-citation'?['invented']:[traffic,src],reasoning:'Route reads a user object.',missingEvidence:['Central authorization policy'],validation:['Compare two controlled accounts.'],remediation:'Enforce owner policy.',regressionTest:'Assert denial across accounts.'}],gaps:['Only one capture.']});
        return{text:(async function*(){yield response.slice(0,50);yield response.slice(50);})()};}};
    const panel={webview:{postMessage:m=>messages.push(m),onDidReceiveMessage:fn=>{receive=fn;}},onDidDispose:fn=>{disposePanel=fn;},dispose(){disposePanel?.();}};
    const vscode={workspace:{isTrusted:true,getConfiguration:()=>({get:(_,fallback)=>fallback}),openTextDocument:async()=>{opened++;return{lineCount:3};}},
      window:{showErrorMessage:m=>errors.push(m),withProgress:(_,fn)=>fn({},new Cancellation().token),createWebviewPanel:()=>panel,showQuickPick:async choices=>scenario==='cancel-selection'?undefined:(choices.find(c=>c.file==='policy.js')||choices[0]),showInputBox:async()=> '1',showTextDocument:async()=>{},showSaveDialog:async()=>({fsPath:path.join(root,'plan.json')})},
      commands:{registerCommand:(name,fn)=>{commands.set(name,fn);return{dispose(){}};}},ViewColumn:{One:1},ProgressLocation:{Notification:1},Range:class{},Uri:{file:fsPath=>({fsPath}),parse:value=>value},env:{openExternal:async uri=>external.push(uri)},CancellationTokenSource:Cancellation,
      lm:{selectChatModels:async()=>scenario==='no-model'?[]:[model]},LanguageModelChatMessage:{User:content=>({content})}};
    const extension=load(vscode);extension.activate({subscriptions:[],workspaceState:{get:k=>state.get(k),update:async(k,v)=>state.set(k,v)}});
    await commands.get('burpnexus.openAnalysis')();assert.deepEqual(errors,[]);await receive({type:'ready'});
    assert.equal(messages.find(m=>m.type==='state').counts.candidate,1);
    await receive({type:'savePlan',endpoint:'E1',checklist:profile});
    const plan=JSON.parse(await fs.readFile(path.join(root,'plan.json'),'utf8'));assert.equal(plan.checks.length,profile==='bounty'?8:3);assert.equal(sent,0);assert.ok(plan.checks.every(c=>c.status==='not-run'));
    if(profile==='bounty'){
      assert.equal(plan.backgroundReferences.length,8);
      for(const id of ['constructor','javascript:alert(1)','https://evil.test'])await receive({type:'openReference',id});
      assert.equal(external.length,0);
      await receive({type:'openReference',id:'H1-582349',url:'https://evil.test'});
      assert.deepEqual(external,['https://gitlab.com/gitlab-org/gitlab-foss/-/issues/62073']);
    }
    await receive({type:'ask',hash:'forged'});assert.equal(sent,0);
    await receive({type:'open',id:'../../secret'});assert.equal(opened,0);
    await receive({type:'preview',endpoint:'E1',checklist:profile,question:'Check ownership'});
    if(scenario==='manual-context')await receive({type:'addSource',endpoint:'E1',checklist:'authorization',question:'Check ownership'});
    const preview=messages.filter(m=>m.type==='preview').at(-1);assert.ok(preview);await receive({type:'open',id:preview.evidence.find(e=>e.kind==='route').id});assert.equal(opened,1);
    if(profile==='bounty'){
      await receive({type:'savePack',hash:preview.hash});
      const pack=await fs.readFile(path.join(root,'plan.json'),'utf8');
      assert.ok(pack.includes(preview.text));assert.ok(pack.includes('H1-582349'));assert.equal(sent,0);
    }
    if(scenario==='stale-source')await fs.appendFile(app,'\n// changed');
    const pending=receive({type:'ask',hash:preview.hash});
    if(scenario.startsWith('cancel-')&&scenario!=='cancel-selection') {await new Promise(resolve=>setTimeout(resolve,30));if(scenario==='cancel-disposed-panel')disposePanel();else await receive({type:'cancel'});}
    await pending;
    if(scenario!=='cancel-disposed-panel')assert.deepEqual(messages.filter(m=>m.type==='busy').map(m=>m.value).slice(-2),[true,false]);
    if(['stream','bounty-stream','manual-context'].includes(scenario)){assert.equal(sent,1);const report=messages.find(m=>m.type==='report').report;assert.equal(report.findings[0].status,'needs-validation');assert.equal(report.contextHash,preview.hash);if(scenario==='manual-context')assert.ok(report.evidence.some(e=>e.kind==='analyst-selected'));if(profile==='bounty')assert.equal(report.scope.backgroundSkill.references.length,8);}
    else{assert.ok(!messages.some(m=>m.type==='report'));if(!['cancel-selection','cancel-disposed-panel'].includes(scenario))assert.ok(messages.some(m=>m.type==='error'));}
    if(['no-model','token-limit','cancel-selection','stale-source'].includes(scenario))assert.equal(sent,0);
  });
}
