'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { getBountySkill, getPublicReference } = require('../src/public-bounty');
const { getPlaybook, buildTestPlan } = require('../src/playbooks');
const { buildReview, parseReview } = require('../src/review');
const endpoint = { id:'E1', display:'GET https://app.test/status', state:'unmapped', count:1, variants:1, matches:[], samples:[{id:'T1',kind:'traffic',file:'request.json',line:1,body:'{"ok":true}'}] };

test('every historical lesson resolves to attributed HTTPS provenance and supplies validation prerequisites', () => {
  const skill = getBountySkill();
  assert.equal(skill.checks.length,8); assert.equal(skill.references.length,8);
  assert.equal(new Set(skill.checks.map(c=>c.id)).size,8);
  const used = new Set();
  for(const check of skill.checks) {
    assert.ok(check.applicability && check.sourceIds.length);
    for(const id of check.sourceIds) {
      used.add(id); const source = getPublicReference(id);
      assert.ok(source && source.author && source.observation);
      assert.equal(new URL(source.url).protocol,'https:');
      if(id.startsWith('H1-')) assert.equal(source.reportUrl,'https://hackerone.com/reports/'+id.slice(3));
    }
  }
  assert.equal(used.size,skill.references.length);
  assert.ok(skill.skill.instructions.includes('references/catalog.json'));
});

test('only packaged reference IDs can resolve; workspace URLs and prototype keys cannot', () => {
  for(const id of ['constructor','__proto__','toString','https://evil.test','javascript:alert(1)','file:///secret',null,{},1]) assert.equal(getPublicReference(id),undefined);
  const reference=getPublicReference('H1-582349');reference.url='https://evil.test';
  assert.equal(new URL(getPublicReference('H1-582349').url).hostname,'gitlab.com');
});

test('offline plan round-trip retains sources and instructions while every procedure remains unexecuted', () => {
  const plan=JSON.parse(JSON.stringify(buildTestPlan(endpoint,'bounty')));
  assert.equal(plan.skill.version,'1.0.0'); assert.equal(plan.backgroundReferences.length,8);
  assert.ok(plan.checks.every(c=>c.status==='not-run' && c.observedResult==='' && c.evidenceReferences.length===0));
  plan.checks[0].steps.push('changed'); plan.backgroundReferences[0].observation='changed'; plan.skill.instructions='changed';
  const fresh=getPlaybook('bounty'); assert.ok(!fresh.checks[0].steps.includes('changed'));
  assert.notEqual(fresh.references[0].observation,'changed'); assert.notEqual(fresh.skill.instructions,'changed');
});

test('preview includes the packaged skill and provenance without treating history as target evidence', () => {
  const context=buildReview(endpoint,{files:new Map()},'bounty','Review this status endpoint.');
  const skill=getBountySkill();
  assert.ok(context.text.includes(JSON.stringify(skill.skill.instructions)));
  assert.deepEqual(context.evidence.map(e=>e.id),['T1']);
  assert.equal(context.scope.backgroundSkill.references.length,8);
  assert.equal(context.scope.playbook.checks.length,8);
  const report={summary:'Policy is unknown.',findings:[],gaps:['Need intended visibility and authorization source.']};
  const accepted=parseReview(JSON.stringify(report),context);
  assert.equal(accepted.findings.length,0); assert.equal(accepted.scope.backgroundSkill.version,'1.0.0');
  assert.equal(accepted.scope.backgroundSkill.references[0].id,'H1-582349');
  const general=buildReview(endpoint,{files:new Map()},'authorization');
  assert.equal(general.scope.backgroundSkill,undefined); assert.ok(!general.text.includes('H1-582349'));
});

test('historical references cannot be laundered into findings even alongside a valid traffic citation', () => {
  const context=buildReview(endpoint,{files:new Map()},'bounty');
  const finding={title:'Visibility hypothesis',severity:'low',confidence:'low',evidenceIds:['T1','H1-582349'],reasoning:'Requires policy evidence.',missingEvidence:['Visibility policy'],validation:['Compare permitted and denied users.'],remediation:'Apply the intended policy.',regressionTest:'Cover denied sibling access.'};
  assert.throws(()=>parseReview(JSON.stringify({summary:'Review',findings:[finding],gaps:[]}),context),/outside the preview/);
  finding.evidenceIds=['T1'];
  assert.equal(parseReview(JSON.stringify({summary:'Review',findings:[finding],gaps:[]}),context).findings[0].status,'needs-validation');
});
