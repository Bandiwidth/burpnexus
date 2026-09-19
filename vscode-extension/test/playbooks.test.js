'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {CHECKS,PROFILES,VERSION,getPlaybook,buildTestPlan}=require('../src/playbooks');
const {buildReview}=require('../src/review');
const endpoint={id:'E1',display:'POST https://app.test/orders',state:'unmapped',count:1,variants:1,matches:[],samples:[]};
test('bundled playbooks supply actionable evidence, inspections, tests and expected results',()=>{
  assert.equal(Object.keys(PROFILES).length,6);assert.equal(Object.keys(CHECKS).length,10);
  for(const id of Object.keys(PROFILES)) {
    const pack=getPlaybook(id);assert.equal(pack.version,VERSION);assert.equal(pack.execution,'guidance-only');
    assert.equal(new Set(pack.checks.map(c=>c.id)).size,pack.checks.length);
    for(const c of pack.checks){for(const k of ['evidence','inspect','steps'])assert.ok(Array.isArray(c[k])&&c[k].length>=3);for(const k of ['title','expected','regression','caution'])assert.ok(c[k].length>15);}
  }
});
test('manual test plans never assert execution or inherit edits from another plan',()=>{
  const plan=buildTestPlan(endpoint,'authorization');assert.equal(plan.endpoint.id,'E1');assert.ok(plan.execution.includes('no tests have been run'));
  assert.ok(plan.checks.every(c=>c.status==='not-run'&&c.observedResult===''&&c.evidenceReferences.length===0));
  plan.checks[0].steps.push('local note');assert.ok(!getPlaybook('authorization').checks[0].steps.includes('local note'));
});
test('exact AI preview contains selected built-in guidance and its version without implying results',()=>{
  const review=buildReview(endpoint,{files:new Map()},'session');
  assert.deepEqual(review.scope.playbook.checks,['SESSION-01','SESSION-02']);assert.equal(review.scope.playbook.version,VERSION);
  assert.ok(review.text.includes('guidance, not test results'));assert.ok(review.text.includes('Mark missing prerequisites as gaps'));assert.ok(review.text.includes('CSRF'));
  assert.ok(!review.text.includes('INPUT-03'));
});
test('unknown and prototype-derived playbooks fail closed',()=>{
  for(const id of ['missing','constructor','__proto__']){assert.throws(()=>getPlaybook(id),/Unknown/);assert.throws(()=>buildReview(endpoint,{files:new Map()},id),/Unknown/);}
});
