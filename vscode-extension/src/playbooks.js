'use strict';

// Bundled, versioned guidance. These records describe tests; they never execute them.
const { getBountySkill } = require('./public-bounty');
const VERSION = '1.1.0';
const CHECKS = {
  'AUTHZ-01': {
    title: 'Object ownership and tenant isolation',
    evidence: ['Intended owner/tenant policy and two controlled principals', 'Matched handler, global authorization policy and service/query scoping', 'Requests and responses for an owned object and a permitted cross-principal comparison'],
    inspect: ['Trace route/body/query identifiers to object retrieval.', 'Check tenant and owner predicates at the service/data boundary.', 'Check whether middleware already enforces the policy before inferring a missing check.'],
    steps: ['Record a legitimate read or update of an object owned by account A.', 'Using controlled account B, repeat the same operation against that object and against an object B owns.', 'Where the environment provides separate test tenants, repeat across those tenants and compare response content and actual side effects.'],
    expected: 'Access follows the documented object and tenant policy; denied operations disclose no protected object data and cause no unauthorized side effects.',
    regression: 'Add positive owner access and negative cross-owner/cross-tenant cases at the service and HTTP boundaries.',
    caution: 'An identifier in a URL, a 200 response or findById in an excerpt does not establish BOLA. Public/shared objects may be intentional.'
  },
  'AUTHZ-02': {
    title: 'Function, role and property authorization',
    evidence: ['A role/action matrix and representative low/high privilege accounts', 'Route decorators, middleware, serializer/binder and service policy', 'Baseline requests showing the intended operation and accepted fields'],
    inspect: ['Check authorization for each HTTP method and privileged action.', 'Inspect server-controlled fields such as owner, tenant, role, status and approval state.', 'Check whether input binding uses allowlists and whether alternate entry points share the policy.'],
    steps: ['Replay a privileged operation with a controlled lower-privilege account and with no authentication where in scope.', 'Change one security-sensitive property on a disposable test object while preserving a legitimate baseline.', 'Verify the resulting stored object and audit record, not only the response status.'],
    expected: 'Only permitted roles/actions and writable properties take effect; server-controlled ownership, role and state remain protected.',
    regression: 'Cover denied roles, alternate methods and prohibited fields alongside permitted operations.',
    caution: 'A hidden UI button is not an authorization boundary. A reflected field is not proof that the field was persisted.'
  },
  'INPUT-01': {
    title: 'Input to query, template or process boundary',
    evidence: ['The exact input field and its decoding/normalization path', 'Handler/service and the actual query, renderer or process API', 'A benign baseline and a controlled comparison with observable results'],
    inspect: ['Distinguish parameterized APIs from string construction.', 'Check escaping/validation at the context where data is used.', 'Verify that the input can reach the suspected sink; same-name declarations are not proof of data flow.'],
    steps: ['Use a disposable test record and change one input at a time using benign markers and type/boundary cases.', 'Observe validation, stored values and safe application logs to establish which processing path ran.', 'Design any further validation specifically for the identified API and authorized test environment; do not infer execution from reflection or a generic error.'],
    expected: 'Untrusted values remain data in the query, template or process API; validation failures do not alter command/query structure or disclose sensitive errors.',
    regression: 'Add parameterization/escaping tests and regression cases for the demonstrated input-to-sink path.',
    caution: 'A concatenation or error pattern is a candidate, not proof of an exploitable injection.'
  },
  'INPUT-02': {
    title: 'Outbound requests and redirect boundaries',
    evidence: ['User-controlled URL or host input', 'URL parsing, resolution, allowlist, redirect handling and outbound client code', 'A tester-controlled destination and permitted observation method'],
    inspect: ['Check scheme/host/port validation and where canonicalization occurs.', 'Check validation after redirects and the application’s network restrictions.', 'Distinguish a browser redirect from a server-side fetch.'],
    steps: ['Start with an explicitly permitted tester-controlled destination.', 'Vary URL representation and redirect behavior within the authorized environment and record the destination actually contacted.', 'Confirm whether protected internal destinations are denied using the organization’s approved lab fixtures.'],
    expected: 'Only approved destinations are reachable under the intended URL and redirect policy; untrusted destinations receive no application credentials.',
    regression: 'Test allowed destinations and denied URL/redirect variants against a local controlled server.',
    caution: 'Do not probe cloud metadata or unrelated internal hosts merely because a URL parameter exists. An outbound URL in source does not prove user control.'
  },
  'INPUT-03': {
    title: 'File paths, uploads and deserialization',
    evidence: ['File/object identifier, upload metadata or serialized input', 'Canonical path checks, storage policy, content handling and deserializer configuration', 'Disposable files/objects and an agreed test directory'],
    inspect: ['Check path containment after normalization and link resolution.', 'Inspect file-type/size enforcement, public serving context and executable-content handling.', 'Check deserializer type restrictions and whether untrusted metadata chooses classes or behavior.'],
    steps: ['Use harmless sample files and disposable storage entries to compare allowed and disallowed names, types and sizes.', 'Check that reads/writes remain within the authorized storage boundary and are scoped to the caller.', 'Verify stored content handling and rejection behavior without executing uploaded code or destructive payloads.'],
    expected: 'Files stay within the intended storage and ownership boundaries; prohibited content/types and unsafe deserialization behavior are rejected.',
    regression: 'Cover containment, link handling, ownership, type/size limits and safe parser configuration.',
    caution: 'An unusual filename or upload acceptance alone does not demonstrate traversal or code execution.'
  },
  'SESSION-01': {
    title: 'Authentication and session/token lifecycle',
    evidence: ['Authentication flow, intended token/session lifetime and controlled test accounts', 'Server-side validation, logout/revocation and authorization policy', 'Before/after captures for the relevant lifecycle events'],
    inspect: ['Check signature validation, issuer/audience/expiry and trusted algorithm configuration where tokens are used.', 'Inspect session renewal, logout, credential-change invalidation and authentication failure behavior.', 'Separate observed token fields and cookie attributes from server acceptance policy.'],
    steps: ['Establish a controlled session and capture a protected operation.', 'Repeat after the relevant logout, expiry or revocation event in the test environment.', 'Compare anonymous, valid and invalid/expired sessions without guessing other users’ credentials.'],
    expected: 'The server accepts only valid sessions/tokens according to the documented lifetime and revocation policy.',
    regression: 'Test invalid signatures/claims and the application’s required expiry, rotation and revocation events.',
    caution: 'Decoding a JWT or observing its algorithm is not proof of server-side acceptance, a weak key or an authentication bypass.'
  },
  'SESSION-02': {
    title: 'Browser trust, CSRF, CORS and cookie behavior',
    evidence: ['Credential transport and browser origin model', 'CSRF/origin/CORS policy and cookie configuration', 'A state-changing operation and captures or browser observations from controlled origins'],
    inspect: ['Determine whether browsers automatically attach credentials to the operation.', 'Check CSRF/origin validation, allowed origins and credentialed cross-origin responses.', 'Interpret Secure, HttpOnly and SameSite in the actual deployment context.'],
    steps: ['Using a controlled test account and harmless state change, compare the legitimate flow with missing/invalid anti-CSRF context.', 'Check the intended same-origin and permitted cross-origin flows in a browser.', 'Confirm that disallowed origins cannot read protected responses or trigger an unintended authenticated operation.'],
    expected: 'Browser credential and origin policies prevent unintended authenticated actions and disclosure while preserving intended integrations.',
    regression: 'Add allowed/denied origin and CSRF cases plus deployment-specific cookie assertions.',
    caution: 'A missing header or cookie attribute by itself does not establish exploitable CSRF or cross-origin data access.'
  },
  'LOGIC-01': {
    title: 'State transitions and server-controlled values',
    evidence: ['Documented business rules, states and allowed actors', 'Handler/service state checks and transaction boundary', 'An ordinary multi-step flow with disposable test data'],
    inspect: ['Check whether state and ownership are revalidated at each transition.', 'Identify prices, quantities, discounts, approvals or limits that must be computed by the server.', 'Check alternate paths that can skip or reorder required steps.'],
    steps: ['Record the legitimate flow and its resulting state.', 'With disposable objects, repeat a transition out of order or with one prohibited server-controlled value.', 'Verify durable state, accounting/audit records and rollback behavior.'],
    expected: 'Only permitted state transitions and server-derived values are committed; invalid sequences preserve consistency.',
    regression: 'Test the allowed state graph and rejected transitions at the transactional service boundary.',
    caution: 'Endpoint ordering inferred from traffic is not a business specification. The analyst must supply intended rules.'
  },
  'LOGIC-02': {
    title: 'Replay, idempotency and concurrency',
    evidence: ['Operations that must occur once and their idempotency contract', 'Uniqueness constraints, locks/transactions and retry handling', 'A safe disposable operation and permitted test limits'],
    inspect: ['Check whether deduplication covers the entire effect and the relevant actor/object scope.', 'Identify check-then-act windows and transaction boundaries.', 'Review retry behavior after failures or interrupted responses.'],
    steps: ['Repeat a harmless operation using the same intended idempotency context and inspect its durable effects.', 'Repeat after a controlled retry/failure condition in a test environment.', 'Only where explicitly in scope, run a small bounded concurrent comparison against disposable data and count completed effects.'],
    expected: 'Retries and concurrent requests preserve the documented uniqueness and consistency guarantees.',
    regression: 'Add transactional uniqueness and bounded concurrency tests for the demonstrated operation.',
    caution: 'Duplicate status codes or a missing lock in an excerpt do not establish a race. Database constraints may enforce the invariant.'
  },
  'DATA-01': {
    title: 'Sensitive output, errors and exposure',
    evidence: ['The caller’s permitted data view and classification policy', 'Serializer/projection, error handling and relevant cache/log behavior', 'Successful and failing response samples for controlled records'],
    inspect: ['Check field-level exposure and whether server-only values enter responses.', 'Inspect exception handling, debug output and caching of personalized data.', 'Review how response values are consumed before asserting script execution or other downstream effects.'],
    steps: ['Compare output fields for the intended roles using controlled records.', 'Trigger a benign validation failure and inspect the response and permitted logs.', 'Check intended cache behavior for user-specific responses.'],
    expected: 'Responses and failures reveal only the data permitted for the caller and deployment mode; personalized data is not shared across users.',
    regression: 'Assert allowed output fields, generic external errors and user-specific cache behavior.',
    caution: 'A field name, reflected marker or stack-like text may be intentional or non-sensitive; classification and execution context matter.'
  }
};
const PROFILES = {
  comprehensive: { title: 'Comprehensive application security review', focus: 'Prioritize authorization and tenant isolation, then input boundaries, sessions, data exposure and business invariants.', checks: Object.keys(CHECKS) },
  authorization: { title: 'Authorization and tenant isolation', focus: 'Review authentication prerequisites, object/function/property authorization and tenant policy.', checks: ['AUTHZ-01','AUTHZ-02','DATA-01'] },
  injection: { title: 'Input and execution boundaries', focus: 'Trace controllable input toward queries, renderers, outbound clients, storage and parser boundaries.', checks: ['INPUT-01','INPUT-02','INPUT-03'] },
  session: { title: 'Authentication and browser trust', focus: 'Review session/token acceptance and lifecycle, browser credentials, CSRF and CORS in the deployment context.', checks: ['SESSION-01','SESSION-02'] },
  logic: { title: 'Business logic and consistency', focus: 'Review documented business invariants, state transitions, replay and concurrency.', checks: ['LOGIC-01','LOGIC-02'] },
  bounty: { title: 'Public bug bounty lessons', focus: 'Apply relevant historical disclosure lessons to the supplied application evidence. Establish prerequisites and disconfirming controls before proposing validation.', checks: [] }
};
const CHECKLISTS = Object.fromEntries(Object.entries(PROFILES).map(([id,p]) => [id,p.focus]));
function getPlaybook(id) {
  if (!Object.hasOwn(PROFILES,id)) throw new Error('Unknown built-in review playbook.');
  const profile=PROFILES[id];
  if (id === 'bounty') return { id, version: VERSION, title: profile.title, focus: profile.focus, execution: 'guidance-only', ...getBountySkill() };
  return { id, version: VERSION, title: profile.title, focus: profile.focus, execution: 'guidance-only', checks: profile.checks.map(checkId => ({ id:checkId, ...structuredClone(CHECKS[checkId]) })) };
}
function allPlaybooks() { return Object.fromEntries(Object.keys(PROFILES).map(id => [id,getPlaybook(id)])); }
function buildTestPlan(endpoint, profile) {
  const playbook=getPlaybook(profile);
  return { format:'burpnexus-manual-test-plan-v1', created:new Date().toISOString(), endpoint:{id:endpoint.id,description:endpoint.display,mapping:endpoint.state}, playbook:{id:profile,version:VERSION,title:playbook.title}, ...(playbook.skill ? { skill:playbook.skill, backgroundReferences:playbook.references } : {}), execution:'manual; no tests have been run by this extension', prerequisite:'Use authorized targets, controlled accounts and disposable data. Supply the application’s intended roles and business rules.', checks:playbook.checks.map(check=>({...check,status:'not-run',observedResult:'',evidenceReferences:[]})) };
}
module.exports={VERSION,CHECKS,PROFILES,CHECKLISTS,getPlaybook,allPlaybooks,buildTestPlan};
