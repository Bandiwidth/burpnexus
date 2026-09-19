'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { extractRoutes, indexSource, hash, lex } = require('../src/source');
const { matchRoute, mapTraffic, loadTraffic } = require('../src/mapping');
const { buildReview, parseReview, redactSource } = require('../src/review');
function source(entries) { return new Map(Object.entries(entries).map(([f,text]) => [f,{ text, lines: text.split('\n'), hash: hash(text) }])); }
async function temp(t) { const root = await fs.mkdtemp(path.join(os.tmpdir(),'nexus-source-')); t.after(() => fs.rm(root,{recursive:true,force:true})); return root; }

test('Express resolves imported router, nested mounts, parameters and middleware evidence', () => {
  const files = source({ 'app.js': `import express from 'express';\nimport users from './users';\nconst app = express();\napp.use('/api', requireAuth, users);\napp.get('/health', health);`, 'users.js': `const router = express.Router();\nrouter.get('/users/:id', authorize, getUser);\nexport default router;` });
  // Multiple middleware arguments before the router are supported.
  const result = extractRoutes(files);
  assert.ok(result.routes.some(r => r.path === '/api/users/:id' && r.mounts[0].file === 'app.js'));
  assert.ok(result.routes.some(r => r.path === '/health' && r.method === 'GET'));
});
test('no fake declarations from comments or string bodies; methods stay distinct', () => {
  const { routes } = extractRoutes(source({ 'app.js': `const app = express();\n// app.get('/fake', x);\nconst example = "app.get('/quoted', x)";\napp.post('/real', x);\napp.get(dynamic, x);` }));
  assert.deepEqual(routes.map(r => [r.method,r.path]), [['POST','/real']]);
});
test('unmounted or dynamically prefixed routers are not silently mapped to root', () => {
  const { routes, warnings } = extractRoutes(source({ 'a.py': `router = APIRouter(prefix=PREFIX)\n@router.get('/users')\ndef users(): pass` }));
  assert.equal(routes.length,0); assert.equal(warnings.length,1);
});
test('FastAPI cross-file include prefix composes with APIRouter prefix', () => {
  const parsed = extractRoutes(source({ 'app/main.py': `from .users import router as users\napp = FastAPI()\napp.include_router(users, prefix='/api')`, 'app/users.py': `router = APIRouter(prefix='/users')\n@router.get('/{user_id}')\ndef user(user_id): pass` }));
  assert.deepEqual(parsed.routes.map(r => r.path), ['/api/users/{user_id}']);
});
test('Flask method lists and Blueprint registration override prefixes', () => {
  const parsed = extractRoutes(source({ 'app.py': `app = Flask(__name__)\nbp = Blueprint('users', __name__, url_prefix='/old')\napp.register_blueprint(bp, url_prefix='/new')\n@bp.route('/<int:id>', methods=['GET','POST'])\ndef user(id): pass` }));
  assert.deepEqual(parsed.routes.map(r => r.method+' '+r.path), ['GET /new/<int:id>','POST /new/<int:id>']);
});
test('Spring class/method arrays and multiple controllers retain correct scope', () => {
  const parsed = extractRoutes(source({ 'Api.java': `@RestController\n@RequestMapping("/api")\nclass Api {\n@GetMapping(path={"/users/{id}","/members/{id}"})\npublic User get(long id) { return service.get(id); }\n}\n@RequestMapping("/other")\nclass Other {\n@PostMapping("/orders")\npublic void create() {}\n}` }));
  assert.deepEqual(parsed.routes.map(r => r.method+' '+r.path), ['GET /api/users/{id}','GET /api/members/{id}','POST /other/orders']);
});
test('Next app router respects route groups, parameters and exported methods', () => {
  const parsed = extractRoutes(source({ 'src/app/(store)/api/orders/[id]/route.ts': `export async function GET(request) {}\nexport const DELETE = async (request) => {};`, 'src/app/api/[...path]/route.ts': `export function POST(req) {}` }));
  assert.deepEqual(parsed.routes.map(r => r.method+' '+r.path), ['GET /api/orders/:id','DELETE /api/orders/:id','POST /api/*path']);
});
test('segment matching rejects regex patterns and wrong typed parameters', () => {
  assert.ok(matchRoute('/users/:id','/users/12'));
  assert.equal(matchRoute('/users/:id','/user/12'),null);
  assert.equal(matchRoute('/users/<int:id>','/users/abc'),null);
  assert.equal(matchRoute('/users/:id(.*)','/users/12'),null);
  assert.ok(matchRoute('/files/*path','/files/a/b'));
  assert.equal(matchRoute('/files/*path','/files'),null);
});
test('origin-scoped proxy rewrites, ambiguity and uncovered routes are explicit', () => {
  const routes = [{id:'R1',method:'GET',path:'/users/:id',file:'a.js',line:1},{id:'R2',method:'GET',path:'/users/me',file:'a.js',line:2},{id:'R3',method:'POST',path:'/users',file:'a.js',line:3}];
  const endpoints = [{id:'E1',method:'GET',origin:'https://app.test',path:'/gateway/users/me'}, {id:'E2',method:'GET',origin:'https://other.test',path:'/gateway/users/me'}];
  const result = mapTraffic({endpoints},{routes},[{origin:'https://app.test',from:'/gateway',to:'/'}]);
  assert.equal(result.endpoints[0].state,'ambiguous');assert.equal(result.endpoints[1].state,'unmapped');assert.equal(result.unobserved[0].id,'R3');
  assert.throws(() => mapTraffic({endpoints},{routes},[{origin:'https://app.test/path',from:'/gateway',to:'/'}]));
});
test('source index excludes dependencies, tests, secret files, binary and oversized files', async t => {
  const root = await temp(t);
  for (const f of ['node_modules/a.js','tests/a.js','.env.js','credentials.js','excluded/a.js','src/good.js','src/binary.js','src/huge.js']) {
    await fs.mkdir(path.dirname(path.join(root,f)),{recursive:true}); await fs.writeFile(path.join(root,f), f.includes('binary') ? '\0' : f.includes('huge') ? 'x'.repeat(300001) : `const app = express(); app.get('/ok', handler);`);
  }
  const result = await indexSource(root,{excludes:['excluded']});
  assert.deepEqual([...result.files.keys()],['src/good.js']);assert.ok(result.warnings.length>=2);
  await assert.rejects(indexSource(root,{cancelled:()=>true}),/cancelled/);
});
test('traffic indexing covers more than the old 50-item AI sample and keeps session variants', async t => {
  const root=await temp(t);await fs.writeFile(path.join(root,'attack-surface-index.json'),JSON.stringify({summary:{total_items:65}}));
  for(let i=0;i<65;i++) await fs.writeFile(path.join(root,`${i}_GET_test.json`),JSON.stringify({metadata:{url:'https://app.test/users/'+i,method:'GET',status:200},request:{headers:{Authorization:'Bearer private'},body:'password=secret'},response:{body:'ok'}}));
  const result=await loadTraffic(root);assert.equal(result.included,65);assert.equal(result.endpoints.length,65);assert.ok(!JSON.stringify(result).includes('Bearer private'));assert.ok(!JSON.stringify(result).includes('password=secret'));
  const bounded=await loadTraffic(root,{maxItems:10});assert.equal(bounded.included,10);assert.ok(bounded.warnings.length);
});
test('preview links bounded source/traffic snapshots and rejects hallucinated evidence IDs', () => {
  const files=source({'app.js':`const app = express();\napp.get('/users/:id', getUser);\nfunction getUser(req) { return query(req.params.id); }\nconst API_KEY = "credential_value";`});
  const endpoint={id:'E1',display:'GET https://app.test/users/1',state:'candidate',count:1,variants:1,samples:[{id:'T1',file:'1_GET.json',hash:'abc',data:{}}],matches:extractRoutes(files).routes};
  const preview=buildReview(endpoint,{files},'authorization','Check ownership');
  assert.ok(!preview.text.includes('credential_value'));assert.ok(preview.text.includes('2: app.get'));assert.ok(preview.text.includes('UNTRUSTED EVIDENCE'));assert.ok(preview.text.length<70000);
  const response={summary:'Potential ownership gap',findings:[{title:'Check owner',status:'confirmed',severity:'high',confidence:'low',evidenceIds:['T1',preview.evidence.find(e=>e.kind==='route').id],reasoning:'Owner policy requires review.',missingEvidence:['Global policy'],validation:['Use two controlled accounts.'],remediation:'Enforce owner.',regressionTest:'Deny cross-owner reads.'}],gaps:[]};
  assert.equal(parseReview(JSON.stringify(response),preview).findings[0].status,'needs-validation');
  response.findings[0].evidenceIds.push('invented');assert.throws(()=>parseReview(JSON.stringify(response),preview),/outside the preview/);
});
test('source redaction preserves identifiers but masks quoted key values and PEM', () => {
  const clean=redactSource(`const config = {"password": "supersecret", apiKey: 'testprivatevalue'};\nverifyToken(request);\n-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----`);
  assert.ok(!clean.includes('supersecret'));assert.ok(!clean.includes('testprivatevalue'));assert.ok(!clean.includes('\nprivate\n'));assert.ok(clean.includes('verifyToken'));
});
test('Spring security annotations do not consume mapping and no-path method maps to class root', () => {
  const result=extractRoutes(source({'Api.java':`@RequestMapping("/api")\nclass Api {\n@GetMapping(produces="application/json")\n@PreAuthorize("hasRole('USER')")\npublic String get() { return "ok"; }\n@RequestMapping(method={RequestMethod.POST,RequestMethod.PUT})\npublic void update() {}\n}`}));
  assert.deepEqual(result.routes.map(r=>r.method+' '+r.path),['GET /api','POST /api','PUT /api']);
});
test('commented imports and regex literals cannot create fictitious router bindings', () => {
  const result=extractRoutes(source({'app.js':`const app=express();\n// import users from './users.js';\nconst text = /app.get('/fake', x)/;\napp.use('/api', users);`, 'users.js':`const router=express.Router(); router.get('/users', list); export default router;`}));
  assert.equal(result.routes.length,0);assert.ok(result.warnings.length);
});
test('chained Express methods work; dynamic mount prefixes remain unresolved', () => {
  const result=extractRoutes(source({'app.js':`const app=express();\nconst router=express.Router();\napp.route('/items/:id').get(getItem).delete(removeItem);\napp.use(PREFIX,router);\nrouter.get('/private',getPrivate);`}));
  assert.deepEqual(result.routes.map(r=>r.method+' '+r.path),['GET /items/:id','DELETE /items/:id']);assert.ok(result.warnings.length);
});
test('FastAPI module imports resolve mounted routers',()=>{
  const result=extractRoutes(source({'app/main.py':`from . import users\napp=FastAPI()\napp.include_router(users.router, prefix='/api')`, 'app/users.py':`router=APIRouter()\n@router.get('/users')\ndef users(): pass`}));
  assert.deepEqual(result.routes.map(r=>r.path),['/api/users']);
});
test('source index does not follow directory junctions outside selected root',async t=>{
  const root=await temp(t),other=await temp(t);await fs.writeFile(path.join(other,'private.js'),"const app=express();app.get('/private',x);");
  try {await fs.symlink(other,path.join(root,'linked'),process.platform==='win32'?'junction':'dir');}
  catch(e){if(['EPERM','EACCES'].includes(e.code)){t.skip('Filesystem does not permit symlink fixture');return;}throw e;}
  const result=await indexSource(root);assert.equal(result.files.size,0);assert.equal(result.routes.length,0);
});
test('analyst-selected policy excerpts are cited and constrained to indexed files',()=>{
  const files=source({'policy.js':'function enforceOwner(user, object) { return user.id === object.owner; }'});
  const endpoint={id:'E1',display:'GET https://app.test/user/1',state:'unmapped',count:1,variants:1,samples:[],matches:[]};
  const preview=buildReview(endpoint,{files},'authorization','',[{file:'policy.js',line:1},{file:'../outside.js',line:1},{file:'policy.js',line:9000}]);
  assert.equal(preview.evidence.length,1);assert.equal(preview.evidence[0].kind,'analyst-selected');assert.ok(preview.text.includes('enforceOwner'));
});
test('lexer and route limits stop adversarially dense files with visible omissions',()=>{
  const tokens=lex(';'.repeat(50000));assert.equal(tokens.length,40000);assert.equal(tokens.truncated,true);
  const result=extractRoutes(source({'dense.js':';'.repeat(45000)+"const app=express();app.get('/hidden',x);"}));
  assert.equal(result.routes.length,0);assert.ok(result.warnings.some(w=>w.includes('token limit')));
});
test('session labels are anonymized without collapsing distinct review samples',async t=>{
  const root=await temp(t);await fs.writeFile(path.join(root,'attack-surface-index.json'),JSON.stringify({summary:{total_items:3}}));
  for(const [i,tag] of ['private-admin-name','private-user-name','private-admin-name'].entries())await fs.writeFile(path.join(root,`${i}_GET_user.json`),JSON.stringify({metadata:{url:'https://app.test/users/1',method:'GET',status:200,session_tag:tag},request:{body:''},response:{body:'ok'}}));
  const traffic=await loadTraffic(root),samples=traffic.endpoints[0].samples;assert.equal(samples.length,2);assert.notEqual(samples[0].data.metadata.session_tag,samples[1].data.metadata.session_tag);assert.ok(!JSON.stringify(traffic).includes('private-admin-name'));
});
test('source redaction preserves line citations, expressions and masks multiline secret literals',()=>{
  const text='const token = request.headers.authorization;\nconst secret = `first-secret-line\nsecond-secret-line`;\n-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----\nfunction authorize() { return verify(token); }';
  const clean=redactSource(text);assert.equal(clean.split('\n').length,text.split('\n').length);assert.equal(clean.split('\n').at(-1),text.split('\n').at(-1));assert.ok(clean.includes('token = request.headers.authorization'));assert.ok(!clean.includes('second-secret-line'));assert.ok(!clean.includes('private-material'));
});
test('oversized URLs and source patterns are omitted before matching or model preview',async t=>{
  const root=await temp(t);await fs.writeFile(path.join(root,'attack-surface-index.json'),JSON.stringify({summary:{total_items:1}}));
  await fs.writeFile(path.join(root,'1_GET_user.json'),JSON.stringify({metadata:{url:'https://app.test/'+ 'x'.repeat(9000),method:'GET'},request:{},response:{}}));
  const traffic=await loadTraffic(root);assert.equal(traffic.endpoints.length,0);assert.ok(traffic.warnings.some(w=>w.includes('8192')));
  const result=extractRoutes(source({'app.js':"const app=express();app.get('/"+'x'.repeat(1100)+"', x);"}));assert.equal(result.routes.length,0);assert.ok(result.warnings.some(w=>w.includes('oversized route')));
  const prefixed=extractRoutes(source({'app.js':"const app=express();const router=express.Router();app.use('/"+'x'.repeat(1100)+"',router);router.get('/user',x);"}));assert.equal(prefixed.routes.length,0);assert.ok(prefixed.warnings.length);
});
