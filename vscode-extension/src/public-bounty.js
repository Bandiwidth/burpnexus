'use strict';
const fs = require('node:fs');
const path = require('node:path');
// Only packaged resources are loaded. Workspace files and remote pages cannot add instructions.
const catalog = require('../skills/public-bounty-review/references/catalog.json');
const instructions = fs.readFileSync(path.join(__dirname, '../skills/public-bounty-review/SKILL.md'), 'utf8')
  .replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '').trim();

function getBountySkill() {
  return structuredClone({
    skill: { id: catalog.id, version: catalog.version, reviewedOn: catalog.reviewedOn, selection: catalog.selection, instructions },
    references: Object.entries(catalog.sources).map(([id, source]) => ({ id, ...source })),
    checks: catalog.checks
  });
}
function getPublicReference(id) {
  if (typeof id !== 'string' || !Object.hasOwn(catalog.sources, id)) return undefined;
  const source = catalog.sources[id];
  const url = new URL(source.url);
  if (url.protocol !== 'https:' || !['gitlab.com', 'portswigger.net'].includes(url.hostname) || url.username || url.password || url.port) return undefined;
  return { id, ...structuredClone(source) };
}
module.exports = { getBountySkill, getPublicReference };
