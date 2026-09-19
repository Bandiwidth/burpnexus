const assert = require('node:assert/strict');
const vscode = require('vscode');
exports.run = async () => {
  const extension = vscode.extensions.getExtension('burpnexus.burpnexus');
  assert.ok(extension, 'development extension discovered');
  await extension.activate();
  const commands = await vscode.commands.getCommands(true);
  assert.ok(commands.includes('burpnexus.openAnalysis'));
  assert.ok(commands.includes('burpnexus.importXml'));
  assert.ok(commands.includes('burpnexus.connect'));
  assert.ok(commands.includes('burpnexus.mapTraffic'));
  assert.equal(extension.packageJSON.version, '1.1.0');
  const { getPlaybook } = require(require('node:path').join(extension.extensionPath, 'src/playbooks'));
  const bounty = getPlaybook('bounty');
  assert.equal(bounty.checks.length, 8);
  assert.equal(bounty.references.length, 8);
  assert.ok(bounty.skill.instructions.includes('public-bounty-review') || bounty.skill.instructions.includes('Public bug bounty review'));
  console.log('BURPNEXUS_HOST_TEST_PASS: discovered, activated and all four commands registered');
};
