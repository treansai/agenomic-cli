// Reproducible demo of coding sessions against a running Agenomic gateway,
// with the real Claude Code and Codex runtimes and local scripted models
// (no provider account, nothing leaves the machine).
//
//   AGENOMIC_E2E_ENDPOINT=http://127.0.0.1:18080 \
//   AGENOMIC_E2E_SEED_DATABASE_URL=postgres://postgres@127.0.0.1:5432/agenomic_e2e \
//   node test/demo.ts [--keep]
//
// It prints each step and, with --keep, leaves a Codex session waiting for
// an approval and the daemon running so the cockpit can be explored with
// the printed credentials.

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { RunnerApi } from '../src/api.ts';
import { defaultConfig, saveConfig, saveCredentials } from '../src/config.ts';
import { Daemon } from '../src/daemon.ts';
import { codexProviderToml, fakeAnthropic, fakeResponses, script } from '../src/fakes.ts';
import { runProbe } from '../src/probe.ts';
import { sleep } from '../src/util.ts';

const E = process.env.AGENOMIC_E2E_ENDPOINT ?? 'http://127.0.0.1:18080';
const keep = process.argv.includes('--keep');
const PASSWORD = 'demo-password-not-secret';
const say = (s: string) => process.stdout.write(`\n▶ ${s}\n`);

class User {
  cookies = new Map<string, string>();
  csrf = '';
  readonly email: string;
  constructor(email: string) {
    this.email = email;
  }
  async call(method: string, p: string, body?: unknown): Promise<any> {
    const res = await fetch(`${E}${p}`, {
      method,
      headers: { cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '), ...(this.csrf ? { 'x-csrf-token': this.csrf } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    for (const c of res.headers.getSetCookie()) {
      const kv = c.split(';')[0]!;
      const i = kv.indexOf('=');
      this.cookies.set(kv.slice(0, i), kv.slice(i + 1));
      if (kv.startsWith('agenomic_csrf=')) this.csrf = kv.slice(i + 1);
    }
    const t = await res.text();
    const json = t ? JSON.parse(t) : {};
    if (res.status >= 400) throw new Error(`${method} ${p}: ${res.status} ${t}`);
    return json;
  }
}

async function until<T>(fn: () => Promise<T | undefined>, ms = 120000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out');
    await sleep(500);
  }
}

say('Organization, an owner who launches and a reviewer who approves');
const boot = (await (await fetch(`${E}/v1/orgs/bootstrap`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: 'Coding demo', owner_email: `bootstrap-${Date.now()}@demo.agenomic.invalid` }) })).json()) as any;
if (process.env.AGENOMIC_E2E_SEED_DATABASE_URL) {
  execFileSync('psql', [process.env.AGENOMIC_E2E_SEED_DATABASE_URL, '-q', '-c', `INSERT INTO billing_subscriptions (org_id, stripe_customer_id, stripe_subscription_id, plan_code, status, quantity, current_period_start, current_period_end) VALUES ('${boot.organization.id}', 'cus_demo_${boot.organization.id}', 'sub_demo_${boot.organization.id}', 'team', 'active', 5, now() - interval '1 day', now() + interval '29 days')`]);
}
async function member(role: string): Promise<User> {
  const email = `${role}-${Date.now()}@demo.agenomic.invalid`;
  const inv = (await (await fetch(`${E}/v1/invites`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': boot.bootstrap_api_key.value }, body: JSON.stringify({ email, role }) })).json()) as any;
  const u = new User(email);
  await u.call('POST', `/v1/invites/${inv.raw_token}/accept`, { password: PASSWORD });
  return u;
}
const owner = await member('owner');
const reviewer = await member('maintainer');
const policies = path.resolve(import.meta.dirname, '../../../agenomic-cloud/examples/coding/policies');
for (const f of fs.readdirSync(policies)) {
  const text = fs.readFileSync(path.join(policies, f), 'utf8');
  const id = text.match(/^policy_id: (\S+)/m)![1];
  await owner.call('POST', '/v1/policies', { document_text: text });
  await owner.call('POST', `/v1/policies/${id}@1.0.0/release`, {});
}

say('Repository with uncommitted human work, and the connector on this machine');
const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agn-demo-')));
const repo = path.join(root, 'shop');
fs.mkdirSync(repo);
const git = (...a: string[]) => execFileSync('git', ['-C', repo, ...a], { stdio: 'ignore' });
git('init', '-q', '-b', 'main');
fs.writeFileSync(path.join(repo, 'AGENTS.md'), '# Instructions\n');
fs.writeFileSync(path.join(repo, 'CLAUDE.md'), '# Instructions\n');
fs.writeFileSync(path.join(repo, 'cart.mjs'), 'export const total = (items) => items.reduce((s, i) => s + i.price, 0);\n');
fs.writeFileSync(path.join(repo, 'cart.test.mjs'), "import { test } from 'node:test';\nimport assert from 'node:assert';\nimport { total } from './cart.mjs';\ntest('total', () => assert.equal(total([{ price: 2 }, { price: 3 }]), 5));\n");
fs.writeFileSync(path.join(repo, 'slow.mjs'), 'setTimeout(() => {}, 60000);\n');
git('add', '.');
git('-c', 'user.email=demo@demo.invalid', '-c', 'user.name=demo', 'commit', '-q', '-m', 'init');
fs.writeFileSync(path.join(repo, 'NOTES.txt'), 'human work in progress\n');
process.env.AGENOMIC_CONNECTOR_HOME = path.join(root, 'connector');
const claudeModel = await fakeAnthropic();
const codexModel = await fakeResponses();
const tok = await owner.call('POST', '/v1/coding/runners/enrollments', { name: 'demo laptop' });
const enrolled = await RunnerApi.enroll(E, { enrollment_token: tok.token, name: 'demo-laptop', kind: 'local_machine', os: process.platform, arch: process.arch, connector_version: '0.1.0' });
const cfg = defaultConfig(E, 'demo-laptop');
cfg.workspaces = [{ id: 'shop', name: 'shop', path: repo, repo: 'local/shop', default_branch: 'main' }];
cfg.runtimes.claude_code.extra_env = { ANTHROPIC_BASE_URL: claudeModel.url, ANTHROPIC_API_KEY: 'demo-not-a-key' };
cfg.runtimes.codex.extra_config_toml = codexProviderToml(codexModel.url);
cfg.runtimes.codex.extra_env = { AGENOMIC_SCRIPTED_KEY: 'demo-not-a-key' };
saveConfig(cfg);
saveCredentials(enrolled.credentials);
say('Validating Claude Code and Codex on this machine (doctor --probe)');
for (const r of await runProbe()) console.log(`  ${r.runtime} ${r.version}: ${Object.entries(r.results).map(([k, v]) => `${k}=${v!.ok ? 'ok' : 'FAIL'}`).join(' ')}`);
const daemon = new Daemon(cfg);
await daemon.start();

for (const runtime of ['claude_code', 'codex'] as const) {
  const shell = runtime === 'claude_code' ? (c: string) => ({ tool: 'Bash', input: { command: c, description: 'demo' } }) : (c: string) => ({ tool: 'exec_command', input: { cmd: c } });
  const cfgFile = runtime === 'claude_code' ? 'CLAUDE.md' : 'AGENTS.md';
  say(`${runtime}: launch in enforce mode with the "isolated development" profile`);
  const launched = await owner.call('POST', '/v1/coding/sessions', {
    runner_id: enrolled.runner.id, runtime, workspace_id: 'shop', branch: `agenomic/demo-${runtime}-${Date.now()}`, mode: 'enforce',
    policy_profile: 'isolated_dev', policy_refs: ['coding-isolated-dev@1.0.0'],
    capture: { conversation: true, commands: true, diffs: true, outputs: false },
    prompt: script([
      shell("printf 'export const discount = (t) => t * 0.9;\\n' > discount.mjs"),
      shell('node --test'),
      shell('git push --force origin HEAD:main'),
      shell(`echo "- keep discounts under 10%" >> ${cfgFile}`),
    ], 'add a discount helper and run the tests'),
  });
  const sid = launched.session.id;
  console.log(`  session ${sid} (${launched.session.control})`);
  const pending = await until(async () => (await owner.call('GET', `/v1/coding/sessions/${sid}/actions`)).items.find((a: any) => a.decision === 'pending'));
  const acts = (await owner.call('GET', `/v1/coding/sessions/${sid}/actions`)).items;
  for (const a of acts) console.log(`  ${a.decision.padEnd(7)} ${a.tool_id.padEnd(28)} ${a.risk.padEnd(8)} ${a.preview}`);
  if (runtime === 'codex' && keep) {
    say(`Leaving approval ${pending.approval_id} pending for the cockpit`);
    break;
  }
  say(`reviewer approves the change to ${cfgFile} (approval ${pending.approval_id})`);
  await reviewer.call('POST', `/v1/protect/approvals/${pending.approval_id}/decide`, { decision: 'approve', comment: 'ok' });
  await until(async () => (await owner.call('GET', `/v1/coding/sessions/${sid}/events?limit=500`)).items.find((e: any) => e.type === 'turn.completed'));
  const evs = (await owner.call('GET', `/v1/coding/sessions/${sid}/events?limit=500`)).items;
  const diff = evs.filter((e: any) => e.type === 'diff.snapshot').pop();
  console.log(`  diff: ${diff.payload.files.map((f: any) => `${f.status} ${f.path}`).join(', ')}`);
  console.log(`  tests: ${evs.filter((e: any) => e.type === 'test.result').map((e: any) => `${e.payload.passed ? 'passed' : 'failed'} (${e.trust})`).join(', ')}`);
  say('interrupt a long turn');
  await owner.call('POST', `/v1/coding/sessions/${sid}/control`, { op: 'acquire' });
  await owner.call('POST', `/v1/coding/sessions/${sid}/commands`, { kind: 'send_message', payload: { text: script([shell('node slow.mjs')], 'long task') }, idempotency_key: `m-${Date.now()}` });
  await until(async () => (await owner.call('GET', `/v1/coding/sessions/${sid}/actions`)).items.find((a: any) => a.preview.includes('slow.mjs')));
  await sleep(2000);
  const intr = await owner.call('POST', `/v1/coding/sessions/${sid}/commands`, { kind: 'interrupt_turn', payload: {}, idempotency_key: `i-${Date.now()}` });
  const done = await until(async () => (await owner.call('GET', `/v1/coding/sessions/${sid}/commands`)).items.find((c: any) => c.id === intr.command.id && c.status !== 'requested' && c.status !== 'received'));
  console.log(`  interrupt_turn: ${done.status}; session status ${(await owner.call('GET', `/v1/coding/sessions/${sid}`)).session.status}`);
  const s = (await owner.call('GET', `/v1/coding/sessions/${sid}`)).session;
  const report = await owner.call('GET', `/v1/tool-execution/runs/${s.tool_run_id}/report`);
  say(`evidence: protect run ${s.tool_run_id}, RMP session ${s.rmp_session_id}`);
  console.log(`  protect report keys: ${Object.keys(report).join(', ')}`);
}

console.log(`\nhuman work untouched: ${fs.readFileSync(path.join(repo, 'NOTES.txt'), 'utf8').trim()}`);
if (keep) {
  console.log(`\ncockpit login: ${owner.email} / ${PASSWORD}   reviewer: ${reviewer.email} / ${PASSWORD}`);
  console.log('daemon running; Ctrl-C to stop');
} else {
  await daemon.stop();
  await claudeModel.close();
  await codexModel.close();
  process.exit(0);
}
