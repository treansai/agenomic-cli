// End to end: a real Agenomic API gateway (AGENOMIC_E2E_ENDPOINT, started
// with the coding sessions migration and dev capability overrides), this
// connector, and the real Claude Code and Codex runtimes driven by local
// scripted model endpoints. Skipped when no gateway is configured.
//
//   AGENOMIC_E2E_ENDPOINT=http://127.0.0.1:18080 node --test test/e2e.test.ts

import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { RunnerApi } from '../src/api.ts';
import { defaultConfig, saveConfig, saveCredentials } from '../src/config.ts';
import { Daemon } from '../src/daemon.ts';
import { codexProviderToml, fakeAnthropic, fakeResponses, script, type FakeServer } from '../src/fakes.ts';
import { runProbe } from '../src/probe.ts';
import { sleep } from '../src/util.ts';

/** Run a CLI with stdin closed, without blocking the event loop. */
function run(cmd: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv; timeout: number }): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: opts.cwd, env: opts.env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    const t = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`${path.basename(cmd)} timed out: ${out.slice(-2000)}`));
    }, opts.timeout);
    child.on('exit', (code) => {
      clearTimeout(t);
      code === 0 ? resolve(out) : reject(new Error(`${path.basename(cmd)} exited ${code}: ${out.slice(-2000)}`));
    });
  });
}
const ENDPOINT = process.env.AGENOMIC_E2E_ENDPOINT;
const skip = !ENDPOINT ? 'AGENOMIC_E2E_ENDPOINT is not set' : false;
const POLICIES = path.resolve(import.meta.dirname, '../../../agenomic-cloud/examples/coding/policies');

class User {
  cookies = new Map<string, string>();
  csrf = '';
  orgId = '';
  userId = '';
  async call(method: string, p: string, body?: unknown): Promise<{ status: number; json: any }> {
    const res = await fetch(`${ENDPOINT}${p}`, {
      method,
      headers: {
        cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '),
        ...(this.csrf ? { 'x-csrf-token': this.csrf } : {}),
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(';');
      const i = kv!.indexOf('=');
      this.cookies.set(kv!.slice(0, i), kv!.slice(i + 1));
      if (kv!.startsWith('agenomic_csrf=')) this.csrf = kv!.slice(i + 1);
    }
    const text = await res.text();
    return { status: res.status, json: text ? JSON.parse(text) : {} };
  }
}

async function signup(email: string): Promise<User> {
  const u = new User();
  const s = await u.call('POST', '/v1/auth/signup', { email, password: 'correct-horse-battery-staple', terms_accepted: true });
  assert.equal(s.status, 200, JSON.stringify(s.json));
  u.userId = s.json.user_id;
  const v = await u.call('POST', '/v1/auth/verify-email', { user_id: u.userId, code: '000000' });
  assert.equal(v.status, 200, JSON.stringify(v.json));
  u.orgId = v.json.active_org.id;
  return u;
}

function repo(): { dir: string; origin: string } {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agn-e2e-')));
  const dir = path.join(root, 'work');
  const origin = path.join(root, 'origin.git');
  const git = (cwd: string, ...a: string[]) => execFileSync('git', ['-C', cwd, ...a], { stdio: 'ignore' });
  execFileSync('git', ['init', '-q', '--bare', origin]);
  fs.mkdirSync(dir);
  git(dir, 'init', '-q', '-b', 'main');
  fs.writeFileSync(path.join(dir, 'CLAUDE.md'), '# Agent instructions\n');
  fs.writeFileSync(path.join(dir, 'AGENTS.md'), '# Agent instructions\n');
  fs.writeFileSync(path.join(dir, 'sum.mjs'), 'export const sum = (a, b) => a + b;\n');
  fs.writeFileSync(path.join(dir, 'slow.mjs'), 'setTimeout(() => {}, 60000);\n');
  fs.writeFileSync(path.join(dir, 'sum.test.mjs'), "import { test } from 'node:test';\nimport assert from 'node:assert';\nimport { sum } from './sum.mjs';\ntest('sum', () => assert.equal(sum(2, 2), 4));\n");
  git(dir, 'add', '.');
  git(dir, '-c', 'user.email=e2e@agenomic.invalid', '-c', 'user.name=e2e', 'commit', '-q', '-m', 'init');
  git(dir, 'remote', 'add', 'origin', origin);
  git(dir, 'push', '-q', 'origin', 'main');
  // Uncommitted human work that must survive every session.
  fs.writeFileSync(path.join(dir, 'human-notes.txt'), 'work in progress, not committed\n');
  return { dir, origin };
}

let owner: User;
let reviewer: User;
let outsider: User;
let daemon: Daemon;
let claudeModel: FakeServer;
let codexModel: FakeServer;
let work: { dir: string; origin: string };
let runnerId = '';

async function until<T>(fn: () => Promise<T | undefined | false>, ms = 120000, every = 500): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v as T;
    if (Date.now() > end) throw new Error('condition not met in time');
    await sleep(every);
  }
}

before(async () => {
  if (skip) return;
  // A bootstrapped organization gets its ed25519 signing key, which policy
  // releases need (organizations created with POST /v1/orgs do not).
  const bootstrap = async (label: string) => (await fetch(`${ENDPOINT}/v1/orgs/bootstrap`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name: `E2E ${label} ${Date.now()}`, owner_email: `boot-${label}-${Date.now()}@e2e.agenomic.invalid` }),
  })).json() as any;
  const other = await bootstrap('outsider');
  const boot = await fetch(`${ENDPOINT}/v1/orgs/bootstrap`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name: `E2E coding ${Date.now()}`, owner_email: `boot-${Date.now()}@e2e.agenomic.invalid` }),
  }).then((r) => r.json() as Promise<any>);
  const orgId: string = boot.organization.id;
  const key: string = boot.bootstrap_api_key.value;
  // Test fixture only: a Team subscription row so the workspace can have
  // several members. Needs a database URL allowed to write it.
  if (process.env.AGENOMIC_E2E_SEED_DATABASE_URL) {
    execFileSync('psql', [process.env.AGENOMIC_E2E_SEED_DATABASE_URL, '-v', 'ON_ERROR_STOP=1', '-q', '-c',
      `INSERT INTO billing_subscriptions (org_id, stripe_customer_id, stripe_subscription_id, plan_code, status, quantity, current_period_start, current_period_end)
       VALUES ('${orgId}', 'cus_e2e_${orgId}', 'sub_e2e_${orgId}', 'team', 'active', 5, now() - interval '1 day', now() + interval '29 days')`]);
  }
  const invite = async (role: string, apiKey = key, org = orgId): Promise<User> => {
    const r = await fetch(`${ENDPOINT}/v1/invites`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': apiKey },
      body: JSON.stringify({ email: `${role}-${Date.now()}@e2e.agenomic.invalid`, role }),
    });
    const inv = (await r.json()) as any;
    assert.equal(r.status, 201, JSON.stringify(inv));
    const u = new User();
    const acc = await u.call('POST', `/v1/invites/${inv.raw_token}/accept`, { password: 'correct-horse-battery-staple' });
    assert.equal(acc.status, 200, JSON.stringify(acc.json));
    u.orgId = org;
    return u;
  };
  outsider = await invite('owner', other.bootstrap_api_key.value, other.organization.id);
  owner = await invite('owner');
  reviewer = await invite('maintainer');
  for (const f of fs.readdirSync(POLICIES)) {
    const text = fs.readFileSync(path.join(POLICIES, f), 'utf8');
    const id = text.match(/^policy_id: (\S+)/m)![1];
    let r = await owner.call('POST', '/v1/policies', { document_text: text });
    assert.equal(r.status, 201, `${id}: ${JSON.stringify(r.json)}`);
    r = await owner.call('POST', `/v1/policies/${id}@1.0.0/release`, {});
    assert.equal(r.status, 200, `${id}: ${JSON.stringify(r.json)}`);
  }

  claudeModel = await fakeAnthropic();
  codexModel = await fakeResponses();
  work = repo();
  process.env.AGENOMIC_CONNECTOR_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'agn-e2e-home-'));
  const e = await owner.call('POST', '/v1/coding/runners/enrollments', { name: 'e2e laptop' });
  assert.equal(e.status, 201);
  const enrolled = await RunnerApi.enroll(ENDPOINT!, { enrollment_token: e.json.token, name: 'e2e-laptop', kind: 'local_machine', os: process.platform, arch: process.arch, connector_version: '0.1.0' });
  runnerId = enrolled.runner.id;
  const cfg = defaultConfig(ENDPOINT!, 'e2e-laptop');
  cfg.runner_id = runnerId;
  cfg.workspaces = [{ id: 'demo', name: 'demo', path: work.dir, repo: 'local/demo', default_branch: 'main' }];
  cfg.runtimes.claude_code.extra_env = { ANTHROPIC_BASE_URL: claudeModel.url, ANTHROPIC_API_KEY: 'e2e-not-a-key' };
  cfg.runtimes.codex.extra_config_toml = codexProviderToml(codexModel.url);
  cfg.runtimes.codex.extra_env = { AGENOMIC_SCRIPTED_KEY: 'e2e-not-a-key' };
  saveConfig(cfg);
  saveCredentials(enrolled.credentials);
  daemon = new Daemon(cfg);
  await daemon.start();
});

after(async () => {
  if (skip) return;
  await daemon?.stop();
  await claudeModel?.close();
  await codexModel?.close();
});

async function actions(sid: string): Promise<any[]> {
  return (await owner.call('GET', `/v1/coding/sessions/${sid}/actions`)).json.items;
}

async function events(sid: string): Promise<any[]> {
  const out: any[] = [];
  let after = '';
  for (;;) {
    const r = await owner.call('GET', `/v1/coding/sessions/${sid}/events?limit=500${after ? `&after=${after}` : ''}`);
    out.push(...r.json.items);
    if (!r.json.has_more) return out;
    after = r.json.next_cursor;
  }
}

async function command(sid: string, kind: string, payload: unknown = {}): Promise<any> {
  const r = await owner.call('POST', `/v1/coding/sessions/${sid}/commands`, { kind, payload, idempotency_key: `${kind}-${Date.now()}-${Math.random()}` });
  assert.equal(r.status, 202, JSON.stringify(r.json));
  return until(async () => {
    const c = (await owner.call('GET', `/v1/coding/sessions/${sid}/commands`)).json.items.find((x: any) => x.id === r.json.command.id);
    return ['applied', 'refused', 'unknown', 'expired'].includes(c.status) ? c : undefined;
  }, 60000);
}

test('unvalidated capabilities never count as protected: enforce is blocked', { skip, timeout: 120000 }, async () => {
  const launch = await owner.call('POST', '/v1/coding/sessions', {
    runner_id: runnerId, runtime: 'codex', workspace_id: 'demo', branch: `agenomic/e2e-blocked-${Date.now()}`, mode: 'enforce',
    policy_refs: ['coding-isolated-dev@1.0.0'], prompt: script([{ tool: 'exec_command', input: { cmd: 'echo blocked > blocked.txt' } }]),
  });
  assert.equal(launch.status, 201, JSON.stringify(launch.json));
  const sid = launch.json.session.id;
  const s = await until(async () => {
    const x = (await owner.call('GET', `/v1/coding/sessions/${sid}`)).json.session;
    return x.mode_effective !== 'none' ? x : undefined;
  });
  assert.equal(s.mode_effective, 'blocked');
  assert.equal(s.capabilities.pre_tool_control.validated, 'unknown');
  const denied = await until(async () => (await actions(sid)).find((a) => a.reason_codes.includes('enforce_prerequisite_missing')));
  assert.equal(denied.decision, 'deny');
  const wt = path.join(process.env.AGENOMIC_CONNECTOR_HOME!, 'state', 'worktrees', sid);
  await sleep(2000);
  assert.equal(fs.existsSync(path.join(wt, 'blocked.txt')), false);
  // Unvalidated operations are refused by the gateway, not attempted.
  await owner.call('POST', `/v1/coding/sessions/${sid}/control`, { op: 'acquire' });
  const stop = await owner.call('POST', `/v1/coding/sessions/${sid}/commands`, { kind: 'stop_process', payload: {}, idempotency_key: `stop-${Date.now()}` });
  assert.equal(stop.status, 409);
  assert.match(stop.json.error.message, /capability_unsupported/);
});

test('validate the runtimes on this machine (doctor --probe)', { skip, timeout: 600000 }, async () => {
  const results = await runProbe();
  for (const r of results) {
    for (const [cap, v] of Object.entries(r.results)) assert.ok(v!.ok, `${r.runtime} ${cap}: ${v!.detail}`);
  }
  await daemon.heartbeat();
});

for (const runtime of ['claude_code', 'codex'] as const) {
  test(`${runtime}: launch, observe, deny, approve, interrupt, evidence`, { skip, timeout: 600000 }, async () => {
    const shell = runtime === 'claude_code' ? (c: string) => ({ tool: 'Bash', input: { command: c, description: 'e2e' } }) : (c: string) => ({ tool: 'exec_command', input: { cmd: c } });
    const configFile = runtime === 'claude_code' ? 'CLAUDE.md' : 'AGENTS.md';
    const outside = path.join(os.tmpdir(), `agn-e2e-outside-${runtime}-${Date.now()}.txt`);
    const originHead = execFileSync('git', ['--git-dir', work.origin, 'rev-parse', 'main']).toString().trim();
    const branch = `agenomic/e2e-${runtime}-${Date.now()}`;
    const steps = [
      shell('echo feature > feature.txt'),
      shell('node --test'),
      shell('git push --force origin HEAD:main'),
      shell(`echo exfil > ${outside}`),
      shell(`echo "- run the tests before pushing" >> ${configFile}`),
    ];
    const launch = await owner.call('POST', '/v1/coding/sessions', {
      runner_id: runnerId, runtime, workspace_id: 'demo', branch, mode: 'enforce',
      policy_profile: 'isolated_dev', policy_refs: ['coding-isolated-dev@1.0.0'],
      prompt: script(steps, 'add the feature, run the tests, update the instructions'),
      capture: { conversation: true, commands: true, diffs: true, outputs: false },
    });
    assert.equal(launch.status, 201, JSON.stringify(launch.json));
    const sid = launch.json.session.id;
    assert.equal(launch.json.session.control, 'controllable');

    // The session reports its native id, its effective mode and protection.
    const running = await until(async () => {
      const s = (await owner.call('GET', `/v1/coding/sessions/${sid}`)).json.session;
      return s.runtime_session_id && s.mode_effective !== 'none' ? s : undefined;
    });
    assert.equal(running.mode_effective, 'enforce', JSON.stringify(running));
    assert.ok(running.protection.protected.length > 0);
    assert.ok(running.tool_run_id && running.rmp_session_id);

    // The agent config change waits for a distinct reviewer.
    const pending = await until(async () => (await actions(sid)).find((a) => a.decision === 'pending' && a.tool_id === 'coding.agent_config.modify'));
    const self = await owner.call('POST', `/v1/protect/approvals/${pending.approval_id}/decide`, { decision: 'approve' });
    assert.equal(self.status, 403, 'the session actor cannot approve their own agent');
    const [a, b] = await Promise.all([
      reviewer.call('POST', `/v1/protect/approvals/${pending.approval_id}/decide`, { decision: 'approve', comment: 'ok for the instructions file' }),
      reviewer.call('POST', `/v1/protect/approvals/${pending.approval_id}/decide`, { decision: 'approve' }),
    ]);
    assert.deepEqual([a.status, b.status].sort(), [200, 409], 'concurrent decisions: exactly one applies');

    await until(async () => (await events(sid)).some((e) => e.type === 'turn.completed'));
    const wt = path.join(process.env.AGENOMIC_CONNECTOR_HOME!, 'state', 'worktrees', sid);
    // Allowed: exactly the expected effect.
    assert.equal(fs.readFileSync(path.join(wt, 'feature.txt'), 'utf8'), 'feature\n');
    // Refused: no push reached the origin, nothing written outside.
    assert.equal(execFileSync('git', ['--git-dir', work.origin, 'rev-parse', 'main']).toString().trim(), originHead);
    assert.equal(fs.existsSync(outside), false);
    // Approved: only the approved change happened, in the worktree only.
    assert.match(fs.readFileSync(path.join(wt, configFile), 'utf8'), /run the tests before pushing/);
    assert.equal(fs.readFileSync(path.join(work.dir, configFile), 'utf8'), '# Agent instructions\n');
    // Human work survived.
    assert.equal(fs.readFileSync(path.join(work.dir, 'human-notes.txt'), 'utf8'), 'work in progress, not committed\n');

    const acts = await actions(sid);
    const byTool = (needle: string) => acts.filter((x) => JSON.stringify(x.preview).includes(needle));
    assert.ok(byTool('feature.txt').some((x) => x.decision === 'allow' && x.status === 'completed'), JSON.stringify(acts));
    assert.ok(byTool('git push --force').every((x) => x.decision === 'deny'));
    assert.ok(byTool('exfil').every((x) => x.decision === 'deny'));
    const approved = acts.find((x) => x.approval_id === pending.approval_id);
    assert.equal(approved.decision, 'allow');
    // RFC 0013 approval_status: an approval the call already used is served as approved.
    assert.equal(approved.approval_status, 'approved');

    const evs = await events(sid);
    assert.ok(evs.some((e) => e.type === 'diff.snapshot' && e.payload.files.some((f: any) => f.path === 'feature.txt')));
    assert.ok(evs.some((e) => e.type === 'test.result' && e.trust === 'derived'), 'test results are derived signals');
    assert.ok(evs.some((e) => e.type === 'message.user'));
    const leaked = JSON.stringify(evs);
    for (const secret of [daemon.api.credentials()!.access_token, daemon.api.credentials()!.refresh_token]) assert.ok(!leaked.includes(secret));

    // Live stream: SSE frames carry the session and the events with their cursor.
    const ac = new AbortController();
    const res = await fetch(`${ENDPOINT}/v1/coding/sessions/${sid}/stream`, { headers: { cookie: [...owner.cookies].map(([k, v]) => `${k}=${v}`).join('; '), accept: 'text/event-stream' }, signal: ac.signal });
    assert.equal(res.status, 200);
    const reader = res.body!.getReader();
    let sse = '';
    while (!sse.includes('event: coding.event')) sse += new TextDecoder().decode((await reader.read()).value);
    ac.abort();
    assert.match(sse, /event: coding\.session/);
    assert.match(sse, /id: \d+/);

    // Interrupt a long turn: an interrupt is not a stop.
    const ctrl = await owner.call('POST', `/v1/coding/sessions/${sid}/control`, { op: 'acquire' });
    assert.equal(ctrl.status, 200, JSON.stringify(ctrl.json));
    const msg = await command(sid, 'send_message', { text: script([shell('node slow.mjs')], 'long task') });
    assert.equal(msg.status, 'applied');
    await until(async () => (await actions(sid)).some((x) => JSON.stringify(x.preview).includes('slow.mjs')));
    await sleep(2000);
    const turnsBefore = (await events(sid)).filter((e) => e.type === 'turn.completed' || e.type === 'turn.interrupted').length;
    const t0 = Date.now();
    const intr = await command(sid, 'interrupt_turn');
    assert.equal(intr.status, 'applied');
    await until(async () => (await events(sid)).filter((e) => e.type === 'turn.completed' || e.type === 'turn.interrupted').length > turnsBefore, 30000);
    assert.ok(Date.now() - t0 < 30000, 'the 60 s command was cut short by the interrupt');
    const s1 = (await owner.call('GET', `/v1/coding/sessions/${sid}`)).json.session;
    assert.notEqual(s1.status, 'stopped', 'an interrupted turn leaves the session alive');
    const stop = await command(sid, 'stop_process');
    assert.equal(stop.status, 'applied');
    assert.equal(stop.result.process_exited, true);

    // Evidence in Protect and RMP.
    const report = await owner.call('GET', `/v1/tool-execution/runs/${running.tool_run_id}/report`);
    assert.equal(report.status, 200, JSON.stringify(report.json));
    assert.ok(JSON.stringify(report.json).includes('coding.git.destructive'));
    const rmp = await owner.call('GET', `/v1/rmp/sessions/${running.rmp_session_id}`);
    assert.equal(rmp.status, 200, JSON.stringify(rmp.json));

    // Another tenant sees nothing.
    assert.equal((await outsider.call('GET', `/v1/coding/sessions/${sid}`)).status, 404);
    assert.equal((await outsider.call('GET', `/v1/coding/sessions/${sid}/events`)).status, 404);
  });
}

// ── Local sessions: the developer's own CLI, with hooks installed ─────────

test('claude_code CLI session with installed hooks appears without import', { skip, timeout: 180000 }, async () => {
  const { planClaude, apply, claudeSettingsFile } = await import('../src/hooks-install.ts');
  const file = claudeSettingsFile('project', work.dir);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ permissions: { allow: ['Read'] }, hooks: { Stop: [{ hooks: [{ type: 'command', command: 'true' }] }] } }, null, 2));
  const plan = planClaude(file, 'open', true);
  assert.equal(apply(plan) !== null, true, 'existing file is backed up');
  assert.equal(planClaude(file, 'open', true).changed, false, 'install is idempotent');
  const cliHome = fs.mkdtempSync(path.join(os.tmpdir(), 'agn-cli-home-'));
  const claude = path.resolve(import.meta.dirname, '../node_modules/@anthropic-ai/claude-agent-sdk-linux-x64/claude');
  // Asynchronous: the connector daemon answering the hooks lives in this process.
  await run(claude, ['-p', script([{ tool: 'Write', input: { file_path: path.join(work.dir, 'cli-note.txt'), content: 'from the cli\n' } }], 'local task'), '--permission-mode', 'acceptEdits'], {
    cwd: work.dir,
    env: { PATH: process.env.PATH!, HOME: cliHome, CLAUDE_CONFIG_DIR: path.join(cliHome, '.claude'), ANTHROPIC_BASE_URL: claudeModel.url, ANTHROPIC_API_KEY: 'e2e-not-a-key' },
    timeout: 120000,
  });
  const s = await until(async () => (await owner.call('GET', '/v1/coding/sessions?origin=local_connected&runtime=claude_code')).json.items[0]);
  assert.equal(s.control, 'observed');
  assert.equal(s.workspace_id, 'demo');
  const acts = await actions(s.id);
  assert.ok(acts.some((a) => a.native_tool === 'Write' && a.decision === 'defer'), JSON.stringify(acts));
  const evs = await events(s.id);
  assert.ok(evs.some((e) => e.type === 'session.started'));
  assert.ok(evs.some((e) => e.type === 'session.ended'), 'SessionEnd closes the session; Stop only ends a turn');
  // Commands are not offered for an observed session.
  const ctrl = await owner.call('POST', `/v1/coding/sessions/${s.id}/control`, { op: 'acquire' });
  assert.equal(ctrl.status, 409);
  // Uninstall removes exactly what install added.
  apply(planClaude(file, 'open', false));
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), { permissions: { allow: ['Read'] }, hooks: { Stop: [{ hooks: [{ type: 'command', command: 'true' }] }] } });
  fs.rmSync(path.join(work.dir, '.claude'), { recursive: true });
  fs.rmSync(path.join(work.dir, 'cli-note.txt'), { force: true });
});

test('codex CLI session with installed hooks appears without import', { skip, timeout: 180000 }, async () => {
  const { installCodex, planCodex, apply } = await import('../src/hooks-install.ts');
  const { codexExecutable } = await import('../src/codex.ts');
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'agn-codex-home-'));
  const file = path.join(codexHome, 'config.toml');
  fs.writeFileSync(file, codexProviderToml(codexModel.url) + '\n');
  const exe = codexExecutable({ enabled: true, env_passthrough: [], extra_env: {}, allowed_domains: [] });
  const r = await installCodex(file, 'open', exe, work.dir, false);
  assert.ok(r.trusted >= 1, 'the installer records trust for its own hooks only');
  await run(process.execPath, [exe, 'exec', '--skip-git-repo-check', '-s', 'read-only', script([{ tool: 'exec_command', input: { cmd: 'git status --short' } }], 'local codex task')], {
    cwd: work.dir,
    env: { PATH: process.env.PATH!, HOME: codexHome, CODEX_HOME: codexHome, AGENOMIC_SCRIPTED_KEY: 'e2e-not-a-key' },
    timeout: 90000,
  });
  const s = await until(async () => (await owner.call('GET', '/v1/coding/sessions?origin=local_connected&runtime=codex')).json.items[0]);
  assert.equal(s.control, 'observed');
  const acts = await actions(s.id);
  assert.ok(acts.some((a) => a.tool_id === 'coding.git.read'), JSON.stringify(acts));
  apply(planCodex(file, 'open', false));
  assert.equal(fs.readFileSync(file, 'utf8').includes('agenomic-connector'), false);
});
