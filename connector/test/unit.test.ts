import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { ApiError, RunnerApi } from '../src/api.ts';
import { manifest, saveProbe } from '../src/capabilities.ts';
import { ClaudeSession, claudeCodeVersion, readClaudeCodeVersion, sdkPackage } from '../src/claude.ts';
import { CodexSession, codexVersion, readCodexVersion } from '../src/codex.ts';
import { defaultConfig, localFailMode, paths, runtimeSecrets, saveConfig } from '../src/config.ts';
import { main } from '../src/cli.ts';
import { Daemon } from '../src/daemon.ts';
import { EventSink } from '../src/events.ts';
import { eventOf } from '../src/hook.ts';
import { apply, codexBlock, hookCommand, planClaude, planCodex } from '../src/hooks-install.ts';
import { clean, redact } from '../src/redact.ts';
import { protection, TOOL_IDS } from '../src/protection.ts';
import { ProbeApi, probeConfig, probedVersion, runProbe, tempRepo } from '../src/probe.ts';
import { isTestCommand, type SessionContext } from '../src/session.ts';
import { realPathEscapes, sleep, ulid } from '../src/util.ts';
import * as ws from '../src/workspace.ts';

const tmp = (p: string) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));
const BIN = path.resolve(import.meta.dirname, '../bin/agenomic-connector.mjs');

test('redaction removes credentials and terminal escapes before export', () => {
  const out = clean('\u001b[31mOPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwx\u001b[0m and https://u:hunter2@host/x ghp_abcdefghijklmnopqrstuvwxyz0123 \u001b]8;;file:///etc/passwd\u0007link');
  assert.ok(!out.includes('abcdefghijklmnop'));
  assert.ok(!out.includes('hunter2'));
  assert.ok(!out.includes('\u001b'));
  assert.ok(!out.includes('file:///etc/passwd'));
  assert.equal(redact('runner agmrt_aaaaaaaaaaaaaaaaaaaaaaaa', []), 'runner [REDACTED]');
  assert.equal(redact('token is s3cret-value-123', ['s3cret-value-123']), 'token is [REDACTED]');
});

test('Claude Code hooks: preserve existing hooks, idempotent, exact uninstall, backup', () => {
  const dir = tmp('agn-hooks-');
  const file = path.join(dir, '.claude', 'settings.local.json');
  fs.mkdirSync(path.dirname(file));
  const original = { permissions: { deny: ['Bash(rm:*)'] }, hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: '/usr/local/bin/team-guard' }] }] } };
  fs.writeFileSync(file, JSON.stringify(original, null, 2));
  const plan = planClaude(file, 'closed', true);
  assert.ok(plan.changed);
  const backup = apply(plan);
  assert.ok(backup && fs.existsSync(backup), 'the previous file is backed up');
  const installed = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(installed.hooks.PreToolUse.length, 2, 'the team hook is kept');
  assert.equal(installed.hooks.PreToolUse[0].hooks[0].command, '/usr/local/bin/team-guard');
  assert.match(installed.hooks.PreToolUse[1].hooks[0].command, /agenomic-connector.* hook claude-code --fail closed/);
  assert.equal(installed.hooks.PreToolUse[1].hooks[0].timeout, 600);
  assert.ok(installed.hooks.SessionEnd && installed.hooks.Stop, 'turn end and session end are distinct hooks');
  assert.deepEqual(installed.permissions, original.permissions);
  assert.equal(planClaude(file, 'closed', true).changed, false, 'a second install changes nothing');
  // A hook added by the user after our install survives the uninstall.
  installed.hooks.PostToolUse.push({ hooks: [{ type: 'command', command: 'echo later' }] });
  fs.writeFileSync(file, JSON.stringify(installed, null, 2));
  apply(planClaude(file, 'closed', false));
  const after = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(after.hooks.PreToolUse, original.hooks.PreToolUse);
  assert.deepEqual(after.hooks.PostToolUse, [{ hooks: [{ type: 'command', command: 'echo later' }] }]);
  assert.deepEqual(after.permissions, original.permissions);
});

test('Claude Code hooks: a user hook added to the Agenomic matcher entry survives reinstall and uninstall', () => {
  const dir = tmp('agn-hooks-');
  const file = path.join(dir, '.claude', 'settings.local.json');
  fs.mkdirSync(path.dirname(file));
  apply(planClaude(file, 'local', true));
  const installed = JSON.parse(fs.readFileSync(file, 'utf8'));
  const user = { type: 'command', command: '/usr/local/bin/audit-log' };
  installed.hooks.PreToolUse[0].hooks.push(user);
  fs.writeFileSync(file, JSON.stringify(installed, null, 2));
  apply(planClaude(file, 'local', true));
  const reinstalled = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(reinstalled.hooks.PreToolUse[0], { matcher: '*', hooks: [user] }, 'the user hook keeps its entry');
  assert.equal(reinstalled.hooks.PreToolUse.length, 2);
  assert.match(reinstalled.hooks.PreToolUse[1].hooks[0].command, /agenomic-connector.* hook claude-code/);
  assert.equal(planClaude(file, 'local', true).changed, false, 'reinstalling again changes nothing');
  apply(planClaude(file, 'local', false));
  const after = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(after.hooks, { PreToolUse: [{ matcher: '*', hooks: [user] }] }, 'only the Agenomic command hooks are removed');
});

test('Codex hooks: managed block only, exact uninstall, refuses a conflicting [hooks] table', () => {
  const dir = tmp('agn-codex-');
  const file = path.join(dir, 'config.toml');
  const original = 'model = "gpt-5"\n\n[mcp_servers.docs]\ncommand = "docs-mcp"\n';
  fs.writeFileSync(file, original);
  apply(planCodex(file, 'closed', true, { 'k:pre_tool_use:0:0': 'sha256:abc' }));
  const text = fs.readFileSync(file, 'utf8');
  assert.ok(text.startsWith(original));
  assert.match(text, /\[\[hooks\.PreToolUse\]\]/);
  assert.match(text, /trusted_hash = "sha256:abc"/);
  assert.equal(planCodex(file, 'closed', true, { 'k:pre_tool_use:0:0': 'sha256:abc' }).changed, false);
  apply(planCodex(file, 'closed', false));
  assert.equal(fs.readFileSync(file, 'utf8'), original);
  fs.writeFileSync(file, original + '\n[hooks]\nfoo = 1\n');
  assert.throws(() => planCodex(file, 'closed', true), /already defines a \[hooks\] table/);
  assert.match(codexBlock('closed', 900), /timeout = 900/);
});

test('a fail-closed hook refuses explicitly when the daemon is unreachable; fail-open does not', () => {
  const input = JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', tool_name: 'Bash', tool_input: { command: 'rm -rf /' } });
  const sock = path.join(tmp('agn-sock-'), 'state', 'missing.sock');
  const closed = spawnSync(process.execPath, [BIN, 'hook', 'claude-code', '--fail', 'closed', '--deadline', '2000', '--socket', sock], { input, encoding: 'utf8' });
  assert.equal(closed.status, 0, 'a structured decision, not a crash exit code');
  const out = JSON.parse(closed.stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, 'deny');
  const open = spawnSync(process.execPath, [BIN, 'hook', 'claude-code', '--fail', 'open', '--deadline', '2000', '--socket', sock], { input, encoding: 'utf8' });
  assert.equal(open.status, 0);
  assert.equal(open.stdout, '', 'fail-open leaves the native flow in charge');
  const garbage = spawnSync(process.execPath, [BIN, 'hook', 'codex', '--fail', 'closed', '--deadline', '2000', '--socket', sock], { input: 'not json', encoding: 'utf8' });
  assert.equal(JSON.parse(garbage.stdout).hookSpecificOutput.permissionDecision, 'deny');
});

test('a fail-closed denial reaches a reader that is not draining the hook output yet', async () => {
  // The runtime reads the hook's stdout pipe at its own pace. A pipe that
  // is already full makes the hook's write asynchronous: exiting the
  // process before it is flushed would leave the runtime with no decision.
  const dir = tmp('agn-fifo-');
  const fifo = path.join(dir, 'out');
  execFileSync('mkfifo', [fifo]);
  const reader = fs.openSync(fifo, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  const writer = fs.openSync(fifo, 'w');
  const filler = 64 * 1024;
  fs.writeSync(writer, Buffer.alloc(filler, 'x'));
  const sock = path.join(dir, 'state', 'missing.sock');
  const input = JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', tool_name: 'Bash', tool_input: { command: 'rm -rf /' } });
  const child = spawn(process.execPath, [BIN, 'hook', 'claude-code', '--fail', 'closed', '--deadline', '2000', '--socket', sock], { stdio: ['pipe', writer, 'ignore'] });
  fs.closeSync(writer);
  let exited = false;
  const status = new Promise<number | null>((resolve) => child.on('exit', (code) => {
    exited = true;
    resolve(code);
  }));
  child.stdin!.end(input);
  await sleep(1000);
  const chunks: Buffer[] = [];
  const buf = Buffer.alloc(64 * 1024);
  try {
    for (;;) {
      let n: number;
      try {
        n = fs.readSync(reader, buf);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EAGAIN') throw error;
        if (exited) break;
        await sleep(20);
        continue;
      }
      if (n === 0) break;
      chunks.push(Buffer.from(buf.subarray(0, n)));
    }
  } finally {
    fs.closeSync(reader);
  }
  assert.equal(await status, 0);
  const out = Buffer.concat(chunks).subarray(filler).toString('utf8');
  assert.equal(JSON.parse(out).hookSpecificOutput.permissionDecision, 'deny');
});

test('local-session hooks follow the current local-sessions mode, not the mode at install time', () => {
  const home = tmp('agn-home-');
  const env = { ...process.env, AGENOMIC_CONNECTOR_HOME: home };
  const cli = (...a: string[]) => spawnSync(process.execPath, [BIN, ...a], { env, encoding: 'utf8' });
  const input = JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', tool_name: 'Bash', tool_input: { command: 'ls' } });
  // The installed command carries no fixed fail mode.
  const command = hookCommand('claude-code', 'local', 2000, path.join(home, 'state', 'connector.sock'));
  assert.match(command, / hook claude-code --fail local /);
  // The daemon is not running: every call below takes the fallback.
  const hook = () => spawnSync(process.execPath, [BIN, 'hook', 'claude-code', '--fail', 'local', '--deadline', '2000', '--socket', path.join(home, 'state', 'connector.sock')], { input, encoding: 'utf8' }).stdout;
  const denied = () => JSON.parse(hook() || '{}').hookSpecificOutput?.permissionDecision === 'deny';
  assert.equal(denied(), false, 'no connector configuration: nothing to enforce');
  const prev = process.env.AGENOMIC_CONNECTOR_HOME;
  process.env.AGENOMIC_CONNECTOR_HOME = home;
  try {
    saveConfig(defaultConfig('http://127.0.0.1:9', 'unit'));
    assert.equal(localFailMode(), 'open');
    assert.equal(denied(), false, 'observe fails open');
    assert.equal(cli('local-sessions', '--mode', 'enforce').status, 0);
    assert.equal(localFailMode(), 'closed');
    assert.equal(denied(), true, 'after the switch to enforce, the same installed hook fails closed');
    // An unreadable configuration: the mode recorded with the last change decides.
    fs.writeFileSync(paths.config(), '{ not json');
    assert.equal(denied(), true);
    fs.rmSync(paths.localFailMode());
    assert.equal(denied(), true, 'neither readable while a configuration exists: closed');
    fs.rmSync(paths.config());
    assert.equal(denied(), false, 'no configuration and no recorded mode: open');
    saveConfig(defaultConfig('http://127.0.0.1:9', 'unit'));
    assert.equal(cli('local-sessions', '--mode', 'enforce').status, 0);
    fs.rmSync(paths.config());
    assert.equal(denied(), true, 'enforce was the last recorded mode: closed');
    assert.equal(cli('hooks', 'install', '--runtime', 'claude-code', '--dir', home).status, 0);
    assert.equal(JSON.parse(fs.readFileSync(path.join(home, '.claude', 'settings.local.json'), 'utf8')).hooks.PreToolUse[0].hooks[0].command.includes('--fail local'), true);
  } finally {
    if (prev === undefined) delete process.env.AGENOMIC_CONNECTOR_HOME;
    else process.env.AGENOMIC_CONNECTOR_HOME = prev;
  }
  // Hooks installed with a fixed mode are replaced by a new install, once.
  const file = path.join(tmp('agn-hooks-'), '.claude', 'settings.local.json');
  apply(planClaude(file, 'open', true));
  apply(planClaude(file, 'local', true));
  const installed = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(installed.hooks.PreToolUse.length, 1);
  assert.match(installed.hooks.PreToolUse[0].hooks[0].command, /--fail local/);
  assert.equal(planClaude(file, 'local', true).changed, false);
  apply(planClaude(file, 'local', false));
  assert.equal(fs.readFileSync(file, 'utf8'), '{}\n');
});

test('an oversized hook payload gets the structured fallback, not a crash exit', () => {
  const sock = path.join(tmp('agn-sock-'), 'state', 'missing.sock');
  const hook = (fail: string, input: string) => spawnSync(process.execPath, [BIN, 'hook', 'claude-code', '--fail', fail, '--deadline', '2000', '--socket', sock], { input, encoding: 'utf8', maxBuffer: 8 << 20 });
  const big = (event: string) => JSON.stringify({ hook_event_name: event, session_id: 's', tool_name: 'Bash', tool_input: { command: 'x'.repeat(1100 * 1024) } });
  const closed = hook('closed', big('PreToolUse'));
  assert.equal(closed.status, 0, closed.stderr);
  const out = JSON.parse(closed.stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /too large/);
  const open = hook('open', big('PreToolUse'));
  assert.equal(open.status, 0, open.stderr);
  assert.equal(open.stdout, '');
  // A large tool response after the fact is not refused as if it were a PreToolUse.
  const post = hook('closed', big('PostToolUse'));
  assert.equal(post.status, 0, post.stderr);
  assert.equal(post.stdout, '');
  assert.equal(eventOf('{"session_id":"s","hook_event_name":"PostToolUse","tool_input":{"command":"xx'), 'PostToolUse');
  assert.equal(eventOf('{"tool_input":{"command":"xx'), undefined);
});

/** Runs the hook command without blocking this process, whose daemon answers it. */
function hookAsync(args: string[], input: string): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, 'hook', ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
    child.stdin.end(input);
  });
}

test('a daemon error reply or a malformed reply takes the fail mode, never a silent pass', async () => {
  await withHome(async () => {
    // The daemon cannot register a new local session: the gateway is unreachable.
    const repo = tempRepo();
    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
    const api = new (class extends ProbeApi {
      override async request<T = any>(method: string, p: string, opts: { body?: any } = {}): Promise<T> {
        if (p === '/v1/coding/runner/sessions') throw new ApiError(0, 'network', 'POST /v1/coding/runner/sessions: gateway unavailable');
        return super.request<T>(method, p, opts);
      }
    })();
    const daemon: any = new Daemon(cfg, api);
    fs.mkdirSync(paths.state(), { recursive: true });
    await daemon.listen();
    try {
      const pre = JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'cli-new', cwd: repo, tool_name: 'Bash', tool_input: { command: 'git push --force' } });
      const args = (fail: string) => ['claude-code', '--fail', fail, '--deadline', '5000', '--socket', paths.socket()];
      const closed = await hookAsync(args('closed'), pre);
      assert.equal(closed.status, 0, closed.stderr);
      const out = JSON.parse(closed.stdout);
      assert.equal(out.hookSpecificOutput.permissionDecision, 'deny', 'fail-closed refuses explicitly');
      assert.match(out.hookSpecificOutput.permissionDecisionReason, /gateway unavailable/);
      const open = await hookAsync(args('open'), pre);
      assert.equal(open.status, 0, open.stderr);
      assert.equal(open.stdout, '', 'fail-open leaves the native flow in charge');
      const post = await hookAsync(args('closed'), JSON.stringify({ hook_event_name: 'PostToolUse', session_id: 'cli-new', cwd: repo, tool_name: 'Bash' }));
      assert.equal(post.stdout, '', 'only a PreToolUse is refused');
    } finally {
      daemon.server.close();
    }
  });
  // Replies of a daemon that does not answer as expected.
  const pre = JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', tool_name: 'Bash', tool_input: { command: 'ls' } });
  const deny = { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'Agenomic: policy' } };
  const cases: [string, 'deny' | 'none' | 'passed'][] = [
    ['{"error":"boom"}', 'deny'], ['{"error":{"code":"x"}}', 'deny'], ['[]', 'deny'], ['null', 'deny'], ['"ok"', 'deny'],
    ['{"output":"allow"}', 'deny'], ['{"output":[]}', 'deny'], ['not json', 'deny'], ['{}', 'none'], [JSON.stringify({ output: deny }), 'passed'],
  ];
  for (const [reply, expected] of cases) {
    const sock = path.join(tmp('agn-sock-'), 'state', 'connector.sock');
    fs.mkdirSync(path.dirname(sock));
    const server = net.createServer((c) => c.once('data', () => c.end(reply + '\n')));
    await new Promise<void>((resolve) => server.listen(sock, resolve));
    try {
      const r = await hookAsync(['codex', '--fail', 'closed', '--deadline', '5000', '--socket', sock], pre);
      assert.equal(r.status, 0, r.stderr);
      if (expected === 'none') assert.equal(r.stdout, '', reply);
      else if (expected === 'passed') assert.deepEqual(JSON.parse(r.stdout), deny, reply);
      else {
        const out = JSON.parse(r.stdout).hookSpecificOutput;
        assert.equal(out.permissionDecision, 'deny', reply);
        assert.match(out.permissionDecisionReason, /^Agenomic connector unavailable/, reply);
      }
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  }
});

class FlakyApi extends RunnerApi {
  up = false;
  sent: any[] = [];
  constructor() {
    super('http://127.0.0.1:9', { access_token: 'agmrt_secretsecretsecretsecretsecret', refresh_token: 'r', access_expires_at: new Date(Date.now() + 3600e3).toISOString(), refresh_expires_at: new Date(Date.now() + 3600e3).toISOString() }, false);
  }
  override async request<T>(_m: string, _p: string, opts: { body?: any } = {}): Promise<T> {
    if (!this.up) throw new Error('offline');
    this.sent.push(...opts.body.events);
    return {} as T;
  }
}

test('event sink: bounded memory, evidence spooled to disk while offline, then delivered in order', async () => {
  const api = new FlakyApi();
  const spool = tmp('agn-spool-');
  const sink = new EventSink(api, 'session-1', () => ['agmrt_secretsecretsecretsecretsecret'], spool, { maxBuffered: 10, maxSpoolBytes: 1 << 20, batchSize: 5, flushIntervalMs: 60000 });
  for (let i = 0; i < 30; i++) sink.emit(i % 2 ? 'tool.started' : 'message.assistant', 'runtime', 'native', { i, leak: 'key agmrt_secretsecretsecretsecretsecret' });
  await sink.flush();
  assert.ok(sink.pending() <= 10, 'memory stays bounded');
  api.up = true;
  await sink.flush();
  await sink.close();
  const tools = api.sent.filter((e) => e.type === 'tool.started').map((e) => e.payload.i);
  assert.deepEqual(tools, [...tools].sort((a, b) => a - b), 'evidence keeps its order');
  assert.equal(tools.length, 15, 'no evidence event was lost');
  assert.ok(api.sent.some((e) => e.type === 'error' && e.payload.code === 'events_dropped'), 'dropped telemetry is reported, not silent');
  assert.ok(!JSON.stringify(api.sent).includes('secretsecret'), 'redacted before buffering');
  const seqs = api.sent.map((e) => e.producer_seq);
  assert.equal(new Set(seqs).size, seqs.length, 'producer sequence numbers are unique');
});

/** A runner API whose event sends wait until the test settles them. */
class GatedApi extends RunnerApi {
  hold = true;
  sent: any[] = [];
  /** The batches whose send is waiting. */
  waiting: any[][] = [];
  private readonly gates: ((ok: boolean) => void)[] = [];
  constructor() {
    super('http://127.0.0.1:9', { access_token: 'a', refresh_token: 'r', access_expires_at: new Date(Date.now() + 3600e3).toISOString(), refresh_expires_at: new Date(Date.now() + 3600e3).toISOString() }, false);
  }
  override async request<T>(_m: string, _p: string, opts: { body?: any } = {}): Promise<T> {
    if (this.hold) this.waiting.push(opts.body.events);
    if (this.hold && !(await new Promise<boolean>((resolve) => this.gates.push(resolve)))) throw new Error('offline');
    this.sent.push(...opts.body.events);
    return {} as T;
  }
  async inFlight(): Promise<void> {
    while (this.gates.length === 0) await sleep(5);
  }
  /** Lets the send in flight succeed or fail; later sends no longer wait. */
  settle(ok: boolean): void {
    this.hold = false;
    this.gates.shift()!(ok);
  }
}

test('event sink: a burst during a slow send neither loses nor duplicates evidence', async () => {
  for (const inFlight of ['queue batch', 'spool batch'] as const) {
    for (const ok of [true, false]) {
      const at = `${inFlight}, send ${ok ? 'succeeds' : 'fails'}`;
      const api = new GatedApi();
      const sink = new EventSink(api, randomUUID(), () => [], tmp('agn-spool-'), { maxBuffered: 6, maxSpoolBytes: 1 << 20, batchSize: 3, flushIntervalMs: 60000 });
      const emitted: any[] = [];
      // Evidence (tool.started) and droppable telemetry (message.assistant).
      const burst = (n: number) => {
        for (let i = 0; i < n; i++) emitted.push(sink.emit(emitted.length % 3 === 1 ? 'message.assistant' : 'tool.started', 'runtime', 'native', { i: emitted.length }));
      };
      // queue batch: three events start a flush, sent from the queue.
      // spool batch: ten events overflow the queue first, so the flush
      // starts with the evidence spilled to disk.
      burst(inFlight === 'queue batch' ? 3 : 10);
      await api.inFlight();
      const first = api.waiting[0]!.map((e) => e.event_id);
      assert.deepEqual(first, inFlight === 'queue batch' ? emitted.slice(0, 3).map((e) => e.event_id) : [emitted[0].event_id], `${at}: the batch in flight`);
      // A burst well over maxBuffered while that batch is in flight.
      burst(20);
      api.settle(ok);
      await sink.flush();
      await sink.close();
      assert.equal(sink.pending(), 0, at);
      const ids = api.sent.map((e) => e.event_id);
      assert.equal(new Set(ids).size, ids.length, `${at}: no event is delivered twice`);
      const evidence = emitted.filter((e) => e.type === 'tool.started');
      const delivered = api.sent.filter((e) => e.type === 'tool.started');
      assert.deepEqual(delivered.map((e) => e.event_id).sort(), evidence.map((e) => e.event_id).sort(), `${at}: every evidence event is delivered`);
      const seqs = delivered.map((e) => e.producer_seq);
      assert.deepEqual(seqs, [...seqs].sort((a, b) => a - b), `${at}: evidence keeps its order`);
      const lost = emitted.filter((e) => e.type === 'message.assistant' && !ids.includes(e.event_id)).length;
      const reported = api.sent.filter((e) => e.type === 'error' && e.payload.code === 'events_dropped').reduce((n, e) => n + e.payload.count, 0);
      assert.equal(reported, lost, `${at}: every dropped event is counted`);
    }
  }
});

test('workspace: dedicated worktree, existing branches and human changes untouched', () => {
  const repo = tmp('agn-ws-');
  const git = (...a: string[]) => execFileSync('git', ['-C', repo, ...a], { encoding: 'utf8' });
  git('init', '-q', '-b', 'main');
  fs.writeFileSync(path.join(repo, 'a.txt'), 'a\n');
  git('add', '.');
  git('-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'init');
  git('branch', 'taken');
  fs.writeFileSync(path.join(repo, 'a.txt'), 'human edit\n');
  fs.writeFileSync(path.join(repo, 'untracked.txt'), 'human\n');
  const target = path.join(tmp('agn-wt-'), 'session');
  assert.throws(() => ws.createWorktree(repo, target, 'taken'), /already exists/);
  const tree = ws.createWorktree(repo, target, 'agenomic/new');
  assert.deepEqual(tree.preexisting_changes.sort(), ['a.txt', 'untracked.txt']);
  fs.writeFileSync(path.join(target, 'b.txt'), 'b\n');
  const changes = ws.changes(target, tree.base_revision!);
  assert.deepEqual(changes.map((c) => [c.path, c.status]), [['b.txt', 'untracked']]);
  assert.equal(fs.readFileSync(path.join(repo, 'a.txt'), 'utf8'), 'human edit\n');
  assert.equal(fs.readFileSync(path.join(repo, 'untracked.txt'), 'utf8'), 'human\n');
});

test('workspace: a captured diff includes untracked files as additions; ignored ones and the real index are untouched', () => {
  const repo = tmp('agn-ws-');
  const git = (...a: string[]) => execFileSync('git', ['-C', repo, ...a], { encoding: 'utf8' });
  git('init', '-q', '-b', 'main');
  fs.writeFileSync(path.join(repo, 'a.txt'), 'a\n');
  fs.writeFileSync(path.join(repo, '.gitignore'), '*.log\n');
  git('add', '.');
  git('-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'init');
  const base = git('rev-parse', 'HEAD').trim();
  fs.writeFileSync(path.join(repo, 'a.txt'), 'a edited\n');
  fs.mkdirSync(path.join(repo, 'src'));
  fs.writeFileSync(path.join(repo, 'src', 'new file*.ts'), 'export const key = "agmrt_secretsecretsecretsecretsecret";\n');
  fs.writeFileSync(path.join(repo, 'blob.bin'), Buffer.from([0, 1, 2, 0]));
  // Over the bytes a diff reads (the cap plus the redaction slack).
  fs.writeFileSync(path.join(repo, 'huge.txt'), 'x'.repeat(80 * 1024));
  fs.writeFileSync(path.join(repo, 'debug.log'), 'ignored\n');
  const before = git('status', '--porcelain=v1');
  const d = ws.diff(repo, base, ['agmrt_secretsecretsecretsecretsecret'], 8 * 1024);
  assert.match(d.text, /diff --git a\/a\.txt b\/a\.txt[\s\S]*\+a edited/, 'tracked changes are still there');
  assert.match(d.text, /diff --git a\/src\/new file\*\.ts b\/src\/new file\*\.ts\nnew file mode 100644[\s\S]*\+\+\+ b\/src\/new file\*\.ts\t?\n@@ -0,0 \+1 @@\n\+export const key/, 'an untracked file is an addition with its content');
  assert.ok(!d.text.includes('secretsecret'), 'untracked content is redacted');
  assert.match(d.text, /Binary files \/dev\/null and b\/blob\.bin differ/, 'a binary untracked file is summarised by git');
  assert.match(d.text, /b\/huge\.txt\nnew file mode 100644\n\(untracked file of 81920 bytes, not captured\)/, 'an untracked file over the cap is named, not read');
  assert.ok(!d.text.includes('debug.log'), 'ignored files stay out');
  assert.equal(git('status', '--porcelain=v1'), before, 'the checkout\'s own index is untouched');
  const listed = ws.changes(repo, base).map((c) => c.path).filter((p) => p !== 'a.txt').sort();
  for (const file of listed) assert.ok(d.text.includes(`b/${file}`), `${file}: every untracked file listed by changes() is in the diff`);
});

test('workspace: many untracked files are read only up to the bytes a diff keeps; the rest are named, not captured', () => {
  const repo = tmp('agn-ws-');
  try {
    const git = (...a: string[]) => execFileSync('git', ['-C', repo, ...a], { encoding: 'utf8' });
    git('init', '-q', '-b', 'main');
    git('-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '--allow-empty', '-m', 'init');
    const base = git('rev-parse', 'HEAD').trim();
    // Each file fits in the bytes read; together they are over git's 64 MiB output buffer.
    const line = 'generated data line\n';
    const content = line.repeat(Math.ceil((230 * 1024) / line.length));
    for (let i = 0; i < 300; i++) fs.writeFileSync(path.join(repo, `data-${String(i).padStart(3, '0')}.txt`), content);
    assert.equal(ws.changes(repo, base).length, 300);
    const d = ws.diff(repo, base);
    assert.equal(d.truncated, true);
    assert.ok(d.text.length <= 256 * 1024);
    assert.match(d.text, /\+\+\+ b\/data-000\.txt\n@@ -0,0 \+1,\d+ @@\n\+generated data line\n/, 'the first files are captured');
    assert.match(d.text, new RegExp(`diff --git a/data-001\\.txt b/data-001\\.txt\\nnew file mode 100644\\n\\(untracked file of ${content.length} bytes, not captured\\)`), 'the files past the bytes read are named');
    assert.ok(!d.text.includes('b/data-001.txt\n@@'), 'no file past the bytes read is diffed');
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('workspace: an untracked file named, not captured, has its path quoted as git quotes it', () => {
  assert.equal(ws.quotePath('src/new file*.ts'), 'src/new file*.ts', 'a name git leaves as is');
  const repo = tmp('agn-ws-');
  const git = (...a: string[]) => execFileSync('git', ['-C', repo, ...a], { encoding: 'utf8' });
  git('init', '-q', '-b', 'main');
  // git's own quoting of the same names, as a tracked addition shows them.
  const names = ['new\nline', 'tab\there', 'q"uote', 'back\\slash', 'caf\u00e9', 'del\u007f', 'plain name'];
  for (const n of names) fs.writeFileSync(path.join(repo, n), 'x\n');
  git('add', '.');
  const quoted = git('-c', 'core.quotePath=true', 'ls-files').split('\n').filter(Boolean).sort();
  assert.deepEqual(names.map((n) => ws.quotePath(n)).sort(), quoted);
  git('-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'init');
  const base = git('rev-parse', 'HEAD').trim();
  // A name forging a hunk, over the bytes read.
  const forged = 'x\n@@ -0,0 +1 @@\n+forged';
  fs.writeFileSync(path.join(repo, forged), 'y'.repeat(80 * 1024));
  const d = ws.diff(repo, base, [], 8 * 1024);
  assert.ok(d.text.startsWith('diff --git "a/x\\n@@ -0,0 +1 @@\\n+forged" "b/x\\n@@ -0,0 +1 @@\\n+forged"\nnew file mode 100644\n(untracked file of 81920 bytes, not captured)\n'), d.text);
  assert.ok(!d.text.split('\n').includes('+forged'), 'the name adds no line of its own');
});

test('workspace: a diff larger than any buffer is read only up to its window; the snapshot keeps its file list', () => {
  const repo = tempRepo();
  const base = execFileSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  // Past the 64 MiB a buffered read accepted.
  const line = 'y'.repeat(99) + '\n';
  const fd = fs.openSync(path.join(repo, 'README.md'), 'w');
  const chunk = line.repeat(10000);
  for (let i = 0; i < 70; i++) fs.writeSync(fd, chunk);
  fs.closeSync(fd);
  try {
    const d = ws.diff(repo, base);
    assert.equal(d.truncated, true);
    assert.equal(d.text.length, 256 * 1024);
    const snap = ws.snapshot(repo, base, true);
    assert.deepEqual((snap.files as ws.FileChange[]).find((f) => f.path === 'README.md'), { path: 'README.md', status: 'modified', added: 700000, deleted: 1 });
    assert.equal(snap.truncated, true);
    assert.equal((snap.diff as string).length, 256 * 1024);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('workspace: a change set larger than a listing reads lists the files that fit; a snapshot is made even when no list can be read', () => {
  const repo = tempRepo();
  const base = execFileSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  try {
    for (let i = 0; i < 200; i++) fs.writeFileSync(path.join(repo, `file-${String(i).padStart(3, '0')}-${'n'.repeat(40)}.txt`), 'x\n');
    fs.writeFileSync(path.join(repo, 'README.md'), 'changed\n');
    const all = ws.changes(repo, base);
    assert.equal(all.length, 202);
    // Each listing is read up to 2 KiB: the files that fit, whole names only.
    const some = ws.changes(repo, base, 2048);
    assert.ok(some.length > 1 && some.length < all.length, String(some.length));
    for (const f of some) assert.ok(all.some((a) => a.path === f.path), f.path);
    assert.deepEqual(some.find((f) => f.path === 'README.md'), { path: 'README.md', status: 'modified', added: 1, deleted: 1 });
    // A base git cannot read: the snapshot is still made, with the reasons.
    const snap = ws.snapshot(repo, '0'.repeat(40), true);
    assert.deepEqual(snap.files, []);
    assert.match(String(snap.files_error), /git diff failed/);
    assert.equal(snap.diff, null);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('workspace: a verbose stderr of a diff that succeeds is not read as a cut diff', () => {
  const repo = tempRepo();
  const git = (...a: string[]) => execFileSync('git', ['-C', repo, ...a], { encoding: 'utf8' });
  const base = git('rev-parse', 'HEAD').trim();
  // A clean filter that writes 1 MiB to stderr each time git reads a file.
  git('config', 'filter.noisy.clean', "head -c 1048576 /dev/zero | tr '\\000' w 1>&2; cat");
  fs.writeFileSync(path.join(repo, '.git', 'info', 'attributes'), '* filter=noisy\n');
  fs.writeFileSync(path.join(repo, 'README.md'), 'probe\nchanged\n');
  try {
    const d = ws.diff(repo, base, [], 8 * 1024);
    assert.equal(d.truncated, false, d.text);
    assert.match(d.text, /^\+changed$/m);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('symlink escapes are detected on the real path', () => {
  const root = tmp('agn-root-');
  const outside = tmp('agn-out-');
  fs.symlinkSync(outside, path.join(root, 'link'));
  assert.equal(realPathEscapes('link/secret', root, root), true);
  assert.equal(realPathEscapes('src/new.txt', root, root), false);
});

test('test commands are recognised, quoted or not; the signal stays derived', () => {
  assert.ok(isTestCommand("/bin/bash -lc 'node --test'"));
  assert.ok(isTestCommand('cargo test -p x'));
  assert.ok(!isTestCommand('echo testing'));
});

/** An executable that prints `line` for `--version`. */
function fakeBinary(line: string): string {
  const file = path.join(tmp('agn-bin-'), 'runtime');
  fs.writeFileSync(file, `#!/bin/sh\necho '${line}'\n`, { mode: 0o755 });
  return file;
}

test('a configured runtime executable reports its own version; a probe of another binary does not validate it', async () => {
  const home = tmp('agn-home-');
  const prev = process.env.AGENOMIC_CONNECTOR_HOME;
  process.env.AGENOMIC_CONNECTOR_HOME = home;
  try {
    const claude = fakeBinary('9.8.7 (Claude Code)');
    const codex = fakeBinary('codex-cli 1.2.3');
    const rt = (executable?: string) => ({ enabled: true, executable, env_passthrough: [], extra_env: {}, allowed_domains: [] });
    assert.equal(claudeCodeVersion(rt(claude)), undefined, 'not read yet: never waited for');
    assert.equal(await readClaudeCodeVersion(rt(claude)), '9.8.7');
    assert.equal(claudeCodeVersion(rt(claude)), '9.8.7', 'cached once read');
    assert.equal(claudeCodeVersion(rt()), sdkPackage()!.claudeCodeVersion, 'the bundled binary: the version the SDK pins');
    assert.equal(await readCodexVersion(rt(codex)), '1.2.3');
    assert.equal(codexVersion(rt(path.join(home, 'missing'))), null);
    assert.equal(await readCodexVersion(rt(fakeBinary('no version here'))), null);

    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    const api = new RunnerApi('http://127.0.0.1:9', { access_token: 'a', refresh_token: 'r', access_expires_at: new Date(Date.now() + 3600e3).toISOString(), refresh_expires_at: new Date(Date.now() + 3600e3).toISOString() }, false);
    // Probes of the bundled binaries, as `doctor --probe` with the default configuration records them.
    const ok = { ok: true, detail: 'probe' };
    saveProbe({ runtime: 'claude_code', surface: 'sdk', version: sdkPackage()!.claudeCodeVersion!, at: '', results: { observe: ok } });
    saveProbe({ runtime: 'codex', surface: 'app_server', version: codexVersion(rt())!, at: '', results: { observe: ok } });
    const bundled = new Daemon(cfg, api).runtimes();
    assert.equal(bundled.find((r) => r.runtime === 'claude_code').capabilities.observe.validated, 'supported_tested');
    assert.equal(bundled.find((r) => r.runtime === 'codex').capabilities.observe.validated, 'supported_tested');

    cfg.runtimes.claude_code.executable = claude;
    cfg.runtimes.codex.executable = codex;
    const custom = new Daemon(cfg, api).runtimes();
    const cc = custom.find((r) => r.runtime === 'claude_code');
    const cx = custom.find((r) => r.runtime === 'codex');
    assert.equal(cc.version, '9.8.7');
    assert.equal(cc.capabilities.observe.validated, 'unknown', 'the bundled binary probe does not validate a custom one');
    assert.ok(cx, 'a custom Codex executable stays in the heartbeat');
    assert.equal(cx.version, '1.2.3');
    assert.equal(cx.capabilities.observe.validated, 'unknown');
    saveProbe({ runtime: 'claude_code', surface: 'sdk', version: '9.8.7', at: '', results: { observe: ok } });
    assert.equal(new Daemon(cfg, api).runtimes().find((r) => r.runtime === 'claude_code').capabilities.observe.validated, 'supported_tested');

    // A binary that cannot tell its version is listed, with nothing validated.
    cfg.runtimes.codex.executable = fakeBinary('no version here');
    await readCodexVersion(cfg.runtimes.codex);
    const unknown = new Daemon(cfg, api).runtimes().find((r) => r.runtime === 'codex');
    assert.equal(unknown.version, 'unknown');
    assert.equal(unknown.capabilities.observe.validated, 'unknown');
  } finally {
    if (prev === undefined) delete process.env.AGENOMIC_CONNECTOR_HOME;
    else process.env.AGENOMIC_CONNECTOR_HOME = prev;
  }
});

test('a slow --version never delays a heartbeat or a hook reply', async () => {
  await withHome(async () => {
    const repo = tempRepo();
    const slow = path.join(tmp('agn-bin-'), 'codex');
    fs.writeFileSync(slow, "#!/bin/sh\nsleep 2\necho 'codex-cli 7.7.7'\n", { mode: 0o755 });
    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
    cfg.runtimes.codex.executable = slow;
    const api = new (class extends ProbeApi {
      heartbeats: any[] = [];
      override async request<T = any>(method: string, p: string, opts: { body?: any } = {}): Promise<T> {
        if (p.endsWith('/heartbeat')) this.heartbeats.push(opts.body);
        return super.request<T>(method, p, opts);
      }
    })();
    const daemon: any = new Daemon(cfg, api);
    const codexOf = (beat: any) => beat.runtimes.find((r: any) => r.runtime === 'codex');
    // The event loop keeps turning while `--version` runs.
    let ticks = 0;
    const ticker = setInterval(() => ticks++, 20);
    try {
      let t = Date.now();
      await daemon.start();
      assert.ok(Date.now() - t < 1000, `start and its first heartbeat took ${Date.now() - t} ms`);
      assert.equal(codexOf(api.heartbeats[0]).version, 'unknown', 'not known yet');
      assert.equal(codexOf(api.heartbeats[0]).capabilities.observe.validated, 'unknown');
      t = Date.now();
      const reply = await daemon.onLocal({ op: 'hook', runtime: 'codex', input: { hook_event_name: 'PreToolUse', session_id: 'thread-slow', cwd: repo, tool_use_id: 'call_1', tool_name: 'Bash', tool_input: { command: 'ls' } } });
      assert.deepEqual(reply, {});
      assert.ok(Date.now() - t < 1000, `the first hook of a new local session took ${Date.now() - t} ms`);
      t = Date.now();
      await daemon.heartbeat();
      assert.ok(Date.now() - t < 1000, `a heartbeat took ${Date.now() - t} ms`);
      // Once `--version` has answered, one more heartbeat reports it.
      const deadline = Date.now() + 10000;
      while (!api.heartbeats.some((b) => codexOf(b).version === '7.7.7') && Date.now() < deadline) await sleep(50);
      assert.equal(codexOf(api.heartbeats.at(-1)).version, '7.7.7');
      assert.ok(ticks >= 50, `the event loop turned ${ticks} times in 2 s`);
    } finally {
      clearInterval(ticker);
      await daemon.stop();
    }
  });
});

test('doctor --probe runs the machine\'s configured runtimes: enabled ones, their executable, its version', async () => {
  const machine = defaultConfig('https://api.example.test', 'unit');
  machine.runtimes.codex.executable = fakeBinary('codex-cli 4.5.6');
  machine.runtimes.codex.env_passthrough = ['OPENAI_API_KEY'];
  machine.runtimes.codex.extra_config_toml = 'model_provider = "corp"';
  machine.runtimes.claude_code.allowed_domains = ['registry.npmjs.org'];
  const codex = probeConfig(machine, 'codex', 'http://127.0.0.1:1', '/tmp/repo');
  assert.equal(codex.runtimes.codex.executable, machine.runtimes.codex.executable);
  assert.deepEqual(codex.runtimes.codex.env_passthrough, [], 'no provider credential reaches the scripted model');
  assert.match(codex.runtimes.codex.extra_config_toml!, /agenomic_scripted/);
  assert.doesNotMatch(codex.runtimes.codex.extra_config_toml!, /corp/);
  assert.equal(codex.runtimes.claude_code.enabled, false);
  assert.equal(await probedVersion(codex, 'codex'), '4.5.6', 'recorded under the version of the binary that ran');
  const claude = probeConfig(machine, 'claude_code', 'http://127.0.0.1:1', '/tmp/repo');
  assert.equal(claude.runtimes.claude_code.executable, undefined);
  assert.deepEqual(claude.runtimes.claude_code.allowed_domains, ['registry.npmjs.org']);
  assert.equal(await probedVersion(claude, 'claude_code'), sdkPackage()!.claudeCodeVersion);
  // Disabled runtimes are not probed at all.
  machine.runtimes.codex.enabled = false;
  machine.runtimes.claude_code.enabled = false;
  assert.deepEqual(await runProbe(machine), []);
});

/** Runs `fn` with the connector home set to a fresh directory. */
async function withHome<T>(fn: (home: string) => Promise<T> | T): Promise<T> {
  const home = tmp('agn-home-');
  const prev = process.env.AGENOMIC_CONNECTOR_HOME;
  process.env.AGENOMIC_CONNECTOR_HOME = home;
  try {
    return await fn(home);
  } finally {
    if (prev === undefined) delete process.env.AGENOMIC_CONNECTOR_HOME;
    else process.env.AGENOMIC_CONNECTOR_HOME = prev;
  }
}

/** A daemon-managed session context and a Codex adapter around it, without a process. */
function codexHarness(cfg = defaultConfig('http://127.0.0.1:9', 'unit'), mode: 'observe' | 'shadow' | 'enforce' = 'enforce', capture = { conversation: true, commands: true, diffs: false, outputs: true }) {
  const api = new ProbeApi();
  const daemon = new Daemon(cfg, api);
  const m = (daemon as any).manage(randomUUID(), 'codex', 'launched', mode, capture, tmp('agn-wt-'), null);
  const codex = new CodexSession({ ctx: m.ctx, cwd: m.cwd, runtime: cfg.runtimes.codex, onNativeSession: async () => undefined, onStatus: () => undefined });
  return { api, daemon, ctx: m.ctx as SessionContext, codex: codex as any };
}

test('captured Codex content is redacted with every runtime credential value, before it is bounded', async () => {
  await withHome(async () => {
    const passthrough = 'corp-provider-credential-7f3a9b2c4d5e';
    const extra = 'corp-gateway-credential-0a1b2c3d4e5f';
    process.env.AGN_UNIT_PROVIDER_CREDENTIAL = passthrough;
    try {
      const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
      cfg.runtimes.codex.env_passthrough = ['AGN_UNIT_PROVIDER_CREDENTIAL'];
      cfg.runtimes.codex.extra_env = { CORP_GATEWAY_TOKEN: extra, CORP_BASE_URL: 'http://gateway.corp.example:8080' };
      assert.deepEqual(runtimeSecrets(cfg.runtimes.codex), [passthrough, extra], 'non secret extra_env values are not redacted');
      const { api, ctx, codex } = codexHarness(cfg);
      codex.onNotification('item/started', { turnId: 't1', item: { type: 'commandExecution', id: 'call_1', command: `curl -H ${extra} gateway` } });
      // The secret straddles the output bound: redacted first, it cannot leave a prefix behind.
      codex.onNotification('item/completed', { turnId: 't1', item: { type: 'commandExecution', id: 'call_1', command: `curl -H ${extra} gateway`, status: 'completed', exitCode: 0, aggregatedOutput: 'x'.repeat(3990) + passthrough } });
      codex.onNotification('item/completed', { turnId: 't1', item: { type: 'agentMessage', id: 'msg_1', text: `the key is ${passthrough}` } });
      await ctx.sink.close();
      const shipped = JSON.stringify(api.events);
      for (const secret of [passthrough, extra]) assert.ok(!shipped.includes(secret.slice(0, 10)), `${secret.slice(0, 10)} leaked`);
      const done = api.events.find((e) => e.type === 'tool.completed');
      assert.match(done.payload.output, /\[REDACTED\]$/);
      assert.match(done.payload.command, /curl -H \[REDACTED\] gateway/);
    } finally {
      delete process.env.AGN_UNIT_PROVIDER_CREDENTIAL;
    }
  });
});

test('a diff snapshot is redacted before it is cut: a secret across the cut leaves no prefix behind', async () => {
  await withHome(async () => {
    const credential = 'corp-provider-credential-7f3a9b2c4d5e';
    process.env.AGN_UNIT_DIFF_CREDENTIAL = credential;
    try {
      const repo = tempRepo();
      const git = (...a: string[]) => execFileSync('git', ['-C', repo, ...a], { encoding: 'utf8', maxBuffer: 64 << 20 });
      const base = git('rev-parse', 'HEAD').trim();
      const CUT = 256 * 1024;
      /** Rewrites README.md so that `secret` starts 6 characters before the cut of the diff. */
      const straddle = (secret: string) => {
        const write = (pad: number) => fs.writeFileSync(path.join(repo, 'README.md'), 'x'.repeat(pad) + ' ' + secret + '\n');
        write(1000);
        const header = git('diff', '-M', base).indexOf(secret) - 1000;
        write(CUT - 6 - header);
        const at = git('diff', '-M', base).indexOf(secret);
        assert.ok(at < CUT && at + secret.length > CUT, 'the secret straddles the cut');
      };
      const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
      cfg.runtimes.codex.env_passthrough = ['AGN_UNIT_DIFF_CREDENTIAL'];
      cfg.runtimes.claude_code.env_passthrough = ['AGN_UNIT_DIFF_CREDENTIAL'];
      const capture = { conversation: false, commands: false, diffs: true, outputs: false };
      // A runtime credential value, and a token recognised by its pattern only.
      for (const secret of [credential, 'ghp_abcdefghijklmnopqrstuvwxyz0123']) {
        straddle(secret);
        const d = ws.diff(repo, base, [credential]);
        assert.equal(d.truncated, true);
        assert.equal(d.text.length, CUT);
        assert.match(d.text, /\[REDAC$/, 'redacted, then cut');
        assert.ok(!d.text.includes(secret.slice(0, 6)), `${secret.slice(0, 6)} leaked`);
        // As both adapters ship it.
        const api = new ProbeApi();
        const daemon: any = new Daemon(cfg, api);
        const cx = daemon.manage(randomUUID(), 'codex', 'launched', 'enforce', capture, repo, base);
        new CodexSession({ ctx: cx.ctx, cwd: repo, runtime: cfg.runtimes.codex, onNativeSession: async () => undefined, onStatus: () => undefined } as any)['snapshotDiff']('t1');
        const cc = daemon.manage(randomUUID(), 'claude_code', 'launched', 'enforce', capture, repo, base);
        new ClaudeSession({ ctx: cc.ctx, cwd: repo, runtime: cfg.runtimes.claude_code, onNativeSession: async () => undefined, onStatus: () => undefined } as any)['snapshotDiff']();
        await cx.ctx.sink.close();
        await cc.ctx.sink.close();
        const snapshots = api.events.filter((e) => e.type === 'diff.snapshot');
        assert.equal(snapshots.length, 2);
        for (const e of snapshots) {
          assert.equal(e.payload.truncated, true);
          assert.match(e.payload.diff, /\[REDAC$/);
          assert.ok(!e.payload.diff.includes(secret.slice(0, 6)), `${secret.slice(0, 6)} leaked`);
        }
      }
    } finally {
      delete process.env.AGN_UNIT_DIFF_CREDENTIAL;
    }
  });
});

test('a Codex executable that cannot be spawned refuses the launch; the daemon stays up', async () => {
  await withHome(async (home) => {
    const repo = tempRepo();
    const missing = path.join(home, 'missing', 'codex');
    const notExecutable = path.join(tmp('agn-bin-'), 'codex');
    fs.writeFileSync(notExecutable, 'not a program\n', { mode: 0o644 });
    // observe spawns the App Server directly; shadow and enforce first ask
    // the binary for its hooks.
    const cases = [[missing, 'observe', /ENOENT/], [missing, 'enforce', /ENOENT/], [notExecutable, 'observe', /EACCES/], [notExecutable, 'shadow', /EACCES/]] as const;
    for (const [executable, mode, why] of cases) {
      const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
      cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
      cfg.runtimes.codex.executable = executable;
      const api = new ProbeApi();
      const daemon = new Daemon(cfg, api);
      const session = randomUUID();
      const launch = ulid();
      await daemon.handleCommand({ id: launch, kind: 'launch', coding_session_id: session, payload: { runtime: 'codex', workspace_id: 'w', mode } });
      const r = api.results.get(launch);
      assert.equal(r?.status, 'refused', `${mode} ${executable}`);
      assert.match(r.error, /codex could not be started/);
      assert.match(r.error, why);
      // A late 'error' event would surface here as an uncaught exception.
      await sleep(100);
      const send = ulid();
      await daemon.handleCommand({ id: send, kind: 'send_message', coding_session_id: session, payload: { text: 'hello' } });
      assert.equal(api.results.get(send)?.status, 'refused');
    }
  });
});

test('a launch or resume whose start fails after the spawn stops the process and unmanages the session', async () => {
  await withHome(async () => {
    const repo = tempRepo();
    // An App Server that starts a thread; the session registration that follows times out.
    const bin = tmp('agn-bin-');
    const fake = path.join(bin, 'codex.js');
    const pidFile = path.join(bin, 'pid');
    fs.writeFileSync(fake, [
      "const fs = require('node:fs');",
      "fs.writeFileSync(process.env.FAKE_PID_FILE, String(process.pid));",
      "const rl = require('node:readline').createInterface({ input: process.stdin });",
      "rl.on('line', (line) => {",
      '  const m = JSON.parse(line);',
      '  if (m.id === undefined) return;',
      "  const result = m.method === 'initialize' ? { userAgent: 'fake' } : m.method.startsWith('thread/') ? { thread: { id: 'thread-fake' } } : {};",
      "  process.stdout.write(JSON.stringify({ id: m.id, result }) + '\\n');",
      '});',
      "rl.on('close', () => process.exit(0));",
    ].join('\n'));
    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
    cfg.runtimes.codex.executable = fake;
    cfg.runtimes.codex.extra_env = { FAKE_PID_FILE: pidFile };
    const api = new (class extends ProbeApi {
      override async request<T = any>(method: string, p: string, opts: { body?: any } = {}): Promise<T> {
        if (p === '/v1/coding/runner/sessions') throw new ApiError(0, 'timeout', 'POST /v1/coding/runner/sessions timed out');
        return super.request<T>(method, p, opts);
      }
    })();
    const daemon: any = new Daemon(cfg, api);
    const session = randomUUID();
    const command = async (kind: string, payload: unknown = {}) => {
      const id = ulid();
      await daemon.handleCommand({ id, kind, coding_session_id: session, payload });
      return api.results.get(id);
    };
    const alive = (pid: number) => {
      try {
        process.kill(pid, 0);
        return true;
      } catch {
        return false;
      }
    };
    const pids: number[] = [];
    try {
      for (const kind of ['launch', 'resume_session'] as const) {
        fs.rmSync(pidFile, { force: true });
        if (kind === 'resume_session') {
          // The refused launch left no record: the resume is of a session
          // this runner launched earlier.
          assert.equal(daemon.persisted[session], undefined);
          daemon.persisted[session] = { runtime: 'codex', cwd: repo, base_revision: null, native_id: 'thread-fake', mode: 'observe', capture: { conversation: false, commands: false, diffs: false, outputs: false } };
        }
        const r = await command(kind, kind === 'launch' ? { runtime: 'codex', workspace_id: 'w', mode: 'observe' } : {});
        assert.equal(r?.status, 'refused', kind);
        assert.match(r.error, /sessions timed out/, kind);
        const pid = Number(fs.readFileSync(pidFile, 'utf8'));
        pids.push(pid);
        assert.equal(alive(pid), false, `${kind}: the spawned App Server was stopped`);
        assert.equal(daemon.sessions.has(session), false, `${kind}: the session is no longer managed`);
        assert.equal(daemon.byNative.size, 0);
        for (const next of ['send_message', 'interrupt_turn', 'stop_process']) {
          assert.equal((await command(next, { text: 'hello' }))?.status, 'refused', `${kind}, then ${next}`);
        }
      }
      assert.ok(api.states.some((s) => s.status === 'failed'), 'the launch is reported failed');
    } finally {
      for (const pid of pids) if (alive(pid)) process.kill(pid, 'SIGKILL');
    }
  });
});

test('a Claude Code launch is applied only once the runtime initialized and its native session is registered', { timeout: 120000 }, async () => {
  await withHome(async () => {
    const repo = tempRepo();
    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
    cfg.runtimes.claude_code.extra_env = { ANTHROPIC_BASE_URL: 'http://127.0.0.1:9' };
    const registered: any[] = [];
    const api = new (class extends ProbeApi {
      override async request<T = any>(method: string, p: string, opts: { body?: any } = {}): Promise<T> {
        if (p === '/v1/coding/runner/sessions') {
          registered.push(opts.body);
          return { session: {} } as T;
        }
        return super.request<T>(method, p, opts);
      }
    })();
    const launch = async (daemon: any, session: string) => {
      const id = ulid();
      await daemon.handleCommand({ id, kind: 'launch', coding_session_id: session, payload: { runtime: 'claude_code', workspace_id: 'w', mode: 'observe' } });
      return api.results.get(id);
    };
    // A runtime that cannot start: refused, not applied with no native id.
    cfg.runtimes.claude_code.executable = path.join(tmp('agn-bin-'), 'missing-claude');
    const broken: any = new Daemon(cfg, api);
    const failed = randomUUID();
    const r1 = await launch(broken, failed);
    assert.equal(r1?.status, 'refused', JSON.stringify(r1));
    assert.match(r1.error, /missing-claude/);
    assert.equal(broken.sessions.has(failed), false);
    assert.equal(registered.length, 0);
    // The bundled runtime, launched without a prompt: no turn runs, yet the
    // native id is known and registered before the launch is applied.
    delete cfg.runtimes.claude_code.executable;
    const daemon: any = new Daemon(cfg, api);
    const session = randomUUID();
    try {
      const r2 = await launch(daemon, session);
      assert.equal(r2?.status, 'applied', JSON.stringify(r2));
      assert.match(r2.result.native_session_id, /^[0-9a-f-]{36}$/);
      assert.deepEqual(registered.map((b) => [b.coding_session_id, b.runtime_session_id]), [[session, r2.result.native_session_id]]);
    } finally {
      await daemon.sessions.get(session)?.adapter?.stop();
    }
  });
});

/**
 * A Codex App Server that initializes and starts or resumes a thread, and
 * exits when its stdin closes. With `turns`, it appends the text of every
 * turn/start it receives to that file.
 */
function fakeAppServer(turns?: string): string {
  const fake = path.join(tmp('agn-bin-'), 'codex.js');
  fs.writeFileSync(fake, [
    "const rl = require('node:readline').createInterface({ input: process.stdin });",
    "rl.on('line', (line) => {",
    '  const m = JSON.parse(line);',
    '  if (m.id === undefined) return;',
    ...(turns ? [`  if (m.method === 'turn/start') require('node:fs').appendFileSync(${JSON.stringify(turns)}, m.params.input[0].text + '\\n');`] : []),
    "  const result = m.method === 'initialize' ? { userAgent: 'fake' } : m.method.startsWith('thread/') ? { thread: { id: 'thread-fake' } } : {};",
    "  process.stdout.write(JSON.stringify({ id: m.id, result }) + '\\n');",
    '});',
    "rl.on('close', () => process.exit(0));",
  ].join('\n'));
  return fake;
}

test('a launch whose starting report fails still starts, and is not left half handled', async () => {
  await withHome(async () => {
    const repo = tempRepo();
    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
    cfg.runtimes.codex.executable = fakeAppServer();
    const api = new (class extends ProbeApi {
      override async request<T = any>(method: string, p: string, opts: { body?: any } = {}): Promise<T> {
        if (p.endsWith('/state') && opts.body?.status === 'starting') throw new ApiError(0, 'network', 'gateway unavailable');
        return super.request<T>(method, p, opts);
      }
    })();
    const daemon: any = new Daemon(cfg, api);
    const session = randomUUID();
    const cmd = { id: ulid(), kind: 'launch', coding_session_id: session, payload: { runtime: 'codex', workspace_id: 'w', mode: 'observe' } };
    try {
      await daemon.deliver(cmd);
      assert.equal(api.results.get(cmd.id)?.status, 'applied', JSON.stringify(api.results.get(cmd.id)));
      assert.equal(daemon.sessions.get(session)?.adapter?.alive(), true, 'the session runs with its adapter');
      // A redelivery of the same launch gets the same answer.
      api.results.clear();
      await daemon.deliver(cmd);
      assert.equal(api.results.get(cmd.id)?.status, 'applied');
    } finally {
      await daemon.sessions.get(session)?.adapter?.stop();
    }
  });
});

test('a launch refused while the gateway is down leaves no record or worktree; redelivered after a restart, it starts', async () => {
  await withHome(async () => {
    const repo = tempRepo();
    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
    cfg.runtimes.codex.executable = fakeAppServer();
    let down = true;
    const api = new (class extends ProbeApi {
      override async request<T = any>(method: string, p: string, opts: { body?: any } = {}): Promise<T> {
        if (down && (p === '/v1/coding/runner/sessions' || p.endsWith('/state'))) throw new ApiError(0, 'network', 'gateway unavailable');
        if (p === '/v1/coding/runner/sessions') return { session: {} } as T;
        return super.request<T>(method, p, opts);
      }
    })();
    const session = randomUUID();
    const cmd = { id: ulid(), kind: 'launch', coding_session_id: session, payload: { runtime: 'codex', workspace_id: 'w', mode: 'observe', branch: 'agenomic/refused' } };
    const first: any = new Daemon(cfg, api);
    await first.deliver(cmd);
    assert.equal(api.results.get(cmd.id)?.status, 'refused', JSON.stringify(api.results.get(cmd.id)));
    assert.deepEqual(JSON.parse(fs.readFileSync(paths.sessions(), 'utf8')), {}, 'no persisted record, native id included');
    assert.equal(fs.existsSync(path.join(paths.worktrees(), session)), false, 'the worktree is removed');
    assert.equal(execFileSync('git', ['-C', repo, 'branch', '--list', 'agenomic/refused'], { encoding: 'utf8' }), '', 'its new branch too');
    assert.doesNotMatch(execFileSync('git', ['-C', repo, 'worktree', 'list'], { encoding: 'utf8' }), new RegExp(session));
    // The daemon restarts, the gateway is back and redelivers the launch.
    down = false;
    api.results.clear();
    const second: any = new Daemon(cfg, api);
    try {
      await second.deliver(cmd);
      assert.equal(api.results.get(cmd.id)?.status, 'applied', JSON.stringify(api.results.get(cmd.id)));
      assert.equal(second.sessions.get(session)?.adapter?.alive(), true);
    } finally {
      await second.sessions.get(session)?.adapter?.stop();
    }
  });
});

test('the first connected status carries the effective mode, after the native session is registered, on launch and on resume', async () => {
  await withHome(async () => {
    const repo = tempRepo();
    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
    cfg.runtimes.codex.executable = fakeAppServer();
    const log: [string, any][] = [];
    let failConnected = 1;
    const api = new (class extends ProbeApi {
      override async request<T = any>(method: string, p: string, opts: { body?: any } = {}): Promise<T> {
        if (p === '/v1/coding/runner/sessions') {
          log.push(['register', opts.body]);
          return { session: {} } as T;
        }
        if (p.endsWith('/state')) {
          // The gateway is unavailable for the first report that connects the session.
          if (opts.body?.mode_effective && failConnected-- > 0) throw new ApiError(0, 'network', 'gateway unavailable');
          log.push(['state', opts.body]);
        }
        return super.request<T>(method, p, opts);
      }
    })();
    const daemon: any = new Daemon(cfg, api);
    const session = randomUUID();
    const command = async (kind: string, payload: unknown = {}) => {
      const id = ulid();
      await daemon.handleCommand({ id, kind, coding_session_id: session, payload });
      return api.results.get(id);
    };
    const connectedAfterRegistration = (from: number) => {
      const rest = log.slice(from);
      const states = rest.filter(([k]) => k === 'state').map(([, b]) => b);
      for (const b of states) {
        if (b.mode_effective !== undefined) assert.notEqual(b.status, 'starting', 'never a mode while starting');
      }
      const first = states.findIndex((b) => b.status && b.status !== 'starting');
      assert.ok(first >= 0, 'a connected status was reported');
      const report = states[first];
      assert.equal(report.status, 'running');
      assert.equal(report.mode_effective, 'observe', 'the first connected status carries the mode');
      assert.ok(report.protection && report.capabilities && report.limitations);
      const at = rest.findIndex(([, b]) => b === report);
      assert.ok(rest.slice(0, at).some(([k, b]) => k === 'register' && b.runtime_session_id === 'thread-fake'), 'registered before');
    };
    try {
      const launched = await command('launch', { runtime: 'codex', workspace_id: 'w', mode: 'observe' });
      assert.equal(launched?.status, 'applied');
      assert.equal(launched.result.native_session_id, 'thread-fake');
      // The connected report that failed is retried and delivered.
      for (let i = 0; i < 50 && !log.some(([k, b]) => k === 'state' && b.mode_effective); i++) await sleep(100);
      connectedAfterRegistration(0);
      assert.equal((await command('stop_process'))?.status, 'applied');
      const from = log.length;
      assert.equal((await command('resume_session'))?.status, 'applied');
      connectedAfterRegistration(from);
    } finally {
      await daemon.sessions.get(session)?.adapter?.stop();
    }
  });
});

test('a launch or resume prompt reaches the runtime only once the gateway holds the session\'s mode', async () => {
  await withHome(async () => {
    const repo = tempRepo();
    const turns = path.join(tmp('agn-turns-'), 'turns');
    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
    cfg.runtimes.codex.executable = fakeAppServer(turns);
    const started = () => (fs.existsSync(turns) ? fs.readFileSync(turns, 'utf8').split('\n').filter(Boolean) : []);
    const connected: string[][] = [];
    let failConnected = 1;
    const api = new (class extends ProbeApi {
      override async request<T = any>(method: string, p: string, opts: { body?: any } = {}): Promise<T> {
        if (p === '/v1/coding/runner/sessions') return { session: {} } as T;
        if (p.endsWith('/state') && opts.body?.mode_effective) {
          if (failConnected-- > 0) throw new ApiError(0, 'network', 'gateway unavailable');
          // The turns the runtime had started when the gateway learnt the mode.
          connected.push(started());
        }
        return super.request<T>(method, p, opts);
      }
    })();
    const daemon: any = new Daemon(cfg, api);
    const session = randomUUID();
    const command = async (kind: string, payload: unknown = {}) => {
      const id = ulid();
      await daemon.handleCommand({ id, kind, coding_session_id: session, payload });
      return api.results.get(id);
    };
    try {
      // The connecting report fails once: the launch is applied, and the
      // prompt waits until the retried report is delivered.
      assert.equal((await command('launch', { runtime: 'codex', workspace_id: 'w', mode: 'observe', prompt: 'first' }))?.status, 'applied');
      for (let i = 0; i < 50 && started().length === 0; i++) await sleep(100);
      assert.deepEqual(connected, [[]], 'no turn had started when the mode was delivered');
      assert.deepEqual(started(), ['first']);
      assert.equal((await command('stop_process'))?.status, 'applied');
      assert.equal((await command('resume_session', { prompt: 'again' }))?.status, 'applied');
      assert.deepEqual(connected, [[], ['first']], 'the resume prompt had not started when the mode was delivered');
      assert.deepEqual(started(), ['first', 'again']);
    } finally {
      await daemon.sessions.get(session)?.adapter?.stop();
    }
  });
});

test('a local Codex terminal session reports the codex:cli_hooks capabilities, validated by its own probe', async () => {
  await withHome(async () => {
    const version = codexVersion(defaultConfig('x', 'x').runtimes.codex)!;
    const caps = manifest('codex', 'cli_hooks', version);
    assert.deepEqual(Object.keys(caps).sort(), ['converse', 'file_diffs', 'interrupt_turn', 'observe', 'pre_tool_control', 'remote_approval', 'resume', 'stop_process', 'subagent_tracking', 'user_questions']);
    assert.equal(caps.pre_tool_control!.announced, 'partial', 'cooperative, shell calls only');
    assert.equal(caps.pre_tool_control!.validated, 'unknown', 'nothing validated without a probe');
    assert.equal(caps.converse!.validated, 'unsupported');
    const ok = { ok: true, detail: 'probe' };
    saveProbe({ runtime: 'codex', surface: 'cli_hooks', version, at: '', results: { observe: ok, pre_tool_control: ok, remote_approval: { ok: false, detail: 'held call did not run' } } });
    const probed = manifest('codex', 'cli_hooks', version);
    assert.equal(probed.observe!.validated, 'partial');
    assert.equal(probed.pre_tool_control!.validated, 'partial');
    assert.equal(probed.remote_approval!.validated, 'unsupported', 'a failed probe never validates');
    assert.equal(probed.stop_process!.validated, 'unsupported');

    const repo = tempRepo();
    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
    cfg.local_sessions.mode = 'enforce';
    const api = new ProbeApi();
    const daemon = new Daemon(cfg, api);
    assert.deepEqual(daemon.runtimes().find((r) => r.runtime === 'codex').surfaces, ['app_server', 'cli_hooks']);
    await (daemon as any).onLocal({ op: 'hook', runtime: 'codex', input: { hook_event_name: 'SessionStart', session_id: 'thread-1', cwd: repo } });
    const state = api.states.find((s) => s.capabilities);
    assert.equal(state.capabilities.pre_tool_control.validated, 'partial');
    assert.equal(state.capabilities.converse.validated, 'unsupported');
  });
});

test('every event envelope carries its coding_session_id, spooled and synthesized ones included', async () => {
  const api = new FlakyApi();
  const spool = tmp('agn-spool-');
  const id = randomUUID();
  // An event spooled by an earlier version, without the session id.
  fs.writeFileSync(path.join(spool, `${id}.jsonl`), JSON.stringify({ event_id: ulid(), schema_version: 'agenomic.coding.event/v1', type: 'tool.started', source: 'runtime', trust: 'native', producer_epoch: 'old', producer_seq: 1, occurred_at: new Date().toISOString(), payload: {} }) + '\n');
  const sink = new EventSink(api, id, () => [], spool, { maxBuffered: 4, maxSpoolBytes: 1 << 20, batchSize: 2, flushIntervalMs: 60000 });
  for (let i = 0; i < 8; i++) sink.emit('message.assistant', 'runtime', 'native', { i });
  sink.emit('tool.requested', 'gateway', 'native', { native_request_id: 'x' }, { coding_session_id: 'another' } as any);
  await sink.flush();
  api.up = true;
  await sink.flush();
  await sink.close();
  assert.ok(api.sent.some((e) => e.producer_epoch === 'old'));
  assert.ok(api.sent.some((e) => e.type === 'error' && e.payload.code === 'events_dropped'));
  for (const e of api.sent) assert.equal(e.coding_session_id, id, JSON.stringify(e));
});

/** The probe API, also recording the action reports. */
class RecordingApi extends ProbeApi {
  reports: { action: string; outcome: string }[] = [];
  override async request<T = any>(method: string, p: string, opts: { body?: any } = {}): Promise<T> {
    if (p.endsWith('/report')) this.reports.push({ action: p.split('/').at(-2)!, outcome: opts.body?.outcome });
    return super.request<T>(method, p, opts);
  }
}

const toolEvents = (api: ProbeApi) => api.events.filter((e) => e.type.startsWith('tool.'));

test('tool events carry the correlation key of their coding action (native_request_id, attempt_id, action_id)', async () => {
  await withHome(async () => {
    // Codex App Server: a call decided by the PreToolUse hook, one decided
    // only by a native approval request, and one never decided.
    const api = new RecordingApi();
    const daemon = new Daemon(defaultConfig('http://127.0.0.1:9', 'unit'), api);
    const m = (daemon as any).manage(randomUUID(), 'codex', 'launched', 'enforce', { conversation: false, commands: true, diffs: false, outputs: false }, tmp('agn-wt-'), null);
    const ctx: SessionContext = m.ctx;
    const codex: any = new CodexSession({ ctx, cwd: m.cwd, runtime: defaultConfig('x', 'x').runtimes.codex, onNativeSession: async () => undefined, onStatus: () => undefined });
    const hooked = await ctx.authorize({ nativeId: 'call_1', tool: 'Bash', input: { command: 'ls' }, context: {}, phase: 'pre_tool', waitForApproval: true });
    await codex.onServerRequest(7, 'item/commandExecution/requestApproval', { itemId: 'call_2', approvalId: 'ap-1', command: 'git status', turnId: 't1' });
    for (const id of ['call_1', 'call_2', 'call_3']) {
      codex.onNotification('item/started', { turnId: 't1', item: { type: 'commandExecution', id, command: 'ls' } });
      codex.onNotification('item/completed', { turnId: 't1', item: { type: 'commandExecution', id, command: 'ls', status: 'completed', exitCode: 0 } });
    }
    await ctx.sink.close();
    const approval = api.events.find((e) => e.type === 'tool.requested' && e.payload.native_request_id === 'call_2:ap-1');
    assert.ok(approval, 'the approval request is its own action');
    for (const e of toolEvents(api)) {
      assert.equal(typeof e.payload.native_request_id, 'string', JSON.stringify(e));
      assert.equal(e.attempt_id, '1', JSON.stringify(e));
      assert.equal(e.coding_session_id, ctx.id);
    }
    for (const e of api.events.filter((x) => x.type === 'tool.requested')) assert.ok(e.action_id, 'tool.requested always names its action');
    const of = (type: string, key: string) => api.events.find((e) => e.type === type && e.payload.native_request_id === key);
    for (const type of ['tool.started', 'tool.completed']) {
      assert.equal(of(type, 'call_1')?.action_id, hooked.actionId, `${type} of a hook-decided call`);
      assert.equal(of(type, 'call_2:ap-1')?.action_id, approval.action_id, `${type} of an approval-decided call keeps the action's key`);
      const observed = of(type, 'call_3');
      assert.ok(observed && observed.action_id === undefined, `${type} of a call without a decision is an observation only`);
    }
    assert.deepEqual(api.reports.map((r) => r.action).sort(), [hooked.actionId, approval.action_id].sort(), 'outcomes are reported for both actions');

    // Claude Code (Agent SDK): PostToolUse of a decided call.
    const c = (daemon as any).manage(randomUUID(), 'claude_code', 'launched', 'enforce', { conversation: false, commands: false, diffs: false, outputs: false }, tmp('agn-wt-'), null);
    const claude: any = new ClaudeSession({ ctx: c.ctx, cwd: c.cwd, runtime: defaultConfig('x', 'x').runtimes.claude_code, onNativeSession: async () => undefined, onStatus: () => undefined });
    const v = await c.ctx.authorize({ nativeId: 'toolu_1', tool: 'Read', input: { file_path: 'a' }, context: {}, phase: 'pre_tool', waitForApproval: false });
    await claude.postToolUse({ tool_use_id: 'toolu_1', tool_name: 'Read', tool_input: { file_path: 'a' } }, false);
    await claude.postToolUse({ tool_use_id: 'toolu_2', tool_name: 'Read', tool_input: { file_path: 'b' } }, true);
    await c.ctx.sink.close();
    const done = api.events.find((e) => e.type === 'tool.completed' && e.payload.native_request_id === 'toolu_1');
    assert.equal(done.action_id, v.actionId);
    assert.equal(done.attempt_id, '1');
    const failed = api.events.find((e) => e.type === 'tool.failed' && e.payload.native_request_id === 'toolu_2');
    assert.equal(failed.action_id, undefined);
    assert.equal(failed.attempt_id, '1');
  });
});

/** A gateway whose outcome reports fail (beyond the retry window) until it recovers. */
class FlakyReportApi extends RecordingApi {
  down = true;
  override async request<T = any>(method: string, p: string, opts: { body?: any } = {}): Promise<T> {
    if (p.endsWith('/report') && this.down) throw new ApiError(0, 'network', 'gateway unavailable');
    return super.request<T>(method, p, opts);
  }
}

test('an outcome whose report fails is retained and delivered when the turn settles, not replaced by unknown', async () => {
  await withHome(async () => {
    const api = new FlakyReportApi();
    const daemon = new Daemon(defaultConfig('http://127.0.0.1:9', 'unit'), api);
    const m = (daemon as any).manage(randomUUID(), 'claude_code', 'launched', 'enforce', { conversation: false, commands: false, diffs: false, outputs: false }, tmp('agn-wt-'), null);
    const ctx: SessionContext = m.ctx;
    const done = await ctx.authorize({ nativeId: 'toolu_1', tool: 'Read', input: { file_path: 'a' }, context: {}, phase: 'pre_tool', waitForApproval: false });
    const broke = await ctx.authorize({ nativeId: 'toolu_2', tool: 'Bash', input: { command: 'false' }, context: {}, phase: 'pre_tool', waitForApproval: false });
    const lost = await ctx.authorize({ nativeId: 'toolu_3', tool: 'Bash', input: { command: 'sleep 9' }, context: {}, phase: 'pre_tool', waitForApproval: false });
    await ctx.report(done.actionId, 'completed', { duration_ms: 5 });
    await ctx.report(broke.actionId, 'failed', { exit_code: 1 });
    assert.deepEqual(api.reports, [], 'nothing reached the gateway while it was down');
    // Still down: the settlement fails too, and loses nothing.
    await ctx.settleOpen('turn ended before the tool reported');
    assert.deepEqual(api.reports, []);
    api.down = false;
    await ctx.settleOpen('turn ended before the tool reported');
    const outcome = (id?: string) => api.reports.filter((r) => r.action === id).map((r) => r.outcome);
    assert.deepEqual(outcome(done.actionId), ['completed'], 'the real outcome is delivered once the gateway recovers');
    assert.deepEqual(outcome(broke.actionId), ['failed']);
    assert.deepEqual(outcome(lost.actionId), ['unknown'], 'an action that never reported settles as unknown');
    // Acknowledged outcomes are not reported again.
    await ctx.settleOpen('session ended before the tool reported');
    assert.equal(api.reports.length, 3);
    await ctx.sink.close();
  });
});

test('the settlement at a session\'s end keeps delivering retained outcomes until the gateway recovers', async () => {
  await withHome(async () => {
    const repo = tempRepo();
    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
    const api = new FlakyReportApi();
    const daemon: any = new Daemon(cfg, api);
    const hook = (input: Record<string, unknown>) => daemon.onLocal({ op: 'hook', runtime: 'claude_code', input: { session_id: 'cli-3', cwd: repo, ...input } });
    await hook({ hook_event_name: 'PreToolUse', tool_use_id: 'toolu_1', tool_name: 'Bash', tool_input: { command: 'ls' } });
    await hook({ hook_event_name: 'PostToolUse', tool_use_id: 'toolu_1', tool_name: 'Bash' });
    // The session ends (and is forgotten) while the gateway is still down.
    await hook({ hook_event_name: 'SessionEnd', reason: 'exit' });
    assert.equal(api.reports.length, 0);
    api.down = false;
    const until = Date.now() + 10000;
    while (api.reports.length === 0 && Date.now() < until) await sleep(50);
    assert.deepEqual(api.reports.map((r) => r.outcome), ['completed'], 'the real outcome reaches the gateway after the session ended');

    // Only the actions open when the session ended are retried: a resumed
    // session's new action is not settled by it.
    const flaky = new FlakyReportApi();
    const m = (new Daemon(defaultConfig('http://127.0.0.1:9', 'unit'), flaky) as any).manage(randomUUID(), 'claude_code', 'launched', 'enforce', { conversation: false, commands: false, diffs: false, outputs: false }, tmp('agn-wt-'), null);
    const ctx: SessionContext = m.ctx;
    const before = await ctx.authorize({ nativeId: 'toolu_1', tool: 'Read', input: { file_path: 'a' }, context: {}, phase: 'pre_tool', waitForApproval: false });
    await ctx.report(before.actionId, 'failed', { exit_code: 2 });
    const settled = ctx.settleFinal('session stopped before the tool reported', 10000, 20);
    const after = await ctx.authorize({ nativeId: 'toolu_2', tool: 'Read', input: { file_path: 'b' }, context: {}, phase: 'pre_tool', waitForApproval: false });
    await sleep(60);
    flaky.down = false;
    // The settlement's waits do not hold the process: the test does.
    while (flaky.reports.length === 0 && Date.now() < until + 10000) await sleep(10);
    await settled;
    assert.deepEqual(flaky.reports, [{ action: before.actionId, outcome: 'failed' }]);
    assert.ok(!flaky.reports.some((r) => r.action === after.actionId));
    await ctx.sink.close();
  });
});

test('local hook sessions: tool events correlated; a launched session\'s hooks do not report a call twice', async () => {
  await withHome(async () => {
    const repo = tempRepo();
    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
    const api = new ProbeApi();
    const daemon: any = new Daemon(cfg, api);
    const hook = (input: Record<string, unknown>) => daemon.onLocal({ op: 'hook', runtime: 'claude_code', input: { session_id: 'cli-1', cwd: repo, ...input } });
    await hook({ hook_event_name: 'PreToolUse', tool_use_id: 'toolu_9', tool_name: 'Bash', tool_input: { command: 'ls' } });
    await hook({ hook_event_name: 'PostToolUse', tool_use_id: 'toolu_9', tool_name: 'Bash' });
    await hook({ hook_event_name: 'SessionEnd', reason: 'exit' });
    const requested = api.events.find((e) => e.type === 'tool.requested');
    const completed = api.events.find((e) => e.type === 'tool.completed');
    assert.equal(requested.attempt_id, '1');
    assert.equal(completed.action_id, requested.action_id);
    assert.equal(completed.attempt_id, '1');
    assert.equal(completed.payload.native_request_id, 'toolu_9');
    assert.equal(completed.coding_session_id, requested.coding_session_id);

    // A launched Codex session: its App Server notifications report the call.
    const m = daemon.manage(randomUUID(), 'codex', 'launched', 'enforce', { conversation: false, commands: false, diffs: false, outputs: false }, repo, null);
    daemon.byNative.set('codex:thread-1', m);
    const codexHook = (input: Record<string, unknown>) => daemon.onLocal({ op: 'hook', runtime: 'codex', input: { session_id: 'thread-1', cwd: repo, ...input } });
    await codexHook({ hook_event_name: 'PreToolUse', tool_use_id: 'call_9', tool_name: 'Bash', tool_input: { command: 'ls' } });
    await codexHook({ hook_event_name: 'PostToolUse', tool_use_id: 'call_9', tool_name: 'Bash' });
    await codexHook({ hook_event_name: 'Stop', turn_id: 't' });
    await m.ctx.sink.close();
    const launched = api.events.filter((e) => e.coding_session_id === m.id).map((e) => e.type);
    assert.deepEqual(launched, ['tool.requested'], 'the PreToolUse decision only');
  });
});

// The 16 ids of coding-action.schema.json (contract C3), spelled out here
// so that a change of the connector's list is a visible test change.
const VOCABULARY = [
  'coding.fs.read', 'coding.fs.write', 'coding.fs.delete', 'coding.shell.exec', 'coding.shell.interactive_input',
  'coding.git.read', 'coding.git.commit', 'coding.git.push', 'coding.git.destructive', 'coding.dependency.install',
  'coding.network.fetch', 'coding.mcp.call', 'coding.agent_config.modify', 'coding.subagent.spawn', 'coding.web.search', 'coding.unknown',
];

test('protection lists tool ids of the closed vocabulary; mechanisms go to notes, gaps to limitations', async () => {
  assert.deepEqual([...TOOL_IDS], VOCABULARY);
  const cases = [['claude_code', 'sdk'], ['claude_code', 'cli_hooks'], ['codex', 'app_server'], ['codex', 'cli_hooks']] as const;
  for (const [runtime, surface] of cases) {
    for (const mode of ['observe', 'shadow', 'enforce'] as const) {
      const p = protection(runtime, surface, mode);
      const at = `${runtime}/${surface}/${mode}`;
      for (const id of [...p.protected, ...p.not_covered]) assert.ok(VOCABULARY.includes(id), `${at}: ${id}`);
      assert.equal(new Set(p.protected).size, p.protected.length, `${at}: unique`);
      assert.equal(new Set(p.not_covered).size, p.not_covered.length, `${at}: unique`);
      assert.deepEqual([...p.protected, ...p.not_covered].sort(), [...VOCABULARY].sort(), `${at}: every id is either protected or not covered`);
      assert.ok(p.notes.length <= 32 && p.notes.every((n) => typeof n === 'string' && n.length > 0 && n.length <= 300), `${at}: notes`);
      assert.ok(p.limitations.every((n) => typeof n === 'string' && n.length > 0), `${at}: limitations`);
      if (mode !== 'enforce') assert.deepEqual(p.protected, [], `${at}: only enforce gates calls`);
    }
  }
  assert.deepEqual(protection('claude_code', 'sdk', 'enforce').protected, VOCABULARY, 'every Claude Code tool goes through PreToolUse');
  const shadow = protection('claude_code', 'sdk', 'shadow');
  assert.deepEqual(shadow.protected, [], 'shadow records would-be decisions, it gates nothing');
  assert.deepEqual(shadow.not_covered, VOCABULARY);
  assert.ok(shadow.notes.includes('shadow evaluates every tool call before it runs, without gating it'), 'what shadow evaluates is described in notes');
  assert.ok(protection('codex', 'app_server', 'shadow').notes.some((n) => n.startsWith('shadow evaluates coding.shell.exec, coding.git.read')));
  assert.ok(!protection('claude_code', 'sdk', 'enforce').notes.some((n) => n.startsWith('shadow evaluates')));
  const codex = protection('codex', 'app_server', 'enforce');
  for (const id of ['coding.shell.interactive_input', 'coding.mcp.call', 'coding.web.search', 'coding.subagent.spawn', 'coding.unknown', 'coding.fs.read']) {
    assert.ok(codex.not_covered.includes(id as any), `codex enforce: ${id} is not re-checked`);
  }
  assert.ok(codex.protected.includes('coding.fs.write'), 'apply_patch goes through the fileChange approval in enforce');
  assert.ok(protection('codex', 'app_server', 'shadow').not_covered.includes('coding.fs.write'), 'no approval requests in shadow');
  assert.ok(protection('codex', 'cli_hooks', 'enforce').not_covered.includes('coding.fs.write'));

  // As reported in the session state of a local session.
  await withHome(async () => {
    const repo = tempRepo();
    const cfg = defaultConfig('http://127.0.0.1:9', 'unit');
    cfg.workspaces = [{ id: 'w', name: 'w', path: repo }];
    cfg.local_sessions.mode = 'enforce';
    // Enforce needs pre-tool control validated on this machine: without a probe, the session is blocked.
    const unprobed = new ProbeApi();
    await (new Daemon(cfg, unprobed) as any).onLocal({ op: 'hook', runtime: 'claude_code', input: { hook_event_name: 'SessionStart', session_id: 'cli-1', cwd: repo } });
    const blocked = unprobed.states.find((s) => s.protection);
    assert.equal(blocked.status, 'running');
    assert.equal(blocked.mode_effective, 'blocked');
    assert.equal(blocked.capabilities.pre_tool_control.validated, 'unknown');
    assert.deepEqual(blocked.protection.protected, [], 'a blocked session protects nothing');
    assert.deepEqual(blocked.protection.not_covered, VOCABULARY);
    assert.ok(blocked.protection.notes.some((n: string) => n.startsWith('blocked: enforce needs pre-tool control validated')));
    const ok = { ok: true, detail: 'probe' };
    saveProbe({ runtime: 'claude_code', surface: 'cli_hooks', version: claudeCodeVersion(cfg.runtimes.claude_code)!, at: '', results: { observe: ok, pre_tool_control: ok } });
    const api = new ProbeApi();
    await (new Daemon(cfg, api) as any).onLocal({ op: 'hook', runtime: 'claude_code', input: { hook_event_name: 'SessionStart', session_id: 'cli-2', cwd: repo } });
    const state = api.states.find((s) => s.protection);
    assert.equal(state.mode_effective, 'enforce');
    assert.equal(state.capabilities.pre_tool_control.validated, 'partial');
    assert.deepEqual(state.protection.protected, VOCABULARY);
    assert.deepEqual(state.protection.not_covered, []);
    assert.ok(state.protection.notes.length > 0);
    assert.ok(state.limitations.some((l: string) => l.startsWith('hooks are cooperative')));
  });
});

test('enroll refuses an insecure endpoint before the one time token is sent', async () => {
  await withHome(async () => {
    const realFetch = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = (async (url: string | URL) => {
      calls.push(String(url));
      throw new Error('no network in this test');
    }) as typeof fetch;
    try {
      await assert.rejects(main(['enroll', '--token', 'agmcen_onetime', '--endpoint', 'http://gateway.example.com']), /plain http is only accepted for a loopback endpoint/);
      assert.deepEqual(calls, [], 'the token was not posted');
      assert.equal(fs.existsSync(paths.config()), false);
      await assert.rejects(main(['enroll', '--token', 'agmcen_onetime', '--endpoint', 'https://gateway.example.com']), /no network in this test/);
      assert.deepEqual(calls, ['https://gateway.example.com/v1/coding/runners/enroll'], 'an https endpoint is enrolled');
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});

test('every public function, class and method of the connector has a doc comment with an example', () => {
  const dir = path.resolve(import.meta.dirname, '../src');
  const missing: string[] = [];
  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.ts'))) {
    const lines = fs.readFileSync(path.join(dir, file), 'utf8').split('\n');
    let inClass = false;
    lines.forEach((line, i) => {
      if (/^export class /.test(line)) inClass = true;
      else if (/^\S/.test(line) && !/^}/.test(line)) inClass = false;
      const exported = /^export (async )?function |^export class |^export const \w+ = (async )?\(/.test(line);
      const method = inClass && /^  (static |async |override )*(?!constructor\b)[a-zA-Z]\w*(<[^>]*>)?\(/.test(line);
      if (!exported && !method) return;
      let j = i - 1;
      if (!lines[j]?.trim().endsWith('*/')) return void missing.push(`${file}:${i + 1} ${line.trim()}`);
      while (j > 0 && !lines[j]!.trim().startsWith('/**')) j--;
      if (!lines.slice(j, i).some((l) => l.includes('@example'))) missing.push(`${file}:${i + 1} ${line.trim()}`);
    });
  }
  assert.deepEqual(missing, []);
});
