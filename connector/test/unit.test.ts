import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { RunnerApi } from '../src/api.ts';
import { manifest, saveProbe } from '../src/capabilities.ts';
import { ClaudeSession, claudeCodeVersion, sdkPackage } from '../src/claude.ts';
import { CodexSession, codexVersion } from '../src/codex.ts';
import { defaultConfig, localFailMode, paths, runtimeSecrets, saveConfig } from '../src/config.ts';
import { Daemon } from '../src/daemon.ts';
import { EventSink } from '../src/events.ts';
import { eventOf } from '../src/hook.ts';
import { apply, codexBlock, hookCommand, planClaude, planCodex } from '../src/hooks-install.ts';
import { clean, redact } from '../src/redact.ts';
import { protection, TOOL_IDS } from '../src/protection.ts';
import { ProbeApi, probeConfig, probedVersion, runProbe, tempRepo } from '../src/probe.ts';
import { isTestCommand, type SessionContext } from '../src/session.ts';
import { realPathEscapes, ulid } from '../src/util.ts';
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

test('a configured runtime executable reports its own version; a probe of another binary does not validate it', () => {
  const home = tmp('agn-home-');
  const prev = process.env.AGENOMIC_CONNECTOR_HOME;
  process.env.AGENOMIC_CONNECTOR_HOME = home;
  try {
    const claude = fakeBinary('9.8.7 (Claude Code)');
    const codex = fakeBinary('codex-cli 1.2.3');
    const rt = (executable?: string) => ({ enabled: true, executable, env_passthrough: [], extra_env: {}, allowed_domains: [] });
    assert.equal(claudeCodeVersion(rt(claude)), '9.8.7');
    assert.equal(claudeCodeVersion(rt()), sdkPackage()!.claudeCodeVersion, 'the bundled binary: the version the SDK pins');
    assert.equal(codexVersion(rt(codex)), '1.2.3');
    assert.equal(codexVersion(rt(path.join(home, 'missing'))), null);
    assert.equal(codexVersion(rt(fakeBinary('no version here'))), null);

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
    const unknown = new Daemon(cfg, api).runtimes().find((r) => r.runtime === 'codex');
    assert.equal(unknown.version, 'unknown');
    assert.equal(unknown.capabilities.observe.validated, 'unknown');
  } finally {
    if (prev === undefined) delete process.env.AGENOMIC_CONNECTOR_HOME;
    else process.env.AGENOMIC_CONNECTOR_HOME = prev;
  }
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
  assert.equal(probedVersion(codex, 'codex'), '4.5.6', 'recorded under the version of the binary that ran');
  const claude = probeConfig(machine, 'claude_code', 'http://127.0.0.1:1', '/tmp/repo');
  assert.equal(claude.runtimes.claude_code.executable, undefined);
  assert.deepEqual(claude.runtimes.claude_code.allowed_domains, ['registry.npmjs.org']);
  assert.equal(probedVersion(claude, 'claude_code'), sdkPackage()!.claudeCodeVersion);
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
      if (mode === 'observe') assert.deepEqual(p.protected, [], `${at}: observe protects nothing`);
    }
  }
  assert.deepEqual(protection('claude_code', 'sdk', 'enforce').protected, VOCABULARY, 'every Claude Code tool goes through PreToolUse');
  assert.deepEqual(protection('claude_code', 'sdk', 'shadow').protected, VOCABULARY);
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
    const api = new ProbeApi();
    await (new Daemon(cfg, api) as any).onLocal({ op: 'hook', runtime: 'claude_code', input: { hook_event_name: 'SessionStart', session_id: 'cli-2', cwd: repo } });
    const state = api.states.find((s) => s.protection);
    assert.deepEqual(state.protection.protected, VOCABULARY);
    assert.deepEqual(state.protection.not_covered, []);
    assert.ok(state.protection.notes.length > 0);
    assert.ok(state.limitations.some((l: string) => l.startsWith('hooks are cooperative')));
  });
});
