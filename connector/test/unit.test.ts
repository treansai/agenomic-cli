import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { RunnerApi } from '../src/api.ts';
import { EventSink } from '../src/events.ts';
import { eventOf } from '../src/hook.ts';
import { apply, codexBlock, planClaude, planCodex } from '../src/hooks-install.ts';
import { clean, redact } from '../src/redact.ts';
import { isTestCommand } from '../src/session.ts';
import { realPathEscapes } from '../src/util.ts';
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
