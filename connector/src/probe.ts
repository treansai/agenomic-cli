import { execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { RunnerApi } from './api.ts';
import { saveProbe, type CapName, type ProbeResult } from './capabilities.ts';
import { readClaudeCodeVersion } from './claude.ts';
import { codexExecutable, readCodexVersion } from './codex.ts';
import { defaultConfig, loadConfig, runtimeEnv, runtimeSecrets, type ConnectorConfig } from './config.ts';
import { Daemon } from './daemon.ts';
import { codexProviderToml, fakeAnthropic, fakeResponses, script, type FakeServer } from './fakes.ts';
import { installCodex } from './hooks-install.ts';
import { clean } from './redact.ts';
import { sleep, ulid } from './util.ts';

/**
 * An in-memory stand-in for the Agenomic runner API used only by the
 * probe: it decides deterministically (inputs containing `deny-me` are
 * refused, `approve-me` needs one approval, granted after a delay) and
 * records everything the connector sent.
 *
 * @example
 * const api = new ProbeApi();
 * await new Daemon(cfg, api).handleCommand(launch);
 * api.has('session.started'); // true once the runtime started
 */
export class ProbeApi extends RunnerApi {
  events: any[] = [];
  authorizations: any[] = [];
  results = new Map<string, any>();
  states: any[] = [];
  private approvals = new Map<string, string>();
  private actions = new Map<string, { approved: boolean }>();

  constructor() {
    // Tokens of the fake runner, redacted like real ones: long and unlike
    // any other text, so that redaction leaves the probe's content intact.
    super('http://127.0.0.1:9', { access_token: 'agenomic-probe-access-not-a-secret', refresh_token: 'agenomic-probe-refresh-not-a-secret', access_expires_at: new Date(Date.now() + 3600e3).toISOString(), refresh_expires_at: new Date(Date.now() + 3600e3).toISOString() }, false);
  }

  /**
   * Answers a runner API call in process, recording what it carries.
   *
   * @example
   * await api.request('POST', `/v1/coding/runner/sessions/${id}/state`, { body: { status: 'idle' } });
   * api.states.at(-1); // { status: 'idle' }
   */
  override async request<T = any>(method: string, p: string, opts: { body?: any } = {}): Promise<T> {
    const b = opts.body ?? {};
    if (p.endsWith('/events')) {
      this.events.push(...b.events);
      return { accepted: b.events.length, duplicates: 0 } as T;
    }
    if (p.endsWith('/authorize')) {
      this.authorizations.push(b);
      const text = JSON.stringify(b.input);
      const id = `${b.native_request_id}`;
      if (text.includes('deny-me')) return { action_id: randomUUID(), decision: 'deny', reason: 'probe deny', classification: {} } as T;
      if (text.includes('approve-me')) {
        // Same native request: the same pending action until approved,
        // exactly as the gateway answers.
        let action = this.approvals.get(id);
        if (!action) {
          action = randomUUID();
          this.approvals.set(id, action);
          this.actions.set(action, { approved: false });
          setTimeout(() => (this.actions.get(action!)!.approved = true), 500);
        }
        if (!this.actions.get(action)!.approved) {
          return { action_id: action, decision: 'pending', approval_id: action, approval_expires_at: new Date(Date.now() + 60000).toISOString(), classification: {} } as T;
        }
        return { action_id: action, decision: 'allow', reason: 'approved', classification: {} } as T;
      }
      return { action_id: randomUUID(), decision: 'allow', reason: 'probe allow', classification: {} } as T;
    }
    if (method === 'GET' && p.includes('/actions/')) {
      const action = p.split('/').pop()!;
      return { approval_status: this.actions.get(action)?.approved ? 'approved' : 'pending' } as T;
    }
    if (p.includes('/commands/') && p.endsWith('/result')) {
      this.results.set(p.split('/')[5]!, b);
      return {} as T;
    }
    if (p.endsWith('/state')) {
      this.states.push(b);
      return { session: {} } as T;
    }
    if (p.endsWith('/runner/sessions')) return { session: { id: b.coding_session_id ?? randomUUID() } } as T;
    if (method === 'GET' && p.startsWith('/v1/coding/runner/commands')) {
      await sleep(1000);
      return { commands: [] } as T;
    }
    return {} as T;
  }

  /**
   * Whether a recorded event of `type` matches `pred`.
   *
   * @example
   * api.has('diff.snapshot', (e) => e.payload.files.length > 0);
   */
  has(type: string, pred: (e: any) => boolean = () => true): boolean {
    return this.events.some((e) => e.type === type && pred(e));
  }
}

async function until(pred: () => boolean, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (pred()) return true;
    await sleep(100);
  }
  return pred();
}

/**
 * A throwaway git checkout with one commit and one uncommitted human file.
 *
 * @example
 * const repo = tempRepo();
 * cfg.workspaces = [{ id: 'probe', name: 'probe', path: repo }];
 */
export function tempRepo(): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agn-probe-repo-')));
  const git = (...a: string[]) => execFileSync('git', ['-C', dir, ...a], { stdio: 'ignore' });
  git('init', '-q', '-b', 'main');
  fs.writeFileSync(path.join(dir, 'README.md'), 'probe\n');
  fs.writeFileSync(path.join(dir, 'slow.mjs'), 'setTimeout(() => {}, 60000);\n');
  fs.writeFileSync(path.join(dir, 'human-wip.txt'), 'uncommitted human work\n');
  git('add', 'README.md', 'slow.mjs');
  git('-c', 'user.email=probe@agenomic.invalid', '-c', 'user.name=probe', 'commit', '-q', '-m', 'init');
  return dir;
}

async function command(d: Daemon, api: ProbeApi, kind: string, session: string, payload: unknown): Promise<string> {
  const id = ulid();
  await d.handleCommand({ id, kind, coding_session_id: session, payload });
  return api.results.get(id)?.status ?? 'missing';
}

/**
 * The configuration a probe runs with: the enrolled machine's own runtime
 * (its executable and sandbox domains), with the provider settings
 * replaced by the scripted model, so that no credential is used and no
 * request leaves the machine. The other runtime is disabled.
 *
 * @example
 * const cfg = probeConfig(loadConfig(), 'codex', fake.url, tempRepo());
 */
export function probeConfig(machine: ConnectorConfig, runtime: 'claude_code' | 'codex', fakeUrl: string, repo: string): ConnectorConfig {
  const cfg: ConnectorConfig = defaultConfig('http://127.0.0.1:9', 'probe');
  cfg.workspaces = [{ id: 'probe', name: 'probe', path: repo }];
  cfg.runtimes.claude_code.enabled = false;
  cfg.runtimes.codex.enabled = false;
  const own = machine.runtimes[runtime];
  cfg.runtimes[runtime] = {
    enabled: true,
    ...(own.executable ? { executable: own.executable } : {}),
    allowed_domains: [...own.allowed_domains],
    env_passthrough: [],
    ...(runtime === 'claude_code'
      ? { extra_env: { ANTHROPIC_BASE_URL: fakeUrl, ANTHROPIC_API_KEY: 'probe-not-a-key' } }
      : { extra_env: { AGENOMIC_SCRIPTED_KEY: 'probe-not-a-key' }, extra_config_toml: codexProviderToml(fakeUrl) }),
  };
  return cfg;
}

/**
 * Version of the binary the probe runs, read from the binary as the daemon does.
 *
 * @example
 * const version = await probedVersion(loadConfig(), 'claude_code');
 */
export async function probedVersion(cfg: ConnectorConfig, runtime: 'claude_code' | 'codex'): Promise<string> {
  return (await (runtime === 'claude_code' ? readClaudeCodeVersion(cfg.runtimes.claude_code) : readCodexVersion(cfg.runtimes.codex))) ?? 'unknown';
}

/**
 * Validates the capabilities of a runtime's launched surface (SDK or App Server) with a scripted enforce session.
 *
 * @example
 * const result = await probeRuntime('codex', await fakeResponses(), tmpHome, loadConfig());
 */
export async function probeRuntime(runtime: 'claude_code' | 'codex', fake: FakeServer, home: string, machine: ConnectorConfig): Promise<ProbeResult> {
  process.env.AGENOMIC_CONNECTOR_HOME = home;
  const repo = tempRepo();
  const cfg = probeConfig(machine, runtime, fake.url, repo);
  const api = new ProbeApi();
  const d = new Daemon(cfg, api);
  await d.start();
  const results: ProbeResult['results'] = {};
  const set = (k: CapName, ok: boolean, detail: string) => (results[k] = { ok, detail });
  const session = randomUUID();
  const outside = path.join(os.tmpdir(), `agn-probe-outside-${Date.now()}.txt`);
  const shell = runtime === 'claude_code'
    ? (cmd: string) => ({ tool: 'Bash', input: { command: cmd, description: 'probe' } })
    : (cmd: string) => ({ tool: 'exec_command', input: { cmd } });
  const steps = [
    shell(`echo in > inside.txt; echo out > ${outside}; true`),
    runtime === 'claude_code' ? { tool: 'Write', input: { file_path: path.join('WORKTREE', 'deny-me.txt'), content: 'x' } } : shell('echo deny-me > deny-me.txt'),
    shell('echo approve-me > approved.txt'),
    ...(runtime === 'claude_code'
      ? [{ tool: 'AskUserQuestion', input: { questions: [{ question: 'Which option?', header: 'Probe', multiSelect: false, options: [{ label: 'a', description: 'first' }, { label: 'b', description: 'second' }] }] } }]
      : [{ tool: 'apply_patch', custom: true, input: '*** Begin Patch\n*** Add File: patched.txt\n+hello\n*** End Patch\n' }]),
  ];
  const worktree = path.join(home, 'state', 'worktrees', session);
  const prompt = script(steps).replace(/WORKTREE/g, worktree);
  try {
    const launch = await command(d, api, 'launch', session, { runtime, workspace_id: 'probe', branch: `agenomic/probe-${Date.now()}`, mode: 'enforce', prompt, capture: { conversation: true, commands: true, diffs: true, outputs: false } });
    set('observe', launch === 'applied' && (await until(() => api.has('session.started'), 30000)), `launch ${launch}`);
    if (runtime === 'claude_code') {
      const asked = await until(() => api.has('question.asked'), 60000);
      const q = api.events.find((e) => e.type === 'question.asked');
      const answered = asked ? await command(d, api, 'answer_question', session, { question_id: q.payload.question_id, text: 'b' }) : 'missing';
      set('user_questions', answered === 'applied' && (await until(() => api.has('question.answered'), 10000)), `answer ${answered}`);
    }
    const idle1 = await until(() => api.has('turn.completed'), 90000);
    const inside = fs.existsSync(path.join(worktree, 'inside.txt'));
    const denied = !fs.existsSync(path.join(worktree, 'deny-me.txt'));
    const outsideBlocked = !fs.existsSync(outside);
    const approved = fs.existsSync(path.join(worktree, 'approved.txt'));
    set('pre_tool_control', idle1 && inside && denied && outsideBlocked, `allowed write ${inside}, denied write absent ${denied}, outside write blocked by sandbox ${outsideBlocked}`);
    set('remote_approval', approved, `approved action executed after the approval: ${approved}`);
    const humanSafe = fs.readFileSync(path.join(repo, 'human-wip.txt'), 'utf8') === 'uncommitted human work\n';
    // inside.txt is created, not staged: the captured diff carries its content too.
    const snapshot = (e: any) => (e.payload.files ?? []).some((f: any) => f.path === 'inside.txt') && /\+\+\+ b\/inside\.txt\n@@ -0,0 \+1 @@\n\+in\n/.test(e.payload.diff ?? '');
    set('file_diffs', api.has('diff.snapshot', snapshot) && humanSafe, `diff snapshot lists inside.txt with its content; human checkout untouched ${humanSafe}`);
    if (runtime === 'codex') {
      // Codex offers apply_patch only for some model families; when it is
      // not offered, the fileChange approval path is not validated here.
      const offered = api.has('file.changed') || fs.existsSync(path.join(worktree, 'patched.txt'));
      results.pre_tool_control!.detail += offered ? ', apply_patch via fileChange approval ok' : ', apply_patch not offered by this Codex model configuration: fileChange approval not validated';
    }
    const before = api.events.filter((e) => e.type === 'turn.completed').length;
    const sent = await command(d, api, 'send_message', session, { text: script([shell('echo two > two.txt')], 'second turn') });
    const two = await until(() => fs.existsSync(path.join(worktree, 'two.txt')) && api.events.filter((e) => e.type === 'turn.completed').length > before, 60000);
    set('converse', sent === 'applied' && two, `second message ${sent}, executed ${two}`);
    // A turn that is still running when the interrupt arrives: the long
    // command started and has not completed.
    const endedBefore = () => api.events.filter((e) => e.type === 'turn.completed' || e.type === 'turn.interrupted').length;
    await command(d, api, 'send_message', session, { text: script([shell('node slow.mjs')], 'long turn') });
    await until(() => api.authorizations.some((a) => JSON.stringify(a.input).includes('slow.mjs')), 30000);
    await sleep(2000);
    const runningAtInterrupt = !api.events.some((e) => (e.type === 'tool.completed' || e.type === 'tool.failed') && JSON.stringify(e.payload).includes('slow.mjs'));
    const ended0 = endedBefore();
    const t0 = Date.now();
    const intr = await command(d, api, 'interrupt_turn', session, {});
    const interrupted = await until(() => endedBefore() > ended0, 20000);
    const elapsed = Date.now() - t0;
    set('interrupt_turn', intr === 'applied' && runningAtInterrupt && interrupted && elapsed < 20000, `turn running at interrupt ${runningAtInterrupt}; interrupt ${intr}; turn ended ${interrupted} after ${elapsed} ms (command would run 60 s)`);
    const stop = await command(d, api, 'stop_process', session, {});
    set('stop_process', stop === 'applied', `stop ${stop} (process exit verified)`);
    const nativeBefore = api.events.find((e) => e.type === 'session.started')?.payload;
    const resumed = await command(d, api, 'resume_session', session, { prompt: script([shell('echo three > three.txt')], 'resumed') });
    const three = await until(() => fs.existsSync(path.join(worktree, 'three.txt')), 60000);
    set('resume', resumed === 'applied' && three && !!nativeBefore, `resume ${resumed}, executed in the same worktree ${three}`);
    await command(d, api, 'stop_process', session, {});
  } finally {
    await d.stop();
  }
  return { runtime, surface: runtime === 'claude_code' ? 'sdk' : 'app_server', version: await probedVersion(cfg, runtime), at: new Date().toISOString(), results };
}

/** Runs a CLI with stdin closed; resolves with its exit code and the end of its output. */
function runCli(command: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv; timeoutMs: number }): Promise<{ code: number | null; tail: string }> {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd: opts.cwd, env: opts.env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    const keep = (d: Buffer) => (out = (out + d).slice(-4000));
    child.stdout.on('data', keep);
    child.stderr.on('data', keep);
    const t = setTimeout(() => child.kill('SIGKILL'), opts.timeoutMs);
    child.on('error', (e) => keep(Buffer.from(String(e))));
    child.on('close', (code) => {
      clearTimeout(t);
      resolve({ code, tail: out });
    });
  });
}

/**
 * The Codex CLI surface (local sessions): a terminal `codex exec` session
 * in a declared workspace, run with the configured Codex binary and the
 * connector's hooks installed in its CODEX_HOME, reported to and decided
 * by this daemon. It validates what those hooks can do: report the
 * session, refuse a shell call before it runs, and hold one until its
 * approval. The other capabilities of the surface are unsupported.
 *
 * @example
 * const result = await probeCodexCli(await fakeResponses(), tmpHome, loadConfig());
 */
export async function probeCodexCli(fake: FakeServer, home: string, machine: ConnectorConfig): Promise<ProbeResult> {
  process.env.AGENOMIC_CONNECTOR_HOME = home;
  const repo = tempRepo();
  const cfg = probeConfig(machine, 'codex', fake.url, repo);
  cfg.local_sessions.mode = 'enforce';
  const api = new ProbeApi();
  const d = new Daemon(cfg, api);
  await d.start();
  const results: ProbeResult['results'] = {};
  const set = (k: CapName, ok: boolean, detail: string) => (results[k] = { ok, detail });
  const codexHome = path.join(home, 'codex-cli');
  fs.mkdirSync(codexHome, { recursive: true, mode: 0o700 });
  const file = path.join(codexHome, 'config.toml');
  fs.writeFileSync(file, codexProviderToml(fake.url) + '\n', { mode: 0o600 });
  const exe = codexExecutable(cfg.runtimes.codex);
  try {
    const hooks = await installCodex(file, 'closed', exe, repo, false, undefined, undefined, runtimeEnv(cfg.runtimes.codex, { HOME: codexHome })).catch((e: Error) => ({ trusted: 0, preToolUse: false, error: e.message }));
    const shell = (cmd: string) => ({ tool: 'exec_command', input: { cmd } });
    const steps = [shell('echo in > inside.txt'), shell('echo deny-me > deny-me.txt'), shell('echo approve-me > approved.txt')];
    const run = hooks.preToolUse
      ? await runCli(exe.endsWith('.js') ? process.execPath : exe, [...(exe.endsWith('.js') ? [exe] : []), 'exec', '--skip-git-repo-check', '-s', 'workspace-write', script(steps, 'cli probe')], {
          cwd: repo,
          env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: codexHome, CODEX_HOME: codexHome, AGENOMIC_SCRIPTED_KEY: 'probe-not-a-key' },
          timeoutMs: 180000,
        })
      : { code: null, tail: 'error' in hooks ? hooks.error : 'codex did not report the installed PreToolUse hook as trusted' };
    await until(() => api.has('session.ended'), 10000);
    const why = run.code === 0 ? '' : `; codex exec exited ${run.code}: ${clean(run.tail.split('\n').slice(-3).join(' '), 300, runtimeSecrets(cfg.runtimes.codex))}`;
    // Until this probe validated pre-tool control, the enforce session is reported blocked.
    const reported = api.states.some((s) => s.mode_effective === 'enforce' || s.mode_effective === 'blocked') && api.has('session.started') && api.has('tool.requested') && api.has('tool.completed') && api.has('turn.completed');
    set('observe', run.code === 0 && reported, `hooks trusted ${hooks.trusted}; session, tool calls and turn end reported ${reported}${why}`);
    const inside = fs.existsSync(path.join(repo, 'inside.txt'));
    const denied = !fs.existsSync(path.join(repo, 'deny-me.txt'));
    set('pre_tool_control', run.code === 0 && inside && denied, `allowed shell call ran ${inside}, denied shell call absent ${denied}${why}`);
    const approved = fs.existsSync(path.join(repo, 'approved.txt')) && api.has('approval.resolved');
    set('remote_approval', run.code === 0 && approved, `shell call held by the hook ran after its approval ${approved}${why}`);
  } finally {
    await d.stop();
  }
  return { runtime: 'codex', surface: 'cli_hooks', version: await probedVersion(cfg, 'codex'), at: new Date().toISOString(), results };
}

/** The surfaces `doctor --probe` validates, per runtime. */
const SURFACES = [['claude_code', 'sdk'], ['codex', 'app_server'], ['codex', 'cli_hooks']] as const;

/**
 * `doctor --probe`: validates the surfaces of the runtimes this machine
 * is configured with (enabled ones only, with their configured
 * executable) and records the result under the version of the binary
 * that ran.
 *
 * @example
 * for (const r of await runProbe()) console.log(r.runtime, r.surface, r.results);
 */
export async function runProbe(machine: ConnectorConfig = loadConfig()): Promise<ProbeResult[]> {
  const realHome = process.env.AGENOMIC_CONNECTOR_HOME;
  const out: ProbeResult[] = [];
  for (const [runtime, surface] of SURFACES) {
    if (!machine.runtimes[runtime].enabled) continue;
    const fake = runtime === 'claude_code' ? await fakeAnthropic() : await fakeResponses();
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'agn-probe-home-'));
    try {
      out.push(surface === 'cli_hooks' ? await probeCodexCli(fake, home, machine) : await probeRuntime(runtime, fake, home, machine));
    } finally {
      await fake.close();
      if (realHome) process.env.AGENOMIC_CONNECTOR_HOME = realHome;
      else delete process.env.AGENOMIC_CONNECTOR_HOME;
    }
  }
  for (const r of out) saveProbe(r);
  return out;
}
