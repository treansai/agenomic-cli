import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { RunnerApi } from './api.ts';
import { manifest } from './capabilities.ts';
import { ClaudeSession, claudeCodeVersion, readClaudeCodeVersion, sdkVersion } from './claude.ts';
import { CodexSession, codexVersion, readCodexVersion } from './codex.ts';
import { DEFAULT_CAPTURE, paths, runtimeSecrets, type Capture, type ConnectorConfig, type Mode, type WorkspaceConfig } from './config.ts';
import { EventSink } from './events.ts';
import { protection } from './protection.ts';
import { clean } from './redact.ts';
import { SessionContext, type Runtime, type Verdict } from './session.ts';
import { errorMessage, log, readJson, resolveExecutable, sleep, ulid, writeSecretFile } from './util.ts';
import * as ws from './workspace.ts';

const VERSION = '0.1.0';

type Adapter = ClaudeSession | CodexSession;

interface Managed {
  id: string;
  runtime: Runtime;
  origin: 'launched' | 'local_connected';
  ctx: SessionContext;
  adapter?: Adapter;
  status: string;
  cwd: string;
  nativeId?: string;
  workspaceId?: string;
}

interface Persisted {
  [codingSessionId: string]: { runtime: Runtime; cwd: string; base_revision: string | null; native_id?: string; mode: Mode; capture: Capture; workspace_id?: string };
}

export function sandboxAvailable(): { ok: boolean; detail: string } {
  if (process.platform === 'darwin') return { ok: true, detail: 'macOS seatbelt' };
  if (process.platform !== 'linux') return { ok: false, detail: `no supported sandbox on ${process.platform}` };
  try {
    execFileSync('bwrap', ['--ro-bind', '/', '/', '--dev', '/dev', 'true'], { stdio: 'ignore', timeout: 5000 });
    return { ok: true, detail: 'bubblewrap' };
  } catch {
    return { ok: false, detail: 'bubblewrap is missing or cannot create namespaces' };
  }
}

/**
 * The machine connector: one outbound authenticated connection to
 * Agenomic (heartbeat, long-poll of commands, events), the adapters that
 * own launched runtime processes, and a local socket for the command hooks
 * of the developer's own sessions. Nothing listens on the network.
 */
export class Daemon {
  readonly api: RunnerApi;
  readonly bootId = ulid();
  private readonly sessions = new Map<string, Managed>();
  private readonly byNative = new Map<string, Managed>();
  private server: net.Server | undefined;
  private readonly abort = new AbortController();
  private readonly inflight = new Set<string>();
  private readonly finished = new Map<string, { status: 'applied' | 'refused' | 'unknown'; result?: unknown; error?: string }>();
  private persisted: Persisted;

  readonly cfg: ConnectorConfig;

  constructor(cfg: ConnectorConfig, api?: RunnerApi) {
    this.cfg = cfg;
    this.api = api ?? new RunnerApi(cfg.endpoint);
    this.persisted = readJson<Persisted>(paths.sessions()) ?? {};
  }

  private persist(): void {
    writeSecretFile(paths.sessions(), JSON.stringify(this.persisted, null, 2));
  }

  runtimes(): any[] {
    const out: any[] = [];
    const sb = sandboxAvailable();
    // The version is the one of the binary sessions run (a configured
    // executable reports its own): a probe of another binary never
    // validates it. One that cannot tell its version stays listed, with
    // nothing validated, and so does one whose `--version` has not
    // answered yet (read in the background, never awaited here).
    const cc = this.cfg.runtimes.claude_code;
    if (cc.enabled) {
      const sdk = sdkVersion();
      if (sdk) {
        const version = claudeCodeVersion(cc) ?? null;
        const caps = manifest('claude_code', 'sdk', version);
        if (!sb.ok) caps.pre_tool_control = { ...caps.pre_tool_control!, validated: 'unsupported', detail: `sandbox unavailable: ${sb.detail}` };
        out.push({ runtime: 'claude_code', version: version ?? 'unknown', sdk_version: sdk, surfaces: ['sdk', 'cli_hooks'], capabilities: caps });
      }
    }
    const cx = this.cfg.runtimes.codex;
    if (cx.enabled) {
      const version = codexVersion(cx) ?? null;
      if (version || (cx.executable && resolveExecutable(cx.executable))) {
        out.push({ runtime: 'codex', version: version ?? 'unknown', surfaces: ['app_server', 'cli_hooks'], capabilities: manifest('codex', 'app_server', version) });
      }
    }
    return out;
  }

  async heartbeat(): Promise<void> {
    await this.api.request('POST', '/v1/coding/runner/heartbeat', {
      body: {
        boot_id: this.bootId,
        connector_version: VERSION,
        runtimes: this.runtimes(),
        workspaces: this.cfg.workspaces.map((w) => ({ id: w.id, name: w.name, repo: w.repo, default_branch: w.default_branch })),
        sessions: [...this.sessions.values()].map((s) => ({
          coding_session_id: s.id,
          status: s.status,
          pid_alive: s.adapter ? s.adapter.alive() : undefined,
        })),
      },
      retry: true,
      timeoutMs: 20000,
    });
  }

  async start(): Promise<void> {
    fs.mkdirSync(paths.state(), { recursive: true, mode: 0o700 });
    await this.listen();
    const versions = this.readVersions();
    await this.heartbeat();
    log('info', 'connector connected', { endpoint: this.cfg.endpoint, workspaces: this.cfg.workspaces.length });
    // A runtime version still unknown in that heartbeat is reported as
    // soon as its `--version` has answered.
    void versions
      .then((pending) => (pending && !this.abort.signal.aborted ? this.heartbeat() : undefined))
      .catch((error) => log('warn', 'heartbeat failed', { error: errorMessage(error) }));
    void this.loop('heartbeat', 20000, () => this.heartbeat());
    void this.commandLoop();
  }

  /** Reads the configured runtime versions; true when one of them was not known yet. */
  private async readVersions(): Promise<boolean> {
    const { claude_code: cc, codex: cx } = this.cfg.runtimes;
    const pending = (cc.enabled && claudeCodeVersion(cc) === undefined) || (cx.enabled && codexVersion(cx) === undefined);
    await Promise.all([cc.enabled ? readClaudeCodeVersion(cc) : null, cx.enabled ? readCodexVersion(cx) : null]);
    return pending;
  }

  async stop(): Promise<void> {
    this.abort.abort();
    this.server?.close();
    for (const s of this.sessions.values()) {
      if (s.adapter?.alive()) await s.adapter.stop();
      await s.ctx.sink.close();
    }
  }

  private async loop(name: string, everyMs: number, fn: () => Promise<void>): Promise<void> {
    while (!this.abort.signal.aborted) {
      await sleep(everyMs, this.abort.signal);
      if (this.abort.signal.aborted) return;
      try {
        await fn();
      } catch (error) {
        log('warn', `${name} failed`, { error: errorMessage(error) });
      }
    }
  }

  private async commandLoop(): Promise<void> {
    while (!this.abort.signal.aborted) {
      try {
        const r = await this.api.request('GET', '/v1/coding/runner/commands?wait=25', { timeoutMs: 40000, signal: this.abort.signal });
        for (const cmd of r.commands ?? []) void this.deliver(cmd);
      } catch (error) {
        if (this.abort.signal.aborted) return;
        log('warn', 'command poll failed', { error: errorMessage(error) });
        await sleep(3000, this.abort.signal);
      }
    }
  }

  /**
   * The gateway redelivers a command whose result it has not received (a
   * poll response can be lost): one that is still running is not started
   * twice, and one already done gets its result posted again.
   */
  private async deliver(cmd: any): Promise<void> {
    if (this.inflight.has(cmd.id)) return;
    const done = this.finished.get(cmd.id);
    if (done) return this.result(cmd.id, done.status, done.result, done.error);
    this.inflight.add(cmd.id);
    try {
      await this.handleCommand(cmd);
    } finally {
      this.inflight.delete(cmd.id);
    }
  }

  private async result(id: string, status: 'applied' | 'refused' | 'unknown', result?: unknown, error?: string): Promise<void> {
    this.finished.set(id, { status, result, error });
    if (this.finished.size > 500) this.finished.delete(this.finished.keys().next().value!);
    try {
      await this.api.request('POST', `/v1/coding/runner/commands/${id}/result`, { body: { status, result, error: error ? clean(error, 500) : undefined }, retry: true });
    } catch (e) {
      log('warn', 'command result not recorded', { command: id, error: errorMessage(e) });
    }
  }

  async handleCommand(cmd: any): Promise<void> {
    const s = this.sessions.get(cmd.coding_session_id);
    try {
      switch (cmd.kind) {
        case 'launch':
          return await this.launch(cmd);
        case 'send_message': {
          if (!s?.adapter) return this.result(cmd.id, 'refused', undefined, 'session is not running on this runner');
          const r = s.adapter instanceof CodexSession ? await s.adapter.send(cmd.payload.text, cmd.payload.expected_turn_id ?? undefined) : s.adapter.send(cmd.payload.text);
          return this.result(cmd.id, r);
        }
        case 'answer_question': {
          if (!s?.adapter) return this.result(cmd.id, 'refused', undefined, 'session is not running on this runner');
          return this.result(cmd.id, s.adapter.answer(String(cmd.payload.question_id), cmd.payload.text));
        }
        case 'interrupt_turn': {
          if (!s?.adapter) return this.result(cmd.id, 'refused', undefined, 'session is not running on this runner');
          return this.result(cmd.id, await s.adapter.interrupt());
        }
        case 'stop_process': {
          if (!s?.adapter) return this.result(cmd.id, 'refused', undefined, 'session is not running on this runner');
          const r = await s.adapter.stop();
          if (r === 'applied') await this.setStatus(s, 'stopped');
          return this.result(cmd.id, r, { process_exited: r === 'applied' });
        }
        case 'resume_session':
          return await this.resume(cmd);
        default:
          return this.result(cmd.id, 'refused', undefined, `unsupported command ${cmd.kind}`);
      }
    } catch (error) {
      log('warn', 'command failed', { kind: cmd.kind, error: errorMessage(error) });
      return this.result(cmd.id, 'unknown', undefined, errorMessage(error));
    }
  }

  private workspace(id: string): WorkspaceConfig | undefined {
    return this.cfg.workspaces.find((w) => w.id === id);
  }

  /** Reports a status (with `extra` fields); a failed report is logged, never fatal. */
  private async setStatus(s: Managed, status: string, extra: Record<string, unknown> = {}): Promise<void> {
    s.status = status;
    try {
      await s.ctx.state({ status, ...extra });
    } catch (error) {
      log('warn', 'state update failed', { session: s.id, error: errorMessage(error) });
    }
  }

  private async launch(cmd: any): Promise<void> {
    const p = cmd.payload ?? {};
    const sessionId: string = cmd.coding_session_id;
    if (this.sessions.has(sessionId) || this.persisted[sessionId]) {
      // A retried launch after a timeout: never start a second process.
      return this.result(cmd.id, this.sessions.get(sessionId)?.adapter?.alive() ? 'applied' : 'unknown', undefined, 'launch already handled on this runner');
    }
    const workspace = this.workspace(p.workspace_id);
    if (!workspace) return this.result(cmd.id, 'refused', undefined, 'workspace not declared on this runner');
    const runtime: Runtime = p.runtime;
    const rcfg = runtime === 'claude_code' ? this.cfg.runtimes.claude_code : this.cfg.runtimes.codex;
    if (!rcfg.enabled) return this.result(cmd.id, 'refused', undefined, `${runtime} is disabled on this runner`);
    const mode: Mode = p.mode;
    if (mode === 'enforce' && runtime === 'claude_code' && !sandboxAvailable().ok) {
      return this.result(cmd.id, 'refused', undefined, 'enforce needs the Claude Code sandbox, which is unavailable on this machine');
    }
    const target = path.join(paths.worktrees(), sessionId);
    let tree: ReturnType<typeof ws.createWorktree>;
    try {
      tree = ws.createWorktree(workspace.path, target, p.branch ?? null);
    } catch (error) {
      return this.result(cmd.id, 'refused', undefined, errorMessage(error));
    }
    const capture: Capture = { ...DEFAULT_CAPTURE, ...(p.capture ?? {}) };
    this.persisted[sessionId] = { runtime, cwd: tree.path, base_revision: tree.base_revision, mode, capture, workspace_id: workspace.id };
    this.persist();
    const managed = this.manage(sessionId, runtime, 'launched', mode, capture, tree.path, tree.base_revision, p.trace_id, workspace.id);
    // Best effort: a gateway that is briefly unavailable must not leave a
    // worktree and a persisted launch without its adapter. Starting is not
    // a connected status; the report after the start establishes the mode.
    await this.setStatus(managed, 'starting', {
      workspace: { base_revision: tree.base_revision, branch: tree.branch, preexisting_changes: tree.preexisting_changes.length, worktree: 'dedicated' },
    });
    try {
      await this.startAdapter(managed, rcfg, { model: p.model, prompt: p.prompt });
    } catch (error) {
      // The partial adapter is stopped (startAdapter); the session is no
      // longer managed, so no later command reaches it.
      this.sessions.delete(sessionId);
      await this.setStatus(managed, 'failed');
      await managed.ctx.sink.close();
      return this.result(cmd.id, 'refused', undefined, errorMessage(error));
    }
    const prot = protection(runtime, runtime === 'claude_code' ? 'sdk' : 'app_server', mode);
    const caps = this.runtimes().find((r) => r.runtime === runtime)?.capabilities ?? {};
    await managed.ctx.state({
      mode_effective: mode,
      protection: { protected: prot.protected, not_covered: prot.not_covered, notes: prot.notes },
      limitations: prot.limitations,
      capabilities: caps,
    });
    return this.result(cmd.id, 'applied', { worktree: 'dedicated', native_session_id: managed.nativeId ?? null });
  }

  private manage(id: string, runtime: Runtime, origin: Managed['origin'], mode: Mode, capture: Capture, cwd: string, base: string | null, traceId?: string, workspaceId?: string): Managed {
    // Runner credentials and the runtime's own credential values, redacted
    // from every event of the session before it is buffered.
    const rcfg = runtime === 'claude_code' ? this.cfg.runtimes.claude_code : this.cfg.runtimes.codex;
    const secrets = () => [this.api.credentials()?.access_token ?? '', this.api.credentials()?.refresh_token ?? '', ...runtimeSecrets(rcfg)].filter(Boolean);
    const sink = new EventSink(this.api, id, secrets, paths.spool());
    const ctx = new SessionContext(this.api, id, runtime, mode, sink, capture, cwd, base, traceId, secrets);
    const m: Managed = { id, runtime, origin, ctx, status: 'starting', cwd, workspaceId };
    this.sessions.set(id, m);
    return m;
  }

  private async startAdapter(m: Managed, rcfg: ConnectorConfig['runtimes']['claude_code'], o: { model?: string; prompt?: string; resume?: string }): Promise<void> {
    const onNativeSession = async (nativeId: string) => {
      m.nativeId = nativeId;
      this.byNative.set(`${m.runtime}:${nativeId}`, m);
      const rec = this.persisted[m.id];
      if (rec) {
        rec.native_id = nativeId;
        this.persist();
      }
      await this.api.request('POST', '/v1/coding/runner/sessions', {
        body: { coding_session_id: m.id, runtime: m.runtime, origin: 'launched', runtime_session_id: nativeId, base_revision: m.ctx.baseRevision ?? undefined },
        retry: true,
      });
    };
    const onStatus = (status: string) => void this.setStatus(m, status);
    const common = { ctx: m.ctx, cwd: m.cwd, model: o.model ?? null, prompt: o.prompt ?? null, resume: o.resume ?? null, runtime: rcfg, onNativeSession, onStatus };
    const adapter: Adapter = m.runtime === 'claude_code' ? new ClaudeSession(common) : new CodexSession(common);
    m.adapter = adapter;
    try {
      await adapter.start();
    } catch (error) {
      // A start that failed after the process was spawned (initialization,
      // thread start or the session registration): commands no longer
      // reach the adapter, and its process is stopped.
      m.adapter = undefined;
      if (m.nativeId && this.byNative.get(`${m.runtime}:${m.nativeId}`) === m) this.byNative.delete(`${m.runtime}:${m.nativeId}`);
      const stopped = await adapter.stop().catch(() => 'unknown' as const);
      if (stopped !== 'applied') log('warn', 'runtime process of a failed start may still run', { session: m.id });
      throw error;
    }
    void adapter.done.then(async () => {
      if (m.status !== 'stopped') await this.setStatus(m, 'stopped');
      await m.ctx.sink.flush();
    });
  }

  private async resume(cmd: any): Promise<void> {
    const rec = this.persisted[cmd.coding_session_id];
    const live = this.sessions.get(cmd.coding_session_id);
    if (live?.adapter?.alive()) return this.result(cmd.id, 'refused', undefined, 'the session is still running');
    if (!rec?.native_id) return this.result(cmd.id, 'refused', undefined, 'no native session recorded on this runner');
    const rcfg = rec.runtime === 'claude_code' ? this.cfg.runtimes.claude_code : this.cfg.runtimes.codex;
    const m = live ?? this.manage(cmd.coding_session_id, rec.runtime, 'launched', rec.mode, rec.capture, rec.cwd, rec.base_revision, undefined, rec.workspace_id);
    // Resume is always by explicit native id, never "the last session".
    try {
      await this.startAdapter(m, rcfg, { resume: rec.native_id, prompt: cmd.payload?.prompt ?? undefined });
    } catch (error) {
      if (!live) {
        this.sessions.delete(m.id);
        await m.ctx.sink.close();
      }
      return this.result(cmd.id, 'refused', undefined, errorMessage(error));
    }
    await this.setStatus(m, 'running');
    return this.result(cmd.id, 'applied');
  }

  // ── Local hook socket ─────────────────────────────────────────────────

  private async listen(): Promise<void> {
    const sock = paths.socket();
    if (fs.existsSync(sock)) {
      // A live daemon answers; a stale socket file does not.
      const alive = await new Promise<boolean>((resolve) => {
        const c = net.createConnection(sock);
        c.on('connect', () => {
          c.destroy();
          resolve(true);
        });
        c.on('error', () => resolve(false));
      });
      if (alive) throw new Error('another connector daemon is running');
      fs.rmSync(sock);
    }
    this.server = net.createServer((conn) => {
      let buf = '';
      conn.on('data', async (d) => {
        buf += d;
        if (buf.length > 2 * 1024 * 1024) return conn.destroy();
        const nl = buf.indexOf('\n');
        if (nl < 0) return;
        const line = buf.slice(0, nl);
        buf = '';
        let reply: unknown;
        try {
          reply = await this.onLocal(JSON.parse(line));
        } catch (error) {
          reply = { error: errorMessage(error) };
        }
        conn.end(JSON.stringify(reply) + '\n');
      });
      conn.on('error', () => undefined);
    });
    const old = process.umask(0o177);
    try {
      await new Promise<void>((resolve, reject) => this.server!.listen(sock, resolve).once('error', reject));
    } finally {
      process.umask(old);
    }
    fs.chmodSync(sock, 0o600);
  }

  private async onLocal(req: any): Promise<unknown> {
    if (req?.op !== 'hook') throw new Error('unsupported request');
    const runtime: Runtime = req.runtime === 'codex' ? 'codex' : 'claude_code';
    const input = req.input ?? {};
    const event: string = input.hook_event_name ?? '';
    const native = String(input.session_id ?? '');
    let m = this.byNative.get(`${runtime}:${native}`);
    if (!m) {
      m = await this.registerLocal(runtime, native, String(input.cwd ?? ''));
      if (!m) return {}; // outside every declared workspace: nothing is sent
    }
    const ctx = m.ctx;
    // A launched Codex session routes its trusted PreToolUse hook here;
    // everything else its hooks report, the App Server notifications
    // already did (a second tool.completed would count the call twice).
    if (m.origin === 'launched' && event !== 'PreToolUse') return {};
    switch (event) {
      case 'SessionStart':
        ctx.sink.emit('session.started', 'runtime', 'native', { source: input.source, model: input.model });
        return {};
      case 'UserPromptSubmit':
        ctx.sink.emit('message.user', 'runtime', 'native', ctx.capture.conversation ? { text: ctx.cleanText(String(input.prompt ?? ''), 16000) } : { length: String(input.prompt ?? '').length });
        return {};
      case 'PreToolUse': {
        const v: Verdict = await ctx.authorize({
          nativeId: String(input.tool_use_id ?? `${native}:${Date.now()}`),
          tool: String(input.tool_name ?? 'unknown'),
          input: input.tool_input ?? {},
          context: {
            cwd: input.cwd,
            workspace_root: m.cwd,
            base_revision: ctx.baseRevision,
            permission_mode: input.permission_mode,
            sandbox: m.origin === 'launched' ? 'workspace-write' : undefined,
          },
          phase: 'pre_tool',
          turnId: input.turn_id,
          waitForApproval: true,
        });
        if (v.decision === 'deny') {
          return { output: { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `Agenomic: ${v.reason}` } } };
        }
        // Never answer allow: the native permission flow still applies.
        return {};
      }
      case 'PostToolUse':
      case 'PostToolUseFailure': {
        const failed = event === 'PostToolUseFailure';
        const v = ctx.toolEvent(failed ? 'tool.failed' : 'tool.completed', String(input.tool_use_id ?? `${native}:no-tool-use-id`), { native_tool: input.tool_name }, { runtime_turn_id: input.turn_id });
        await ctx.report(v?.actionId, failed ? 'failed' : 'completed');
        return {};
      }
      case 'SubagentStart':
      case 'SubagentStop':
        ctx.sink.emit(event === 'SubagentStart' ? 'subagent.started' : 'subagent.stopped', 'runtime', 'native', { agent_id: input.agent_id, agent_type: input.agent_type });
        return {};
      case 'Stop':
        // End of a turn, not of the session.
        ctx.sink.emit('turn.completed', 'runtime', 'native', {}, { runtime_turn_id: input.turn_id });
        void ctx.settleOpen('turn ended before the tool reported');
        return {};
      case 'SessionEnd':
        ctx.sink.emit('session.ended', 'runtime', 'native', { reason: input.reason });
        void ctx.settleFinal('session ended before the tool reported');
        if (m.origin === 'local_connected') {
          await this.setStatus(m, 'stopped');
          await ctx.sink.close();
          this.sessions.delete(m.id);
          this.byNative.delete(`${runtime}:${native}`);
        }
        return {};
      default:
        return {};
    }
  }

  /** A developer session in a declared workspace, seen for the first time. */
  private async registerLocal(runtime: Runtime, native: string, cwd: string): Promise<Managed | undefined> {
    if (!native || !cwd) return undefined;
    const real = (() => {
      try {
        return fs.realpathSync(cwd);
      } catch {
        return cwd;
      }
    })();
    const workspace = this.cfg.workspaces.find((w) => real === w.path || real.startsWith(w.path + path.sep));
    if (!workspace) return undefined;
    const state = ws.inspect(workspace.path);
    const local = this.cfg.local_sessions;
    const res = await this.api.request('POST', '/v1/coding/runner/sessions', {
      body: {
        runtime,
        origin: 'local_connected',
        runtime_session_id: native,
        workspace_id: workspace.id,
        repo: workspace.repo,
        branch: state.branch ?? undefined,
        base_revision: state.base_revision ?? undefined,
        cwd_hint: real.replace(os.homedir(), '~'),
        mode_requested: local.mode,
        policy_refs: local.policy_refs,
        surface: 'cli_hooks',
        capture: local.capture,
      },
      retry: true,
    });
    const id: string = res.session.id;
    const existing = this.sessions.get(id);
    if (existing) {
      this.byNative.set(`${runtime}:${native}`, existing);
      return existing;
    }
    const m = this.manage(id, runtime, 'local_connected', local.mode, local.capture, workspace.path, state.base_revision, res.session.trace_id, workspace.id);
    m.status = 'running';
    m.nativeId = native;
    this.byNative.set(`${runtime}:${native}`, m);
    const caps = manifest(runtime, 'cli_hooks', this.runtimes().find((r) => r.runtime === runtime)?.version ?? null);
    const prot = protection(runtime, 'cli_hooks', local.mode);
    await m.ctx.state({
      status: 'running',
      mode_effective: local.mode,
      protection: { protected: prot.protected, not_covered: prot.not_covered, notes: prot.notes },
      capabilities: caps,
      limitations: [...prot.limitations, 'a session that was already open before the hooks were installed must be restarted to be connected'],
      workspace: { base_revision: state.base_revision, branch: state.branch, preexisting_changes: state.preexisting_changes.length },
    });
    return m;
  }
}
