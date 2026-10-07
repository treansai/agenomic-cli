import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { ApiError, RunnerApi } from './api.ts';
import { manifest, type CapEntry } from './capabilities.ts';
import { ClaudeSession, claudeCodeVersion, readClaudeCodeVersion, sdkVersion } from './claude.ts';
import { CodexSession, codexVersion, readCodexVersion } from './codex.ts';
import { DEFAULT_CAPTURE, paths, runtimeSecrets, type Capture, type ConnectorConfig, type Mode, type WorkspaceConfig } from './config.ts';
import { EventSink } from './events.ts';
import { blockedProtection, protection, type Surface } from './protection.ts';
import { clean } from './redact.ts';
import { SessionContext, type Runtime, type Verdict } from './session.ts';
import { errorMessage, executableVersion, log, readExecutableVersion, readJson, redactLogsWith, resolveExecutable, sleep, ulid, writeSecretFile } from './util.ts';
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
  /**
   * For a local session, the executable of the runtime process that runs
   * it (reported by its hook): its capabilities are validated for that
   * binary's version, never for the configured one's.
   */
  executable?: string;
  /** The surface the session connected through, and the mode fields last reported for it. */
  surface?: Surface;
  limitations?: string[];
  reportedMode?: string;
  /**
   * Whether the report that establishes the session's mode (connect) was
   * made. Until then a status the runtime reports is only held: no
   * connected status reaches the gateway without the effective mode.
   */
  connected: boolean;
  held?: string;
  /** State reports of the session, sent one after the other. */
  reports: Promise<void>;
}

interface Persisted {
  [codingSessionId: string]: {
    runtime: Runtime;
    cwd: string;
    base_revision: string | null;
    native_id?: string;
    mode: Mode;
    capture: Capture;
    workspace_id?: string;
    /** Real path of the workspace checkout at launch: a resume is refused once the workspace id points elsewhere. */
    workspace_root?: string;
  };
}

/**
 * Whether the Claude Code sandbox can run here (seatbelt on macOS, bubblewrap on Linux).
 *
 * @example
 * const sb = sandboxAvailable();
 * if (!sb.ok) console.log(`enforce is unavailable: ${sb.detail}`);
 */
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

/** Real path of `p`, or `p` itself when it cannot be resolved. */
function realPath(p: string): string {
  try {
    return fs.realpathSync(p);
  } catch {
    return p;
  }
}

/**
 * Why a session recorded for a workspace cannot resume under the
 * workspace now declared with that id, or undefined when it can. A
 * workspace id can be declared again for another checkout (`workspace
 * add`): the session then belongs to the old one. The record's workspace
 * root must be the declared one's real path, and the session's directory
 * must lie in that checkout or be a worktree of its repository (a record
 * written before the root was recorded is checked on that alone).
 *
 * @example
 * workspaceMoved(persisted[sessionId], workspace); // undefined, or the refusal
 */
export function workspaceMoved(rec: { cwd: string; workspace_root?: string }, workspace: WorkspaceConfig): string | undefined {
  const root = realPath(workspace.path);
  const refusal = `workspace ${workspace.id} now names another checkout than the one the session was launched from; the session is not resumed (launch a new session)`;
  if (rec.workspace_root !== undefined && rec.workspace_root !== root) return refusal;
  const cwd = realPath(rec.cwd);
  if (cwd === root || cwd.startsWith(root + path.sep)) return undefined;
  const repo = ws.commonDir(workspace.path);
  if (repo === null || ws.commonDir(rec.cwd) !== repo) return refusal;
  return undefined;
}

/**
 * The machine connector: one outbound authenticated connection to
 * Agenomic (heartbeat, long-poll of commands, events), the adapters that
 * own launched runtime processes, and a local socket for the command hooks
 * of the developer's own sessions. Nothing listens on the network.
 *
 * @example
 * const daemon = new Daemon(loadConfig());
 * await daemon.start();
 * process.once('SIGTERM', () => void daemon.stop());
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
  private readonly unredactLogs: () => void;
  /**
   * How long connecting a session waits for its runtime's `--version`.
   * A session connected before it answered is reported with its version
   * unknown, then reported again once it has answered.
   */
  versionWaitMs = 3000;

  constructor(cfg: ConnectorConfig, api?: RunnerApi) {
    this.cfg = cfg;
    this.api = api ?? new RunnerApi(cfg.endpoint);
    this.persisted = readJson<Persisted>(paths.sessions()) ?? {};
    // Every log line of the process is redacted with the runner's tokens
    // and the credential values of both runtimes.
    this.unredactLogs = redactLogsWith(() => this.secrets());
  }

  /** The runner's tokens and the credential values given to the runtimes (one runtime's, or both). */
  private secrets(runtime?: Runtime): string[] {
    const creds = this.api.credentials();
    const runtimes = runtime ? [runtime === 'claude_code' ? this.cfg.runtimes.claude_code : this.cfg.runtimes.codex] : [this.cfg.runtimes.claude_code, this.cfg.runtimes.codex];
    return [creds?.access_token ?? '', creds?.refresh_token ?? '', ...runtimes.flatMap((r) => runtimeSecrets(r))].filter(Boolean);
  }

  private persist(): void {
    writeSecretFile(paths.sessions(), JSON.stringify(this.persisted, null, 2));
  }

  /**
   * The runtimes this machine offers, with their versions, surfaces and capability manifests, as heartbeats report them.
   *
   * @example
   * const codex = daemon.runtimes().find((r) => r.runtime === 'codex');
   */
  runtimes(): any[] {
    const out: any[] = [];
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
        out.push({ runtime: 'claude_code', version: version ?? 'unknown', sdk_version: sdk, surfaces: ['sdk', 'cli_hooks'], capabilities: this.capabilities('claude_code', 'sdk', version) });
      }
    }
    const cx = this.cfg.runtimes.codex;
    if (cx.enabled) {
      const version = codexVersion(cx) ?? null;
      if (version || (cx.executable && resolveExecutable(cx.executable))) {
        out.push({ runtime: 'codex', version: version ?? 'unknown', surfaces: ['app_server', 'cli_hooks'], capabilities: this.capabilities('codex', 'app_server', version) });
      }
    }
    return out;
  }

  /** The capability manifest of a runtime surface for a binary version; the SDK surface also needs the sandbox. */
  private capabilities(runtime: Runtime, surface: Surface, version: string | null): Record<string, CapEntry> {
    const caps = manifest(runtime, surface, version);
    if (runtime === 'claude_code' && surface === 'sdk') {
      const sb = sandboxAvailable();
      if (!sb.ok) caps.pre_tool_control = { ...caps.pre_tool_control!, validated: 'unsupported', detail: `sandbox unavailable: ${sb.detail}` };
    }
    return caps;
  }

  /**
   * Version of the binary a session runs, `undefined` while its
   * `--version` has not answered. A launched session runs the configured
   * runtime; a local one the executable its hook reported, and a local
   * session whose executable is not known has no version (nothing is
   * validated for it): the configured binary's version is never
   * substituted, since a probe of that binary says nothing about another
   * CLI the developer runs.
   */
  private sessionVersion(m: Managed): string | null | undefined {
    if (m.origin === 'local_connected') return m.executable ? executableVersion(m.executable) : null;
    return m.runtime === 'claude_code' ? claudeCodeVersion(this.cfg.runtimes.claude_code) : codexVersion(this.cfg.runtimes.codex);
  }

  /** sessionVersion(), waiting for the binary's answer. */
  private readSessionVersion(m: Managed): Promise<string | null> {
    if (m.origin === 'local_connected') return m.executable ? readExecutableVersion(m.executable) : Promise.resolve(null);
    return m.runtime === 'claude_code' ? readClaudeCodeVersion(this.cfg.runtimes.claude_code) : readCodexVersion(this.cfg.runtimes.codex);
  }

  /**
   * The mode a connected session holds, with its protection, limitations
   * and capabilities. Enforce needs pre-tool control validated on this
   * machine (supported_tested or partial) for the version the session
   * runs: without it the session is blocked, never reported as enforce.
   */
  private modeFields(m: Managed, version: string | null): Record<string, unknown> {
    const surface = m.surface!;
    const caps = this.capabilities(m.runtime, surface, version);
    const validated = (caps as Record<string, { validated?: string }>).pre_tool_control?.validated;
    const blocked = m.ctx.mode === 'enforce' && validated !== 'supported_tested' && validated !== 'partial';
    const requested = protection(m.runtime, surface, m.ctx.mode);
    const prot = blocked
      ? blockedProtection(requested, `enforce needs pre-tool control validated on this machine (agenomic-connector doctor --probe); it is ${validated ?? 'not reported'}`)
      : requested;
    return {
      mode_effective: blocked ? 'blocked' : m.ctx.mode,
      protection: { protected: prot.protected, not_covered: prot.not_covered, notes: prot.notes },
      limitations: [...prot.limitations, ...(m.limitations ?? [])],
      capabilities: caps,
    };
  }

  /**
   * Reports a connected session's mode again once the version of its
   * runtime, unknown when it connected, has answered: a session reported
   * blocked only because `--version` had not answered yet becomes enforce
   * when that version is validated, and its capabilities are those of the
   * version it runs. Nothing is sent when nothing changed.
   */
  private async refreshMode(m: Managed): Promise<void> {
    await this.readSessionVersion(m);
    if (this.abort.signal.aborted || !m.connected || this.sessions.get(m.id) !== m || m.status === 'stopped' || m.status === 'failed') return;
    const version = this.sessionVersion(m);
    if (version === undefined) return;
    const fields = this.modeFields(m, version);
    const key = JSON.stringify(fields);
    if (key === m.reportedMode) return;
    m.reportedMode = key;
    try {
      await this.reportUntil(m, { status: m.status, ...fields }, true).first;
    } catch (error) {
      log('warn', 'refreshed mode report failed; retrying', { session: m.id, error: errorMessage(error) });
    }
  }

  /**
   * Reports the runner, its runtimes, workspaces and sessions to the gateway.
   *
   * @example
   * await daemon.heartbeat();
   */
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

  /**
   * Listens on the local hook socket, sends the first heartbeat, then keeps heartbeating and polling commands.
   *
   * @example
   * await new Daemon(loadConfig()).start();
   */
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

  /**
   * Stops polling, closes the hook socket, stops the runtimes it launched and flushes their events.
   *
   * @example
   * await daemon.stop();
   */
  async stop(): Promise<void> {
    this.abort.abort();
    this.server?.close();
    for (const s of this.sessions.values()) {
      if (s.adapter?.alive()) await s.adapter.stop();
      await s.ctx.sink.close();
    }
    this.unredactLogs();
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

  private async result(id: string, status: 'applied' | 'refused' | 'unknown', result?: unknown, reason?: string): Promise<void> {
    // A refusal can quote a runtime failure: redacted with every credential value.
    const error = reason ? clean(reason, 500, this.secrets()) : undefined;
    this.finished.set(id, { status, result, error });
    if (this.finished.size > 500) this.finished.delete(this.finished.keys().next().value!);
    try {
      await this.api.request('POST', `/v1/coding/runner/commands/${id}/result`, { body: { status, result, error }, retry: true });
    } catch (e) {
      log('warn', 'command result not recorded', { command: id, error: errorMessage(e) });
    }
  }

  /**
   * Executes one gateway command and posts its result (applied, refused or unknown).
   *
   * @example
   * await daemon.handleCommand({ id: commandId, kind: 'interrupt_turn', coding_session_id: sessionId, payload: {} });
   */
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
      await this.report(s, { status, ...extra });
    } catch (error) {
      log('warn', 'state update failed', { session: s.id, error: errorMessage(error) });
    }
  }

  /**
   * Sends a state report after the session's earlier ones, so that the
   * gateway applies them in order. The promise settles with the first
   * attempt; a `persistent` report that failed is retried in the
   * background, ahead of the later reports, until it is delivered or the
   * gateway refuses it.
   */
  private report(m: Managed, body: Record<string, unknown>, persistent = false): Promise<void> {
    return this.reportUntil(m, body, persistent).first;
  }

  /** report(), with `delivered`: whether the report was, in the end, delivered. */
  private reportUntil(m: Managed, body: Record<string, unknown>, persistent: boolean): { first: Promise<void>; delivered: Promise<boolean> } {
    let settle!: (error?: unknown) => void;
    const first = new Promise<void>((resolve, reject) => (settle = (error) => (error === undefined ? resolve() : reject(error))));
    let done!: (delivered: boolean) => void;
    const delivered = new Promise<boolean>((resolve) => (done = resolve));
    m.reports = m.reports.then(async () => {
      for (let attempt = 0; ; attempt++) {
        try {
          await m.ctx.state(body);
          settle();
          return done(true);
        } catch (error) {
          settle(error);
          const refused = error instanceof ApiError && error.status >= 400 && error.status < 500;
          if (!persistent || refused || this.abort.signal.aborted) return done(false);
          log('warn', 'state report failed; retrying', { session: m.id, error: errorMessage(error) });
          await sleep(Math.min(1000 * 2 ** attempt, 30000), this.abort.signal);
        }
      }
    });
    return { first, delivered };
  }

  /** A status the runtime reports: held until the session is connected. */
  private async adapterStatus(m: Managed, status: string): Promise<void> {
    if (!m.connected) {
      m.held = status;
      return;
    }
    await this.setStatus(m, status);
  }

  /**
   * The report that connects a session once its runtime is attached and
   * its native session registered: the connected status (running, or the
   * one the runtime reported meanwhile) together with the effective mode,
   * the protection and the capabilities, in one report, so that the
   * gateway never holds a connected status without a mode. It is retried
   * until delivered. The mode follows modeFields(), for the version of
   * the runtime the session runs: connecting waits up to `versionWaitMs`
   * for a `--version` that has not answered yet, and a session connected
   * without it is reported again once it has (refreshMode). It resolves
   * after the first attempt, with whether the report was delivered then
   * (`now`) and whether it is in the end (`delivered`).
   */
  private async connect(m: Managed, surface: Surface, extra: { limitations?: string[]; workspace?: unknown } = {}): Promise<{ now: boolean; delivered: Promise<boolean> }> {
    if (this.sessionVersion(m) === undefined) {
      let timer: NodeJS.Timeout | undefined;
      await Promise.race([this.readSessionVersion(m), new Promise((resolve) => (timer = setTimeout(resolve, this.versionWaitMs)))]);
      clearTimeout(timer);
    }
    const status = m.held ?? 'running';
    m.connected = true;
    m.held = undefined;
    m.status = status;
    m.surface = surface;
    m.limitations = extra.limitations;
    const version = this.sessionVersion(m);
    const fields = this.modeFields(m, version ?? null);
    m.reportedMode = JSON.stringify(fields);
    const r = this.reportUntil(m, { status, ...fields, ...(extra.workspace ? { workspace: extra.workspace } : {}) }, true);
    if (version === undefined) void this.refreshMode(m).catch((error) => log('warn', 'mode refresh failed', { session: m.id, error: errorMessage(error) }));
    try {
      await r.first;
      return { now: true, delivered: r.delivered };
    } catch (error) {
      log('warn', 'connected state report failed; retrying', { session: m.id, error: errorMessage(error) });
      return { now: false, delivered: r.delivered };
    }
  }

  /**
   * Hands the launch or resume prompt to the runtime once the gateway
   * holds the session's effective mode: the first turn's tool calls are
   * authorized under that mode, never under the `none` of a session that
   * is not connected yet (which enforce denies). A connecting report still
   * being retried delays the prompt until it is delivered, without
   * holding the command's result; one the gateway refused leaves the
   * prompt undelivered, reported as an error event.
   */
  private async deliverPrompt(m: Managed, adapter: Adapter, prompt: string | undefined, connected: { now: boolean; delivered: Promise<boolean> }): Promise<void> {
    if (!prompt) return;
    const deliver = async () => {
      const why = !(await connected.delivered)
        ? 'the session could not be connected'
        : await Promise.resolve(adapter.send(prompt)).then(
            (r) => (r === 'applied' ? undefined : 'the session no longer runs'),
            (error) => errorMessage(error),
          );
      if (!why) return;
      log('warn', 'prompt not delivered', { session: m.id, reason: why });
      m.ctx.sink.emit('error', 'adapter', 'native', { code: 'prompt_not_delivered', message: m.ctx.cleanText(why, 500) });
    };
    if (connected.now) await deliver();
    else void deliver();
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
    this.persisted[sessionId] = { runtime, cwd: tree.path, base_revision: tree.base_revision, mode, capture, workspace_id: workspace.id, workspace_root: realPath(workspace.path) };
    this.persist();
    const managed = this.manage(sessionId, runtime, 'launched', mode, capture, tree.path, tree.base_revision, p.trace_id, workspace.id);
    // Best effort: a gateway that is briefly unavailable must not leave a
    // worktree and a persisted launch without its adapter. Starting is not
    // a connected status; the report after the start establishes the mode.
    await this.setStatus(managed, 'starting', {
      workspace: { base_revision: tree.base_revision, branch: tree.branch, preexisting_changes: tree.preexisting_changes.length, worktree: 'dedicated' },
    });
    try {
      // The prompt waits for the connected report (deliverPrompt).
      await this.startAdapter(managed, rcfg, { model: p.model });
    } catch (error) {
      // The partial adapter is stopped (startAdapter); the session is no
      // longer managed, so no later command reaches it. Its record and its
      // worktree (no prompt reached the runtime) are removed too: a launch
      // redelivered after a restart starts again rather than being taken
      // for one already handled.
      this.sessions.delete(sessionId);
      delete this.persisted[sessionId];
      this.persist();
      try {
        ws.removeWorktree(workspace.path, tree.path, p.branch ?? null, tree.base_revision);
      } catch (e) {
        log('warn', 'worktree of a refused launch not removed', { session: sessionId, error: errorMessage(e) });
      }
      await this.setStatus(managed, 'failed');
      await managed.ctx.sink.close();
      return this.result(cmd.id, 'refused', undefined, errorMessage(error));
    }
    const connected = await this.connect(managed, runtime === 'claude_code' ? 'sdk' : 'app_server');
    await this.deliverPrompt(managed, managed.adapter!, p.prompt ?? undefined, connected);
    return this.result(cmd.id, 'applied', { worktree: 'dedicated', native_session_id: managed.nativeId ?? null });
  }

  private manage(id: string, runtime: Runtime, origin: Managed['origin'], mode: Mode, capture: Capture, cwd: string, base: string | null, traceId?: string, workspaceId?: string): Managed {
    // Runner credentials and the runtime's own credential values, redacted
    // from every event of the session before it is buffered.
    const secrets = () => this.secrets(runtime);
    const sink = new EventSink(this.api, id, secrets, paths.spool());
    const ctx = new SessionContext(this.api, id, runtime, mode, sink, capture, cwd, base, traceId, secrets);
    const m: Managed = { id, runtime, origin, ctx, status: 'starting', cwd, workspaceId, connected: false, reports: Promise.resolve() };
    // Statuses the session context reports (waiting for an approval) follow the same order.
    ctx.reportStatus = (status) => void this.adapterStatus(m, status);
    this.sessions.set(id, m);
    return m;
  }

  private async startAdapter(m: Managed, rcfg: ConnectorConfig['runtimes']['claude_code'], o: { model?: string; resume?: string }): Promise<void> {
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
    const onStatus = (status: string) => void this.adapterStatus(m, status);
    const common = { ctx: m.ctx, cwd: m.cwd, model: o.model ?? null, prompt: null, resume: o.resume ?? null, runtime: rcfg, onNativeSession, onStatus };
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
      // However the runtime ended (a stop, the end of its session, a crash
      // or a kill), the actions it admitted get their final settlement:
      // retained outcomes are delivered, unreported ones settle as
      // unknown. After a stop this is the stop's own settlement.
      void m.ctx.settleFinal('runtime exited before the tool reported');
      if (m.status !== 'stopped') await this.adapterStatus(m, 'stopped');
      await m.ctx.sink.flush();
    });
  }

  private async resume(cmd: any): Promise<void> {
    const rec = this.persisted[cmd.coding_session_id];
    const live = this.sessions.get(cmd.coding_session_id);
    if (live?.adapter?.alive()) return this.result(cmd.id, 'refused', undefined, 'the session is still running');
    if (!rec?.native_id) return this.result(cmd.id, 'refused', undefined, 'no native session recorded on this runner');
    const rcfg = rec.runtime === 'claude_code' ? this.cfg.runtimes.claude_code : this.cfg.runtimes.codex;
    // Like a launch: a runtime disabled since the session was recorded is
    // not started, and the session is not managed again.
    if (!rcfg.enabled) return this.result(cmd.id, 'refused', undefined, `${rec.runtime} is disabled on this runner`);
    // The other start-time refusals of a launch hold for a resume too: a
    // workspace no longer declared here, or an enforce session of Claude
    // Code whose sandbox has since become unavailable.
    if (rec.workspace_id !== undefined) {
      const workspace = this.workspace(rec.workspace_id);
      if (!workspace) return this.result(cmd.id, 'refused', undefined, 'workspace not declared on this runner');
      const moved = workspaceMoved(rec, workspace);
      if (moved) return this.result(cmd.id, 'refused', undefined, moved);
    }
    if (rec.mode === 'enforce' && rec.runtime === 'claude_code' && !sandboxAvailable().ok) {
      return this.result(cmd.id, 'refused', undefined, 'enforce needs the Claude Code sandbox, which is unavailable on this machine');
    }
    const m = live ?? this.manage(cmd.coding_session_id, rec.runtime, 'launched', rec.mode, rec.capture, rec.cwd, rec.base_revision, undefined, rec.workspace_id);
    // The gateway's resumed session is not connected until this runner
    // re-establishes its mode: statuses are held until then.
    const before = { connected: m.connected, held: m.held };
    m.connected = false;
    m.held = undefined;
    // Resume is always by explicit native id, never "the last session".
    try {
      // The prompt waits for the connected report (deliverPrompt).
      await this.startAdapter(m, rcfg, { resume: rec.native_id });
    } catch (error) {
      if (!live) {
        this.sessions.delete(m.id);
        await m.ctx.sink.close();
      } else Object.assign(m, before);
      return this.result(cmd.id, 'refused', undefined, errorMessage(error));
    }
    const connected = await this.connect(m, rec.runtime === 'claude_code' ? 'sdk' : 'app_server');
    await this.deliverPrompt(m, m.adapter!, cmd.payload?.prompt ?? undefined, connected);
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
          // The reply reaches the runtime through its hook: redacted.
          reply = { error: clean(errorMessage(error), 500, this.secrets()) };
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
      m = await this.registerLocal(runtime, native, String(input.cwd ?? ''), typeof req.invoker === 'string' && path.isAbsolute(req.invoker) ? req.invoker : undefined);
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
  private async registerLocal(runtime: Runtime, native: string, cwd: string, executable?: string): Promise<Managed | undefined> {
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
    m.nativeId = native;
    m.executable = executable;
    this.byNative.set(`${runtime}:${native}`, m);
    await this.connect(m, 'cli_hooks', {
      limitations: [
        'a session that was already open before the hooks were installed must be restarted to be connected',
        ...(executable ? [] : ['the runtime executable running this session could not be identified, so no capability is validated for it']),
      ],
      workspace: { base_revision: state.base_revision, branch: state.branch, preexisting_changes: state.preexisting_changes.length },
    });
    return m;
  }
}
