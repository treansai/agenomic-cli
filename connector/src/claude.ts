import { spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { paths, type RuntimeConfig } from './config.ts';
import { commandText, isTestCommand, type SessionContext, type Verdict } from './session.ts';
import { errorMessage, executableVersion, log, readExecutableVersion, realPathEscapes } from './util.ts';
import * as ws from './workspace.ts';

// Pinned in package.json; imported lazily so `hooks install` and `enroll`
// work on a machine without the SDK.
type Sdk = typeof import('@anthropic-ai/claude-agent-sdk');
let sdk: Sdk | undefined;
async function loadSdk(): Promise<Sdk> {
  sdk ??= await import('@anthropic-ai/claude-agent-sdk');
  return sdk;
}

/**
 * The SDK's package.json (its `exports` hide the file from require).
 *
 * @example
 * const pkg = sdkPackage(); // null when the SDK is not installed
 * console.log(pkg?.version, pkg?.claudeCodeVersion);
 */
export function sdkPackage(): { version: string; claudeCodeVersion?: string } | null {
  try {
    const req = createRequire(import.meta.url);
    let dir = path.dirname(req.resolve('@anthropic-ai/claude-agent-sdk'));
    for (let i = 0; i < 4; i++) {
      const file = path.join(dir, 'package.json');
      if (fs.existsSync(file)) {
        const pkg = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (pkg.name === '@anthropic-ai/claude-agent-sdk') return pkg;
      }
      dir = path.dirname(dir);
    }
  } catch {
    /* not installed */
  }
  return null;
}

/**
 * Version of the installed Claude Agent SDK, or null.
 *
 * @example
 * if (!sdkVersion()) console.log('claude_code is not offered: the Agent SDK is not installed');
 */
export function sdkVersion(): string | null {
  return sdkPackage()?.version ?? null;
}

/**
 * Version of the Claude Code binary a session runs: what a configured
 * executable reports itself (`undefined` until it has answered, see
 * executableVersion), otherwise the version the pinned SDK bundles.
 * Never the bundled version for a custom executable.
 *
 * @example
 * const version = claudeCodeVersion(cfg.runtimes.claude_code); // undefined while a custom executable has not answered
 */
export function claudeCodeVersion(runtime: RuntimeConfig): string | null | undefined {
  if (runtime.executable) return executableVersion(runtime.executable);
  return sdkPackage()?.claudeCodeVersion ?? null;
}

/**
 * claudeCodeVersion(), waiting for a configured executable's answer.
 *
 * @example
 * const version = await readClaudeCodeVersion(cfg.runtimes.claude_code);
 */
export async function readClaudeCodeVersion(runtime: RuntimeConfig): Promise<string | null> {
  if (runtime.executable) return readExecutableVersion(runtime.executable);
  return sdkPackage()?.claudeCodeVersion ?? null;
}

class Inbox<T> implements AsyncIterable<T> {
  private items: T[] = [];
  private waiters: ((r: IteratorResult<T>) => void)[] = [];
  private closed = false;
  push(item: T): void {
    const w = this.waiters.shift();
    if (w) w({ value: item, done: false });
    else this.items.push(item);
  }
  close(): void {
    this.closed = true;
    for (const w of this.waiters.splice(0)) w({ value: undefined as never, done: true });
  }
  [Symbol.asyncIterator](): AsyncIterator<T> {
    return {
      next: () => {
        const item = this.items.shift();
        if (item !== undefined) return Promise.resolve({ value: item, done: false });
        if (this.closed) return Promise.resolve({ value: undefined as never, done: true });
        return new Promise((resolve) => this.waiters.push(resolve));
      },
    };
  }
}

export interface LaunchOptions {
  ctx: SessionContext;
  cwd: string;
  model?: string | null;
  prompt?: string | null;
  resume?: string | null;
  runtime: RuntimeConfig;
  onNativeSession: (nativeId: string) => Promise<void>;
  onStatus: (status: string) => void;
  /** How long start() waits for Claude Code to initialize. */
  initTimeoutMs?: number;
}

/**
 * A Claude Code session driven through the Claude Agent SDK.
 *
 * @example
 * const session = new ClaudeSession({ ctx, cwd: worktree, prompt: 'fix the tests', runtime: cfg.runtimes.claude_code, onNativeSession: register, onStatus: report });
 * await session.start();
 * await session.done;
 */
export class ClaudeSession {
  private readonly inbox = new Inbox<any>();
  private query: any;
  private child: ChildProcess | undefined;
  private nativeId: string | null = null;
  private turnId = 0;
  private readonly questions = new Map<string, (answer: string) => void>();
  private readonly toolStart = new Map<string, number>();
  private ended = false;
  private started = false;
  /** Why the SDK stream ended with an error, if it did. */
  private failure: string | undefined;
  readonly done: Promise<void>;
  private resolveDone!: () => void;

  private readonly o: LaunchOptions;

  constructor(o: LaunchOptions) {
    this.o = o;
    this.done = new Promise((r) => (this.resolveDone = r));
  }

  private env(): Record<string, string> {
    const home = paths.runtimeHome('claude_code');
    fs.mkdirSync(path.join(home, 'config'), { recursive: true, mode: 0o700 });
    const env: Record<string, string> = {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      HOME: home,
      CLAUDE_CONFIG_DIR: path.join(home, 'config'),
      DISABLE_AUTOUPDATER: '1',
      // Telemetry stays opt-in: no prompt or tool detail export by default.
      CLAUDE_CODE_ENABLE_TELEMETRY: '0',
    };
    for (const k of this.o.runtime.env_passthrough) if (process.env[k]) env[k] = process.env[k]!;
    Object.assign(env, this.o.runtime.extra_env);
    return env;
  }

  private context(input: Record<string, unknown>, tool: string): Record<string, unknown> {
    const cwd = this.o.cwd;
    const candidates = [input.file_path, input.notebook_path, input.path].filter((p): p is string => typeof p === 'string');
    const escapes = candidates.filter((p) => realPathEscapes(p, cwd, cwd)).map((p) => `${p} (symlink leaves the workspace)`);
    return {
      cwd,
      workspace_root: cwd,
      base_revision: this.o.ctx.baseRevision,
      sandbox: 'claude-sandbox',
      permission_mode: this.o.ctx.mode === 'enforce' ? 'default' : 'acceptEdits',
      symlink_escapes: escapes,
      paths: candidates,
      ...(tool === 'Bash' ? {} : {}),
    };
  }

  /**
   * Starts Claude Code and resolves once it has initialized and its native
   * session is registered (onNativeSession). The session id is chosen
   * here (or is the resumed one), so it is known before the first turn,
   * which a launch without a prompt does not start. A runtime that fails
   * or exits before it initialized, or does not within initTimeoutMs,
   * rejects the start instead of being reported running.
   *
   * @example
   * await session.start(); // throws when Claude Code could not start
   * session.native(); // the registered native session id
   */
  async start(): Promise<void> {
    const { query } = await loadSdk();
    const ctx = this.o.ctx;
    const enforce = ctx.mode === 'enforce';
    const self = this;
    const preToolUse = async (input: any) => {
      if (input.tool_name === 'AskUserQuestion') return {};
      const v = await ctx.authorize({
        nativeId: input.tool_use_id,
        tool: input.tool_name,
        input: input.tool_input,
        context: self.context(input.tool_input ?? {}, input.tool_name),
        phase: 'pre_tool',
        turnId: String(self.turnId),
        waitForApproval: false,
        timeoutMs: 20000,
      });
      self.toolStart.set(input.tool_use_id, Date.now());
      if (v.decision === 'deny' && v.reason.startsWith('Waiting for approval')) {
        // Hand the wait to canUseTool, which may block until the decision.
        return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: v.reason } };
      }
      if (v.decision === 'deny') {
        return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `Agenomic: ${v.reason}` } };
      }
      // allow and defer: never force an allow; native rules still apply.
      return {};
    };
    const canUseTool = async (toolName: string, input: Record<string, unknown>, opts: { signal: AbortSignal; toolUseID?: string }) => {
      const id = opts.toolUseID ?? `nohook-${Date.now()}`;
      if (toolName === 'AskUserQuestion') return self.ask(id, input, opts.signal);
      let v: Verdict | undefined = ctx.known(id);
      if (!v || v.reason.startsWith('Waiting for approval')) {
        v = await ctx.authorize({
          nativeId: id,
          tool: toolName,
          input,
          context: self.context(input, toolName),
          phase: 'native_approval',
          turnId: String(self.turnId),
          waitForApproval: true,
          signal: opts.signal,
        });
      }
      if (v.decision === 'allow') return { behavior: 'allow', updatedInput: input };
      if (v.decision === 'defer' && !enforce) {
        // Observe and shadow sessions have no Agenomic approver: a native
        // prompt that reaches here is declined, the native safe default.
        return { behavior: 'deny', message: 'No interactive approver for this native permission prompt (observe/shadow session).' };
      }
      return { behavior: 'deny', message: `Agenomic: ${v.reason}` };
    };
    const post = (failed: boolean) => (input: any) => self.postToolUse(input, failed);
    const lifecycle = (type: 'subagent.started' | 'subagent.stopped') => async (input: any) => {
      ctx.sink.emit(type, 'runtime', 'native', { agent_id: input.agent_id, agent_type: input.agent_type });
      return {};
    };
    const nativeId = this.o.resume ?? randomUUID();
    this.nativeId = nativeId;
    if (this.o.prompt) this.pushUser(this.o.prompt);
    this.query = query({
      prompt: this.inbox,
      options: {
        cwd: this.o.cwd,
        env: this.env(),
        model: this.o.model ?? undefined,
        resume: this.o.resume ?? undefined,
        // Repository settings (hooks, permissions, MCP) are not loaded: a
        // repository cannot change the session's governance.
        settingSources: [],
        permissionMode: enforce ? 'default' : 'acceptEdits',
        sandbox: {
          enabled: true,
          failIfUnavailable: true,
          autoAllowBashIfSandboxed: !enforce,
          allowUnsandboxedCommands: false,
          filesystem: { denyRead: [paths.state(), path.dirname(paths.credentials())] },
          network: { allowedDomains: this.o.runtime.allowed_domains },
        },
        canUseTool,
        hooks: {
          PreToolUse: [{ hooks: [preToolUse], timeout: 900 }],
          PostToolUse: [{ hooks: [post(false)] }],
          PostToolUseFailure: [{ hooks: [post(true)] }],
          SubagentStart: [{ hooks: [lifecycle('subagent.started')] }],
          SubagentStop: [{ hooks: [lifecycle('subagent.stopped')] }],
        },
        // A new session's id is fixed by the connector; a resumed one keeps its own.
        sessionId: this.o.resume ? undefined : nativeId,
        pathToClaudeCodeExecutable: this.o.runtime.executable,
        spawnClaudeCodeProcess: (opts: any) => {
          const child = spawn(opts.command, opts.args, { cwd: opts.cwd, env: opts.env, signal: opts.signal, stdio: ['pipe', 'pipe', 'pipe'] });
          child.stderr?.on('data', (d) => log('debug', 'claude stderr', { line: this.o.ctx.cleanText(String(d), 500) }));
          this.child = child;
          return child as any;
        },
      } as any,
    });
    void this.pump();
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        this.query.initializationResult(),
        this.done.then(() => {
          throw new Error(`claude code ended before it initialized${this.failure ? `: ${this.failure}` : ''}`);
        }),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('claude code did not initialize in time')), this.o.initTimeoutMs ?? 60000);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
    await this.o.onNativeSession(nativeId);
  }

  /** PostToolUse / PostToolUseFailure: the observed outcome of a call, correlated with its action. */
  private async postToolUse(input: any, failed: boolean): Promise<Record<string, never>> {
    const ctx = this.o.ctx;
    const started = this.toolStart.get(input.tool_use_id);
    const duration = started ? Date.now() - started : undefined;
    const cmd = commandText(input.tool_name, input.tool_input, ctx.secrets());
    const verdict = ctx.toolEvent(failed ? 'tool.failed' : 'tool.completed', String(input.tool_use_id), {
      native_tool: input.tool_name,
      duration_ms: duration,
      ...(ctx.capture.commands && cmd ? { command: cmd } : {}),
      ...(ctx.capture.outputs ? { output: ctx.cleanText(JSON.stringify(input.tool_response ?? input.error ?? ''), 4000) } : {}),
    }, { runtime_turn_id: String(this.turnId) });
    if (input.tool_name === 'Bash' && isTestCommand(cmd)) {
      ctx.sink.emit('test.result', 'adapter', 'derived', { command: ctx.capture.commands ? cmd : undefined, passed: !failed, basis: 'tool_outcome' });
    }
    if (['Write', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(input.tool_name) && !failed) {
      ctx.sink.emit('file.changed', 'runtime', 'native', { path: input.tool_input?.file_path ?? input.tool_input?.notebook_path, tool: input.tool_name });
    }
    await ctx.report(verdict?.actionId, failed ? 'failed' : 'completed', { duration_ms: duration });
    return {};
  }

  private pushUser(text: string): void {
    this.turnId++;
    this.o.ctx.sink.emit('message.user', 'adapter', 'native', this.o.ctx.capture.conversation ? { text: this.o.ctx.cleanText(text, 16000) } : { length: text.length }, { runtime_turn_id: String(this.turnId) });
    this.o.ctx.sink.emit('turn.started', 'adapter', 'native', {}, { runtime_turn_id: String(this.turnId) });
    this.inbox.push({ type: 'user', message: { role: 'user', content: text }, parent_tool_use_id: null });
  }

  private async pump(): Promise<void> {
    const ctx = this.o.ctx;
    try {
      for await (const m of this.query) {
        if (m.type === 'system' && m.subtype === 'init') {
          // The id start() registered, unless the runtime chose another one.
          if (m.session_id && m.session_id !== this.nativeId) {
            this.nativeId = m.session_id;
            await this.o.onNativeSession(m.session_id);
          }
          if (!this.started) {
            this.started = true;
            ctx.sink.emit('session.started', 'runtime', 'native', { model: m.model, permission_mode: m.permissionMode, tools: (m.tools ?? []).length });
          }
          this.o.onStatus('running');
        } else if (m.type === 'assistant') {
          const text = (m.message?.content ?? []).filter((c: any) => c.type === 'text').map((c: any) => c.text).join('\n');
          if (text) ctx.sink.emit('message.assistant', 'runtime', 'native', ctx.capture.conversation ? { text: ctx.cleanText(text, 16000) } : { length: text.length }, { runtime_turn_id: String(this.turnId) });
        } else if (m.type === 'result') {
          ctx.sink.emit(m.subtype === 'error_during_execution' ? 'turn.interrupted' : 'turn.completed', 'runtime', 'native', {
            subtype: m.subtype, is_error: m.is_error, num_turns: m.num_turns, duration_ms: m.duration_ms,
          }, { runtime_turn_id: String(this.turnId) });
          void ctx.settleOpen(`turn ended (${m.subtype}) before the tool reported`);
          ctx.sink.emit('usage', 'runtime', 'native', {
            input_tokens: m.usage?.input_tokens ?? null,
            output_tokens: m.usage?.output_tokens ?? null,
            basis: m.usage ? 'measured' : 'unavailable',
            // The SDK's cost is computed client side from its price table.
            cost_usd: typeof m.total_cost_usd === 'number' ? m.total_cost_usd : null,
            cost_basis: 'estimated',
          });
          this.snapshotDiff();
          this.o.onStatus('idle');
        }
      }
    } catch (error) {
      this.failure = ctx.cleanText(errorMessage(error), 500);
      ctx.sink.emit('error', 'adapter', 'native', { code: 'runtime_error', message: this.failure });
      log('warn', 'claude session ended with an error', { session: ctx.id, error: errorMessage(error) });
    } finally {
      this.ended = true;
      ctx.sink.emit('session.ended', 'supervisor', 'native', { exit_code: this.child?.exitCode ?? null });
      this.resolveDone();
    }
  }

  private snapshotDiff(): void {
    const ctx = this.o.ctx;
    if (!ctx.baseRevision) return;
    try {
      const payload = ws.snapshot(this.o.cwd, ctx.baseRevision, ctx.capture.diffs, ctx.secrets());
      ctx.sink.emit('diff.snapshot', 'filesystem', 'observed', payload, { runtime_turn_id: String(this.turnId) });
    } catch (error) {
      log('warn', 'diff snapshot failed', { error: errorMessage(error) });
    }
  }

  private async ask(id: string, input: Record<string, unknown>, signal: AbortSignal) {
    const ctx = this.o.ctx;
    const questions = (input.questions ?? []) as { question: string; options?: { label: string }[] }[];
    ctx.sink.emit('question.asked', 'runtime', 'native', {
      question_id: id,
      ...(ctx.capture.conversation ? { questions: questions.map((q) => ({ question: ctx.cleanText(q.question, 1000), options: (q.options ?? []).map((o) => ctx.cleanText(o.label, 200)) })) } : { count: questions.length }),
    });
    this.o.onStatus('waiting_input');
    const answer = await new Promise<string | null>((resolve) => {
      this.questions.set(id, resolve);
      signal.addEventListener('abort', () => resolve(null), { once: true });
    });
    this.questions.delete(id);
    this.o.onStatus('running');
    if (answer === null) return { behavior: 'deny', message: 'The question was cancelled.' };
    let answers: Record<string, string> = {};
    try {
      const parsed = JSON.parse(answer);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) answers = parsed;
    } catch {
      for (const q of questions) answers[q.question] = answer;
    }
    ctx.sink.emit('question.answered', 'adapter', 'native', { question_id: id, ...(ctx.capture.conversation ? { text: ctx.cleanText(answer, 4000) } : {}) });
    return { behavior: 'allow', updatedInput: { ...input, answers } };
  }

  // ── Commands ──────────────────────────────────────────────────────────

  /**
   * Sends a user message as a new turn; refused once the session ended.
   *
   * @example
   * session.send('now run the linter'); // 'applied' or 'refused'
   */
  send(text: string): 'applied' | 'refused' {
    if (this.ended) return 'refused';
    this.pushUser(text);
    return 'applied';
  }

  /**
   * Answers a pending AskUserQuestion; refused when no such question waits.
   *
   * @example
   * session.answer(questionId, JSON.stringify({ 'Which option?': 'b' }));
   */
  answer(questionId: string, text: string): 'applied' | 'refused' {
    const resolve = this.questions.get(questionId);
    if (!resolve) return 'refused';
    resolve(text);
    return 'applied';
  }

  /**
   * Interrupts the current turn; the process and session stay alive.
   *
   * @example
   * if ((await session.interrupt()) === 'applied') console.log('turn interrupted, session alive');
   */
  async interrupt(): Promise<'applied' | 'unknown'> {
    try {
      await this.query.interrupt();
      this.o.ctx.sink.emit('turn.interrupted', 'adapter', 'native', { requested_by: 'agenomic' }, { runtime_turn_id: String(this.turnId) });
      return 'applied';
    } catch (error) {
      log('warn', 'interrupt failed', { error: errorMessage(error) });
      return 'unknown';
    }
  }

  /**
   * Stops the runtime process and reports `applied` only once it exited.
   *
   * @example
   * const r = await session.stop(); // 'unknown' when the process could not be confirmed gone
   */
  async stop(): Promise<'applied' | 'unknown'> {
    void this.o.ctx.settleFinal('session stopped before the tool reported');
    this.inbox.close();
    try {
      this.query.close?.();
    } catch {
      /* already closed */
    }
    const child = this.child;
    if (!child || child.exitCode !== null || child.signalCode !== null) return 'applied';
    const exited = await new Promise<boolean>((resolve) => {
      const t = setTimeout(() => {
        child.kill('SIGKILL');
        setTimeout(() => resolve(child.exitCode !== null || child.signalCode !== null), 2000);
      }, 5000);
      child.once('exit', () => {
        clearTimeout(t);
        resolve(true);
      });
    });
    return exited ? 'applied' : 'unknown';
  }

  /**
   * Whether the Claude Code process still runs this session.
   *
   * @example
   * if (!session.alive()) console.log('ended');
   */
  alive(): boolean {
    return !this.ended && !!this.child && this.child.exitCode === null && this.child.signalCode === null;
  }

  /**
   * The native Claude Code session id, known once start() resolved.
   *
   * @example
   * const nativeId = session.native(); // resume with { resume: nativeId }
   */
  native(): string | null {
    return this.nativeId;
  }
}
