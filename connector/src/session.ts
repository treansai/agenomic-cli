import { ApiError, type RunnerApi } from './api.ts';
import type { Capture, Mode } from './config.ts';
import type { CodingEvent, EventSink } from './events.ts';
import { clean } from './redact.ts';
import { errorMessage, log, sleep } from './util.ts';

export type Runtime = 'claude_code' | 'codex';

export interface CallContext {
  cwd?: string;
  workspace_root?: string;
  base_revision?: string | null;
  sandbox?: string;
  permission_mode?: string;
  network_scope?: unknown;
  patch_digest?: string;
  paths?: string[];
  symlink_escapes?: string[];
}

export interface Verdict {
  /** What the adapter must do: run, refuse, or let the native flow decide. */
  decision: 'allow' | 'deny' | 'defer';
  reason: string;
  actionId?: string;
  effectiveMode?: string;
  /** The native request id and attempt the decision was asked for (the action's correlation key). */
  nativeId: string;
  attempt: number;
}

export interface AuthorizeArgs {
  nativeId: string;
  tool: string;
  input: unknown;
  context: CallContext;
  phase: 'pre_tool' | 'native_approval';
  turnId?: string;
  attempt?: number;
  signal?: AbortSignal;
  /** Wait for a pending approval (SDK callbacks, App Server requests) or not (CLI hooks with a short timeout). */
  waitForApproval: boolean;
  /** Budget for the call itself, below the native hook timeout. */
  timeoutMs?: number;
}

/**
 * State and Agenomic calls shared by the Claude Code and Codex adapters for
 * one coding session.
 *
 * @example
 * const ctx = new SessionContext(api, sessionId, 'codex', 'enforce', sink, DEFAULT_CAPTURE, worktree, baseRevision);
 * const v = await ctx.authorize({ nativeId: 'call_1', tool: 'exec_command', input: { cmd: 'git push' }, context: { cwd: worktree }, phase: 'pre_tool', waitForApproval: false });
 */
export class SessionContext {
  private readonly verdicts = new Map<string, Verdict>();
  /** A call decided under another native request id (a Codex approval id). */
  private readonly aliases = new Map<string, string>();
  /**
   * Admitted actions whose outcome the gateway has not acknowledged yet,
   * with the outcome observed for them when its report failed, so that
   * settling them later delivers that outcome instead of a generic one.
   */
  private readonly open = new Map<string, Outcome | undefined>();
  /** The settlement at the end of the session, once started. */
  private final: Promise<void> | undefined;

  readonly api: RunnerApi;
  readonly id: string;
  readonly runtime: Runtime;
  readonly mode: Mode;
  readonly sink: EventSink;
  readonly capture: Capture;
  readonly workspaceRoot: string;
  baseRevision: string | null;
  readonly traceId?: string;
  /** Values redacted from content before it is shipped (runner and runtime credentials). */
  readonly secrets: () => string[];
  /** Reports a status change of the session; the daemon orders it with its other reports. */
  reportStatus: (status: string) => void = (status) => void this.state({ status }).catch(() => undefined);

  constructor(api: RunnerApi, id: string, runtime: Runtime, mode: Mode, sink: EventSink, capture: Capture, workspaceRoot: string, baseRevision: string | null, traceId?: string, secrets: () => string[] = () => []) {
    this.api = api;
    this.id = id;
    this.runtime = runtime;
    this.mode = mode;
    this.sink = sink;
    this.capture = capture;
    this.workspaceRoot = workspaceRoot;
    this.baseRevision = baseRevision;
    this.traceId = traceId;
    this.secrets = secrets;
  }

  /**
   * Captured content made safe to ship: the session's credential values
   * are redacted before the text is bounded, so that a cut never leaves
   * a partial secret the event-level redaction cannot recognise.
   *
   * @example
   * ctx.cleanText(toolOutput, 4000);
   */
  cleanText(text: string, max: number): string {
    return clean(text, max, this.secrets());
  }

  /**
   * The decision already obtained for a native request id, if any.
   *
   * @example
   * const prior = ctx.known(toolUseId); // the PreToolUse verdict, reused by canUseTool
   */
  known(nativeId: string): Verdict | undefined {
    return this.verdicts.get(nativeId);
  }

  /**
   * Record that the call `callId` was decided under the native request id `nativeId`.
   *
   * @example
   * ctx.alias(itemId, `${itemId}:${approvalId}`);
   */
  alias(callId: string, nativeId: string): void {
    if (callId !== nativeId) this.aliases.set(callId, nativeId);
  }

  /**
   * The decision that governs the call `callId`: its own, or the one it was decided under.
   *
   * @example
   * const verdict = ctx.lookup(itemId);
   * await ctx.report(verdict?.actionId, 'completed');
   */
  lookup(callId: string): Verdict | undefined {
    const alias = this.aliases.get(callId);
    return this.verdicts.get(callId) ?? (alias !== undefined ? this.verdicts.get(alias) : undefined);
  }

  /**
   * An observed tool.started / tool.completed / tool.failed, correlated
   * with the coding action of the call: payload.native_request_id and
   * attempt_id are the action's native request id and attempt, and
   * action_id is set whenever a decision exists for the call. Without
   * one (no decision was asked), the event is an observation only.
   *
   * @example
   * const v = ctx.toolEvent('tool.completed', toolUseId, { native_tool: 'Bash', duration_ms: 120 });
   */
  toolEvent(type: 'tool.started' | 'tool.completed' | 'tool.failed', callId: string, payload: Record<string, unknown>, extra: Partial<CodingEvent> = {}): Verdict | undefined {
    const v = this.lookup(callId);
    this.sink.emit(type, 'runtime', 'native', { ...payload, native_request_id: v?.nativeId ?? callId }, {
      ...extra,
      action_id: v?.actionId,
      attempt_id: String(v?.attempt ?? 1),
    });
    return v;
  }

  /**
   * Asks the gateway to decide a tool call and records it
   * (tool.requested). When the gateway cannot answer, enforce fails
   * closed and the other modes defer to the runtime; a pending approval
   * is waited for when `waitForApproval` is set.
   *
   * @example
   * const v = await ctx.authorize({ nativeId: toolUseId, tool: 'Bash', input: { command: 'rm -rf build' }, context: { cwd }, phase: 'pre_tool', waitForApproval: true });
   * if (v.decision === 'deny') console.log(v.reason);
   */
  async authorize(a: AuthorizeArgs): Promise<Verdict> {
    const attempt = a.attempt ?? 1;
    const body = {
      native_request_id: a.nativeId,
      runtime_turn_id: a.turnId,
      attempt,
      phase: a.phase,
      tool: a.tool,
      input: a.input,
      context: a.context,
    };
    const key = { nativeId: a.nativeId, attempt };
    const failClosed = (why: string): Verdict =>
      this.mode === 'enforce'
        ? { decision: 'deny', reason: `Agenomic could not authorize this action (${why}); refused in enforce mode`, ...key }
        : { decision: 'defer', reason: `Agenomic unavailable (${why}); ${this.mode} mode leaves the decision to the runtime`, ...key };
    let res: any;
    try {
      res = await this.api.request('POST', `/v1/coding/runner/sessions/${this.id}/authorize`, {
        body,
        timeoutMs: a.timeoutMs ?? 20000,
        retry: true,
        signal: a.signal,
      });
    } catch (error) {
      log('warn', 'authorize failed', { session: this.id, error: this.cleanText(errorMessage(error), 500) });
      const v = failClosed(errorMessage(error));
      this.sink.emit('error', 'adapter', 'native', { code: 'authorize_failed', native_request_id: a.nativeId, decision: v.decision });
      return v;
    }
    this.sink.emit('tool.requested', 'gateway', 'native', {
      native_request_id: a.nativeId,
      native_tool: a.tool,
      tool_id: res.classification?.tool_id,
      risk: res.classification?.risk,
      decision: res.decision,
      effective_mode: res.effective_mode,
      would_have_been: res.would_have_been ?? null,
      ...(this.capture.commands ? { command: commandText(a.tool, a.input, this.secrets()) } : {}),
    }, { action_id: res.action_id, attempt_id: String(attempt), runtime_turn_id: a.turnId, trace_id: this.traceId });

    if (res.decision === 'pending') {
      this.sink.emit('approval.requested', 'gateway', 'native', { approval_id: res.approval_id, expires_at: res.approval_expires_at }, { action_id: res.action_id });
      if (!a.waitForApproval) {
        const v: Verdict = { decision: 'deny', reason: `Waiting for approval ${res.approval_id} in Agenomic; retry after it is approved`, actionId: res.action_id, ...key };
        return v;
      }
      this.reportStatus('waiting_approval');
      const resolved = await this.waitForApproval(res.action_id, res.approval_expires_at, a.signal);
      this.reportStatus('running');
      this.sink.emit('approval.resolved', 'gateway', 'native', { approval_id: res.approval_id, status: resolved }, { action_id: res.action_id });
      if (resolved !== 'approved') {
        // Let the gateway record the final refusal (rejected or expired)
        // on the action instead of leaving it pending.
        const final = await this.authorize({ ...a, waitForApproval: false }).catch(() => undefined);
        const v: Verdict = { decision: 'deny', reason: final?.reason && !final.reason.startsWith('Waiting') ? final.reason : `Approval ${resolved}`, actionId: res.action_id, ...key };
        this.verdicts.set(a.nativeId, v);
        return v;
      }
      // Re-submit the identical call: the gateway re-checks the digest and
      // consumes the approval exactly once.
      return this.authorize({ ...a, waitForApproval: false });
    }
    const v: Verdict = {
      decision: res.decision === 'allow' ? 'allow' : res.decision === 'defer' ? 'defer' : 'deny',
      reason: res.reason ?? res.decision,
      actionId: res.action_id,
      effectiveMode: res.effective_mode,
      ...key,
    };
    this.verdicts.set(a.nativeId, v);
    if (v.decision !== 'deny' && v.actionId && !this.open.has(v.actionId)) this.open.set(v.actionId, undefined);
    return v;
  }

  private async waitForApproval(actionId: string, expiresAt: string | null, signal?: AbortSignal): Promise<string> {
    const deadline = expiresAt ? Date.parse(expiresAt) + 2000 : Date.now() + 15 * 60 * 1000;
    while (Date.now() < deadline) {
      if (signal?.aborted) return 'cancelled';
      try {
        const r = await this.api.request('GET', `/v1/coding/runner/sessions/${this.id}/actions/${actionId}`, { retry: true, timeoutMs: 15000, signal });
        const s = r.approval_status as string | null;
        if (s === 'approved' || s === 'rejected' || s === 'expired' || s === 'consumed') return s;
      } catch (error) {
        log('warn', 'approval poll failed', { session: this.id, error: this.cleanText(errorMessage(error), 500) });
      }
      await sleep(1000, signal);
    }
    return 'expired';
  }

  /**
   * Reports the observed outcome of an admitted action, retained until the gateway acknowledges it.
   *
   * @example
   * await ctx.report(verdict?.actionId, 'failed', { exit_code: 1, duration_ms: 950 });
   */
  async report(actionId: string | undefined, outcome: OutcomeKind, detail: OutcomeDetail = {}): Promise<void> {
    if (!actionId) return;
    if (outcome === 'started') {
      await this.send(actionId, outcome, detail);
      return;
    }
    // An outcome is retained until the gateway acknowledges it: a report
    // that fails (the gateway unavailable beyond the retry window) is
    // delivered again when the turn or the session settles its actions.
    const entry: Outcome = { outcome, detail };
    this.open.set(actionId, entry);
    entry.sending = this.send(actionId, outcome, detail).then((ok) => {
      entry.sending = undefined;
      if (ok && this.open.get(actionId) === entry) this.open.delete(actionId);
    });
    await entry.sending;
  }

  /** Whether the outcome is settled on the gateway (acknowledged, or refused for good). */
  private async send(actionId: string, outcome: OutcomeKind, detail: OutcomeDetail): Promise<boolean> {
    try {
      await this.api.request('POST', `/v1/coding/runner/sessions/${this.id}/actions/${actionId}/report`, {
        body: { outcome, exit_code: detail.exit_code ?? undefined, duration_ms: detail.duration_ms, summary: detail.summary ? clean(detail.summary, 400) : undefined },
        retry: true,
        timeoutMs: 15000,
      });
      return true;
    } catch (error) {
      log('warn', 'action report failed', { session: this.id, action: actionId, error: this.cleanText(errorMessage(error), 500) });
      // A refusal of the report itself will not change on a retry.
      return refused(error);
    }
  }

  /**
   * Report every admitted action still without an acknowledged outcome:
   * the outcome observed for it when its report failed, otherwise
   * `unknown` (an interrupted turn, a stopped process), so that the
   * gateway settles them instead of leaving them pending. A report in
   * flight is awaited rather than duplicated; an action whose report
   * fails again stays open for the next settlement.
   *
   * @example
   * await ctx.settleOpen('turn ended before the tool reported');
   */
  async settleOpen(summary: string, only?: ReadonlySet<string>): Promise<void> {
    await Promise.all([...this.open].filter(([id]) => !only || only.has(id)).map(async ([id, retained]) => {
      if (retained?.sending) await retained.sending;
      if (!this.open.has(id) || this.open.get(id) !== retained) return;
      await (retained ? this.report(id, retained.outcome, retained.detail) : this.report(id, 'unknown', { summary }));
    }));
  }

  /**
   * The settlement at the end of the session. Nothing settles its actions
   * after it, so the outcomes the gateway did not acknowledge (it is still
   * unavailable) are delivered again, with a growing delay, until they are
   * or `budgetMs` has passed. It runs in the background of the daemon,
   * whose process its waits do not keep alive. Only the actions open when
   * it starts are retried: a resumed session's new actions are its own.
   * Settling twice (a stop, then the session's end) shares one settlement.
   *
   * @example
   * void ctx.settleFinal('session stopped before the tool reported');
   */
  settleFinal(summary: string, budgetMs = 10 * 60 * 1000, firstDelayMs = 2000): Promise<void> {
    this.final ??= (async () => {
      const ids = new Set(this.open.keys());
      const deadline = Date.now() + budgetMs;
      for (let delay = firstDelayMs; ; delay = Math.min(delay * 2, 60000)) {
        await this.settleOpen(summary, ids);
        const left = [...ids].filter((id) => this.open.has(id));
        if (left.length === 0) return;
        if (Date.now() + delay >= deadline) {
          log('warn', 'action outcomes left unreported', { session: this.id, actions: left });
          return;
        }
        await new Promise<void>((resolve) => setTimeout(resolve, delay).unref());
      }
    })().finally(() => {
      this.final = undefined;
    });
    return this.final;
  }

  /**
   * Reports a state change of the session to the gateway.
   *
   * @example
   * await ctx.state({ status: 'idle' });
   */
  async state(update: Record<string, unknown>): Promise<any> {
    return this.api.request('POST', `/v1/coding/runner/sessions/${this.id}/state`, { body: update, retry: true, timeoutMs: 15000 });
  }
}

type OutcomeKind = 'started' | 'completed' | 'failed' | 'unknown';
type OutcomeDetail = { exit_code?: number | null; duration_ms?: number; summary?: string };
type Outcome = { outcome: OutcomeKind; detail: OutcomeDetail; sending?: Promise<void> };

/** A report the gateway answered with a client error: retrying it cannot succeed. */
function refused(error: unknown): boolean {
  return error instanceof ApiError && error.status >= 400 && error.status < 500 && error.status !== 408 && error.status !== 429;
}

/**
 * The command a tool call runs (redacted, bounded), or the file it touches.
 *
 * @example
 * commandText('Bash', { command: 'npm test' }); // 'npm test'
 */
export function commandText(tool: string, input: unknown, secrets: string[] = []): string | undefined {
  const i = (input ?? {}) as Record<string, unknown>;
  const c = i.command ?? i.cmd;
  if (typeof c === 'string') return clean(c, 2000, secrets);
  if (Array.isArray(c)) return clean(c.join(' '), 2000, secrets);
  if (typeof i.file_path === 'string') return `${tool} ${i.file_path}`;
  return undefined;
}

const TEST_RUNNERS = /(^|\s|\/|['"])(cargo test|npm test|npm run test|pnpm test|pnpm run test|yarn test|pytest|go test|vitest|jest|mvn test|gradle test|make test|ctest|tox|node --test)(\s|$|['"])/;

/**
 * A command that looks like a test run. Its exit code is a derived signal, not a proof.
 *
 * @example
 * isTestCommand('npx vitest run'); // true
 */
export function isTestCommand(command: string | undefined): boolean {
  return !!command && TEST_RUNNERS.test(command);
}
