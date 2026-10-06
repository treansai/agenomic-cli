import type { RunnerApi } from './api.ts';
import type { Capture, Mode } from './config.ts';
import type { EventSink } from './events.ts';
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
 */
export class SessionContext {
  private readonly verdicts = new Map<string, Verdict>();
  /** Admitted actions whose outcome was not reported yet. */
  private readonly open = new Set<string>();

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
   */
  cleanText(text: string, max: number): string {
    return clean(text, max, this.secrets());
  }

  /** The decision already obtained for a native request id, if any. */
  known(nativeId: string): Verdict | undefined {
    return this.verdicts.get(nativeId);
  }

  async authorize(a: AuthorizeArgs): Promise<Verdict> {
    const body = {
      native_request_id: a.nativeId,
      runtime_turn_id: a.turnId,
      attempt: a.attempt ?? 1,
      phase: a.phase,
      tool: a.tool,
      input: a.input,
      context: a.context,
    };
    const failClosed = (why: string): Verdict =>
      this.mode === 'enforce'
        ? { decision: 'deny', reason: `Agenomic could not authorize this action (${why}); refused in enforce mode` }
        : { decision: 'defer', reason: `Agenomic unavailable (${why}); ${this.mode} mode leaves the decision to the runtime` };
    let res: any;
    try {
      res = await this.api.request('POST', `/v1/coding/runner/sessions/${this.id}/authorize`, {
        body,
        timeoutMs: a.timeoutMs ?? 20000,
        retry: true,
        signal: a.signal,
      });
    } catch (error) {
      log('warn', 'authorize failed', { session: this.id, error: errorMessage(error) });
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
    }, { action_id: res.action_id, runtime_turn_id: a.turnId, trace_id: this.traceId });

    if (res.decision === 'pending') {
      this.sink.emit('approval.requested', 'gateway', 'native', { approval_id: res.approval_id, expires_at: res.approval_expires_at }, { action_id: res.action_id });
      if (!a.waitForApproval) {
        const v: Verdict = { decision: 'deny', reason: `Waiting for approval ${res.approval_id} in Agenomic; retry after it is approved`, actionId: res.action_id };
        return v;
      }
      void this.state({ status: 'waiting_approval' }).catch(() => undefined);
      const resolved = await this.waitForApproval(res.action_id, res.approval_expires_at, a.signal);
      void this.state({ status: 'running' }).catch(() => undefined);
      this.sink.emit('approval.resolved', 'gateway', 'native', { approval_id: res.approval_id, status: resolved }, { action_id: res.action_id });
      if (resolved !== 'approved') {
        // Let the gateway record the final refusal (rejected or expired)
        // on the action instead of leaving it pending.
        const final = await this.authorize({ ...a, waitForApproval: false }).catch(() => undefined);
        const v: Verdict = { decision: 'deny', reason: final?.reason && !final.reason.startsWith('Waiting') ? final.reason : `Approval ${resolved}`, actionId: res.action_id };
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
    };
    this.verdicts.set(a.nativeId, v);
    if (v.decision !== 'deny' && v.actionId) this.open.add(v.actionId);
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
        log('warn', 'approval poll failed', { session: this.id, error: errorMessage(error) });
      }
      await sleep(1000, signal);
    }
    return 'expired';
  }

  async report(actionId: string | undefined, outcome: 'started' | 'completed' | 'failed' | 'unknown', detail: { exit_code?: number | null; duration_ms?: number; summary?: string } = {}): Promise<void> {
    if (!actionId) return;
    if (outcome !== 'started') this.open.delete(actionId);
    try {
      await this.api.request('POST', `/v1/coding/runner/sessions/${this.id}/actions/${actionId}/report`, {
        body: { outcome, exit_code: detail.exit_code ?? undefined, duration_ms: detail.duration_ms, summary: detail.summary ? clean(detail.summary, 400) : undefined },
        retry: true,
        timeoutMs: 15000,
      });
    } catch (error) {
      log('warn', 'action report failed', { session: this.id, action: actionId, error: errorMessage(error) });
    }
  }

  /**
   * Report every admitted action still without an outcome as `unknown`
   * (an interrupted turn, a stopped process), so that the gateway settles
   * them instead of leaving them pending.
   */
  async settleOpen(summary: string): Promise<void> {
    const ids = [...this.open];
    this.open.clear();
    await Promise.all(ids.map((id) => this.report(id, 'unknown', { summary })));
  }

  async state(update: Record<string, unknown>): Promise<any> {
    return this.api.request('POST', `/v1/coding/runner/sessions/${this.id}/state`, { body: update, retry: true, timeoutMs: 15000 });
  }
}

export function commandText(tool: string, input: unknown, secrets: string[] = []): string | undefined {
  const i = (input ?? {}) as Record<string, unknown>;
  const c = i.command ?? i.cmd;
  if (typeof c === 'string') return clean(c, 2000, secrets);
  if (Array.isArray(c)) return clean(c.join(' '), 2000, secrets);
  if (typeof i.file_path === 'string') return `${tool} ${i.file_path}`;
  return undefined;
}

const TEST_RUNNERS = /(^|\s|\/|['"])(cargo test|npm test|npm run test|pnpm test|pnpm run test|yarn test|pytest|go test|vitest|jest|mvn test|gradle test|make test|ctest|tox|node --test)(\s|$|['"])/;

/** A command that looks like a test run. Its exit code is a derived signal, not a proof. */
export function isTestCommand(command: string | undefined): boolean {
  return !!command && TEST_RUNNERS.test(command);
}
