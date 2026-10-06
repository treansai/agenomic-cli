import fs from 'node:fs';
import path from 'node:path';
import type { RunnerApi } from './api.ts';
import { redactValue } from './redact.ts';
import { errorMessage, log, ulid } from './util.ts';

export type EventType =
  | 'session.started' | 'session.ended' | 'turn.started' | 'turn.completed' | 'turn.interrupted'
  | 'message.user' | 'message.assistant' | 'question.asked' | 'question.answered'
  | 'tool.requested' | 'tool.started' | 'tool.completed' | 'tool.failed'
  | 'approval.requested' | 'approval.resolved' | 'subagent.started' | 'subagent.stopped'
  | 'file.changed' | 'diff.snapshot' | 'test.result' | 'config.changed' | 'permission.changed'
  | 'protection.state' | 'usage' | 'error';

export type Source = 'runtime' | 'adapter' | 'gateway' | 'supervisor' | 'filesystem';
export type Trust = 'native' | 'derived' | 'observed';

export interface CodingEvent {
  event_id: string;
  /** The Agenomic session the event belongs to, always set by this producer. */
  coding_session_id: string;
  schema_version: 'agenomic.coding.event/v1';
  type: EventType;
  source: Source;
  trust: Trust;
  producer_epoch: string;
  producer_seq: number;
  occurred_at: string;
  runtime_turn_id?: string;
  action_id?: string;
  attempt_id?: string;
  trace_id?: string;
  parent_span_id?: string;
  payload: Record<string, unknown>;
}

/** Evidence events are never dropped: they spill to disk instead. */
const MANDATORY: ReadonlySet<EventType> = new Set([
  'tool.requested', 'tool.started', 'tool.completed', 'tool.failed', 'approval.requested', 'approval.resolved',
  'session.started', 'session.ended', 'turn.interrupted', 'config.changed', 'permission.changed', 'protection.state', 'error',
]);

export interface SinkOptions {
  maxBuffered: number;
  maxSpoolBytes: number;
  batchSize: number;
  flushIntervalMs: number;
}

/**
 * Per session event pipeline: redaction before buffering, monotonic
 * per-epoch sequence numbers, bounded memory, a bounded disk spool for
 * evidence while the cloud is unreachable, and at-least-once delivery
 * (the server deduplicates on event id and producer sequence).
 */
export class EventSink {
  private readonly queue: CodingEvent[] = [];
  private seq = 0;
  private dropped = 0;
  private flushing: Promise<void> | undefined;
  private timer: NodeJS.Timeout | undefined;
  private readonly spoolFile: string;
  readonly epoch: string;

  private readonly api: RunnerApi;
  readonly sessionId: string;
  private readonly secrets: () => string[];
  private readonly opts: SinkOptions;

  constructor(
    api: RunnerApi,
    sessionId: string,
    secrets: () => string[],
    spoolDir: string,
    opts: SinkOptions = { maxBuffered: 2000, maxSpoolBytes: 64 * 1024 * 1024, batchSize: 100, flushIntervalMs: 1000 },
    epoch = ulid(),
  ) {
    this.api = api;
    this.sessionId = sessionId;
    this.secrets = secrets;
    this.opts = opts;
    this.epoch = epoch;
    fs.mkdirSync(spoolDir, { recursive: true, mode: 0o700 });
    this.spoolFile = path.join(spoolDir, `${sessionId}.jsonl`);
    this.timer = setInterval(() => void this.flush(), opts.flushIntervalMs);
    this.timer.unref();
  }

  emit(type: EventType, source: Source, trust: Trust, payload: Record<string, unknown> = {}, extra: Partial<CodingEvent> = {}): CodingEvent {
    const event: CodingEvent = {
      event_id: ulid(),
      schema_version: 'agenomic.coding.event/v1',
      type,
      source,
      trust,
      producer_epoch: this.epoch,
      producer_seq: ++this.seq,
      occurred_at: new Date().toISOString(),
      ...extra,
      coding_session_id: this.sessionId,
      payload: redactValue(payload, this.secrets()) as Record<string, unknown>,
    };
    if (this.queue.length >= this.opts.maxBuffered) {
      const idx = this.queue.findIndex((e) => !MANDATORY.has(e.type));
      if (idx >= 0) {
        this.queue.splice(idx, 1);
        this.dropped++;
      } else {
        this.spill([this.queue.shift()!]);
      }
    }
    this.queue.push(event);
    if (this.queue.length >= this.opts.batchSize) void this.flush();
    return event;
  }

  private spill(events: CodingEvent[]): void {
    const size = fs.existsSync(this.spoolFile) ? fs.statSync(this.spoolFile).size : 0;
    if (size > this.opts.maxSpoolBytes) {
      // Evidence would be lost: say so loudly and keep counting.
      this.dropped += events.length;
      log('error', 'event spool full: evidence events dropped', { session: this.sessionId, count: events.length });
      return;
    }
    fs.appendFileSync(this.spoolFile, events.map((e) => JSON.stringify(e)).join('\n') + '\n', { mode: 0o600 });
  }

  pending(): number {
    return this.queue.length;
  }

  async flush(): Promise<void> {
    if (this.flushing) return this.flushing;
    this.flushing = this.doFlush().finally(() => {
      this.flushing = undefined;
    });
    return this.flushing;
  }

  private async doFlush(): Promise<void> {
    if (this.dropped > 0) {
      const n = this.dropped;
      this.dropped = 0;
      this.queue.unshift({
        event_id: ulid(), coding_session_id: this.sessionId, schema_version: 'agenomic.coding.event/v1', type: 'error', source: 'supervisor', trust: 'native',
        producer_epoch: this.epoch, producer_seq: ++this.seq, occurred_at: new Date().toISOString(),
        payload: { code: 'events_dropped', count: n },
      });
    }
    // Spooled evidence first, in order.
    if (fs.existsSync(this.spoolFile)) {
      const lines = fs.readFileSync(this.spoolFile, 'utf8').split('\n').filter(Boolean);
      // One spool file per session: an event spooled by an earlier
      // version without the session id gets it here.
      const spooled = lines.map((l) => ({ ...(JSON.parse(l) as CodingEvent), coding_session_id: this.sessionId }));
      try {
        for (let i = 0; i < spooled.length; i += this.opts.batchSize) {
          await this.send(spooled.slice(i, i + this.opts.batchSize));
        }
        fs.rmSync(this.spoolFile, { force: true });
      } catch (error) {
        log('warn', 'spool flush deferred', { session: this.sessionId, error: errorMessage(error) });
        return;
      }
    }
    while (this.queue.length > 0) {
      const batch = this.queue.slice(0, this.opts.batchSize);
      try {
        await this.send(batch);
        this.queue.splice(0, batch.length);
      } catch (error) {
        log('warn', 'event flush deferred', { session: this.sessionId, error: errorMessage(error) });
        // Keep memory bounded while offline: evidence goes to disk.
        if (this.queue.length > this.opts.maxBuffered / 2) {
          const mandatory = this.queue.filter((e) => MANDATORY.has(e.type));
          this.dropped += this.queue.length - mandatory.length;
          this.spill(mandatory);
          this.queue.length = 0;
        }
        return;
      }
    }
  }

  private async send(events: CodingEvent[]): Promise<void> {
    await this.api.request('POST', `/v1/coding/runner/sessions/${this.sessionId}/events`, { body: { events }, retry: true, timeoutMs: 20000 });
  }

  async close(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.flush();
    if (this.queue.length > 0) this.spill(this.queue.splice(0));
  }
}
