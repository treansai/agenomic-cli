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
 *
 * @example
 * const sink = new EventSink(api, sessionId, () => [token], paths.spool());
 * sink.emit('turn.completed', 'runtime', 'native', {}, { runtime_turn_id: '1' });
 * await sink.close();
 */
export class EventSink {
  private readonly queue: CodingEvent[] = [];
  /** The batch being sent, out of the queue until its send settles. */
  private inflight: CodingEvent[] = [];
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

  /**
   * Queues an event, redacted first; evidence is spooled to disk rather than dropped.
   *
   * @example
   * sink.emit('file.changed', 'runtime', 'native', { path: 'src/app.ts', tool: 'Edit' });
   */
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
    // The bound applies to the queue only: the batch in flight is no
    // longer in it, so it is neither dropped nor spilled here.
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

  private spoolSize(): number {
    try {
      return fs.statSync(this.spoolFile).size;
    } catch {
      return 0;
    }
  }

  private writeSpool(data: Buffer): void {
    const tmp = `${this.spoolFile}.tmp`;
    fs.writeFileSync(tmp, data, { mode: 0o600 });
    fs.renameSync(tmp, this.spoolFile);
  }

  /** Appends evidence to the spool, or inserts it at byte offset `at` (ahead of what was spilled after it). */
  private spill(events: CodingEvent[], at?: number): void {
    if (events.length === 0) return;
    const size = this.spoolSize();
    if (size > this.opts.maxSpoolBytes) {
      // Evidence would be lost: say so loudly and keep counting.
      this.dropped += events.length;
      log('error', 'event spool full: evidence events dropped', { session: this.sessionId, count: events.length });
      return;
    }
    const lines = Buffer.from(events.map((e) => JSON.stringify(e)).join('\n') + '\n');
    if (at === undefined || at >= size) {
      fs.appendFileSync(this.spoolFile, lines, { mode: 0o600 });
      return;
    }
    const data = fs.readFileSync(this.spoolFile);
    this.writeSpool(Buffer.concat([data.subarray(0, at), lines, data.subarray(at)]));
  }

  /**
   * Events not delivered yet: queued, and in flight.
   *
   * @example
   * if (sink.pending() > 0) await sink.flush();
   */
  pending(): number {
    return this.queue.length + this.inflight.length;
  }

  /**
   * Sends the spooled and queued events, oldest first.
   *
   * @example
   * await sink.flush();
   */
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
    for (;;) {
      // Spooled evidence first: events are spilled oldest first, so the
      // spool is older than everything still queued, also when it grew
      // while a batch was in flight.
      if (!(await this.flushSpool())) return;
      // Spilled while that result was awaited: it goes first too.
      if (this.spoolSize() > 0) continue;
      if (this.queue.length === 0) return;
      // The batch leaves the queue while it is sent: what emit() drops or
      // spills meanwhile is never part of it, and a success removes
      // exactly the events that were sent.
      const batch = this.queue.splice(0, this.opts.batchSize);
      const mark = this.spoolSize();
      this.inflight = batch;
      try {
        await this.send(batch);
      } catch (error) {
        log('warn', 'event flush deferred', { session: this.sessionId, error: errorMessage(error) });
        this.requeue(batch, mark);
        // Keep memory bounded while offline: evidence goes to disk.
        if (this.queue.length > this.opts.maxBuffered / 2) {
          const mandatory = this.queue.filter((e) => MANDATORY.has(e.type));
          this.dropped += this.queue.length - mandatory.length;
          this.spill(mandatory);
          this.queue.length = 0;
        }
        return;
      } finally {
        this.inflight = [];
      }
    }
  }

  /**
   * A batch whose send failed goes back ahead of the events emitted after
   * it: to the front of the queue, or, when queued events were spilled
   * while it was in flight, to the spool at the offset it had then.
   */
  private requeue(batch: CodingEvent[], mark: number): void {
    if (this.spoolSize() <= mark) {
      this.queue.unshift(...batch);
      return;
    }
    const mandatory = batch.filter((e) => MANDATORY.has(e.type));
    this.dropped += batch.length - mandatory.length;
    this.spill(mandatory, mark);
  }

  /**
   * Sends the spool in order until it is empty; false when the cloud is
   * unreachable. Only the lines that were sent are removed: events
   * spilled while a batch was in flight stay, and are sent next.
   */
  private async flushSpool(): Promise<boolean> {
    for (;;) {
      let data: Buffer;
      try {
        data = fs.readFileSync(this.spoolFile);
      } catch {
        return true;
      }
      if (data.length === 0) {
        fs.rmSync(this.spoolFile, { force: true });
        return true;
      }
      // Each event with the byte offset just past its line. One spool
      // file per session: an event spooled by an earlier version without
      // the session id gets it here. An unreadable line is consumed and
      // counted as dropped.
      const lines: { end: number; event?: CodingEvent }[] = [];
      for (let start = 0; start < data.length;) {
        const nl = data.indexOf(10, start);
        const end = nl < 0 ? data.length : nl + 1;
        const text = data.subarray(start, nl < 0 ? data.length : nl).toString('utf8');
        start = end;
        if (!text.trim()) continue;
        try {
          lines.push({ end, event: { ...(JSON.parse(text) as CodingEvent), coding_session_id: this.sessionId } });
        } catch {
          this.dropped++;
          lines.push({ end });
        }
      }
      let sent = 0;
      try {
        let batch: CodingEvent[] = [];
        for (let i = 0; i < lines.length; i++) {
          if (lines[i]!.event) batch.push(lines[i]!.event!);
          if (batch.length >= this.opts.batchSize || i === lines.length - 1) {
            if (batch.length > 0) await this.send(batch);
            batch = [];
            sent = lines[i]!.end;
          }
        }
        sent = data.length;
      } catch (error) {
        log('warn', 'spool flush deferred', { session: this.sessionId, error: errorMessage(error) });
        return false;
      } finally {
        this.trimSpool(sent);
      }
    }
  }

  /** Removes the first `bytes` of the spool, keeping what was appended since it was read. */
  private trimSpool(bytes: number): void {
    if (bytes <= 0) return;
    const data = fs.readFileSync(this.spoolFile);
    if (data.length <= bytes) fs.rmSync(this.spoolFile, { force: true });
    else this.writeSpool(data.subarray(bytes));
  }

  private async send(events: CodingEvent[]): Promise<void> {
    await this.api.request('POST', `/v1/coding/runner/sessions/${this.sessionId}/events`, { body: { events }, retry: true, timeoutMs: 20000 });
  }

  /**
   * Stops the periodic flush and sends what is left.
   *
   * @example
   * await sink.close();
   */
  async close(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.flush();
    if (this.queue.length > 0) this.spill(this.queue.splice(0));
  }
}
