import { loadCredentials, saveCredentials, type Credentials } from './config.ts';
import { errorMessage, log, sleep } from './util.ts';

/**
 * An error answered by the gateway (or a network failure, status 0), with its stable code.
 *
 * @example
 * try {
 *   await api.request('GET', '/v1/coding/runner/commands');
 * } catch (error) {
 *   if (error instanceof ApiError && error.status === 401) console.error(error.code);
 * }
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export interface RequestOptions {
  body?: unknown;
  /** Total time budget for this call, retries included. */
  timeoutMs?: number;
  /** Only idempotent calls are retried on network errors and 5xx. */
  retry?: boolean;
  signal?: AbortSignal;
}

/**
 * Runner side of the coding API. Credentials are short lived bearer tokens
 * rotated with the refresh token; they never appear in URLs, arguments or
 * logs, and are never handed to the runtimes.
 *
 * @example
 * const api = new RunnerApi('https://agenomic.example.com');
 * await api.request('POST', '/v1/coding/runner/heartbeat', { body: { boot_id: ulid() }, retry: true });
 */
export class RunnerApi {
  readonly endpoint: string;
  private creds: Credentials | undefined;
  private refreshing: Promise<void> | undefined;
  private readonly persist: boolean;

  constructor(endpoint: string, creds?: Credentials, persist = true) {
    this.endpoint = endpoint.replace(/\/+$/, '');
    this.creds = creds ?? loadCredentials();
    this.persist = persist;
  }

  /**
   * Public enrollment: exchanges a one time token for credentials.
   *
   * @example
   * const { runner, credentials } = await RunnerApi.enroll('https://agenomic.example.com', {
   *   enrollment_token: 'agmcen_…', name: 'laptop', kind: 'local_machine', os: process.platform, arch: process.arch, connector_version: '0.1.0',
   * });
   * saveCredentials(credentials);
   */
  static async enroll(endpoint: string, body: Record<string, unknown>): Promise<{ runner: { id: string }; credentials: Credentials }> {
    const res = await fetch(`${endpoint.replace(/\/+$/, '')}/v1/coding/runners/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15000),
    });
    const json = (await res.json().catch(() => ({}))) as Record<string, any>;
    if (res.status !== 201) throw new ApiError(res.status, json?.error?.code ?? 'enroll_failed', json?.error?.message ?? `enroll failed (${res.status})`);
    return json as any;
  }

  /**
   * The current runner credentials, rotated in place by request().
   *
   * @example
   * const token = api.credentials()?.access_token; // redacted from every event, never logged
   */
  credentials(): Credentials | undefined {
    return this.creds;
  }

  private async refresh(): Promise<void> {
    if (this.refreshing) return this.refreshing;
    this.refreshing = (async () => {
      if (!this.creds) throw new ApiError(401, 'not_enrolled', 'no runner credentials');
      const res = await fetch(`${this.endpoint}/v1/coding/runners/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ refresh_token: this.creds.refresh_token }),
        signal: AbortSignal.timeout(15000),
      });
      const json = (await res.json().catch(() => ({}))) as Record<string, any>;
      if (res.status !== 200) {
        throw new ApiError(res.status, 'refresh_failed', 'runner credentials were refused (revoked, expired or reused); enroll again');
      }
      this.creds = json.credentials as Credentials;
      if (this.persist) saveCredentials(this.creds);
      log('info', 'runner credentials rotated');
    })().finally(() => {
      this.refreshing = undefined;
    });
    return this.refreshing;
  }

  /**
   * Calls the runner API with the current credentials, refreshing them once on a 401; `retry` retries network errors and 5xx within `timeoutMs`.
   *
   * @example
   * const { commands } = await api.request<{ commands: unknown[] }>('GET', '/v1/coding/runner/commands?wait=25', { timeoutMs: 40000 });
   */
  async request<T = any>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    const deadline = Date.now() + (opts.timeoutMs ?? 30000);
    let attempt = 0;
    let refreshed = false;
    for (;;) {
      attempt++;
      if (this.creds && Date.parse(this.creds.access_expires_at) - Date.now() < 30000 && !refreshed) {
        await this.refresh();
        refreshed = true;
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new ApiError(0, 'timeout', `${method} ${path} timed out`);
      let res: Response;
      try {
        res = await fetch(`${this.endpoint}${path}`, {
          method,
          headers: {
            authorization: `Bearer ${this.creds?.access_token ?? ''}`,
            ...(opts.body !== undefined ? { 'content-type': 'application/json' } : {}),
          },
          body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
          signal: opts.signal ? AbortSignal.any([opts.signal, AbortSignal.timeout(remaining)]) : AbortSignal.timeout(remaining),
        });
      } catch (error) {
        if (opts.signal?.aborted) throw error;
        if (!opts.retry || attempt >= 4 || Date.now() >= deadline) throw new ApiError(0, 'network', `${method} ${path}: ${errorMessage(error)}`);
        await sleep(Math.min(200 * 4 ** (attempt - 1), Math.max(0, deadline - Date.now())));
        continue;
      }
      if (res.status === 401 && !refreshed) {
        await this.refresh();
        refreshed = true;
        continue;
      }
      if (res.status >= 500 && opts.retry && attempt < 4 && Date.now() < deadline) {
        await sleep(Math.min(200 * 4 ** (attempt - 1), Math.max(0, deadline - Date.now())));
        continue;
      }
      const text = await res.text();
      const json = text ? (() => { try { return JSON.parse(text); } catch { return { raw: text }; } })() : {};
      if (res.status >= 400) {
        throw new ApiError(res.status, json?.error?.code ?? `http_${res.status}`, json?.error?.message ?? `${method} ${path} failed with ${res.status}`);
      }
      return json as T;
    }
  }
}
