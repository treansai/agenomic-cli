import { loadCredentials, saveCredentials, type Credentials } from './config.ts';
import { errorMessage, log, sleep } from './util.ts';

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

  /** Public enrollment: exchanges a one time token for credentials. */
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
