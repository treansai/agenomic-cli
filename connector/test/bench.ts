// Ingestion throughput against a running gateway (manual; not part of npm test).
// AGENOMIC_E2E_ENDPOINT=… AGENOMIC_E2E_SEED_DATABASE_URL=… node test/bench.ts
import { RunnerApi } from '../src/api.ts';
import { ulid } from '../src/util.ts';
const E = process.env.AGENOMIC_E2E_ENDPOINT!;
const boot = (await (await fetch(`${E}/v1/orgs/bootstrap`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: `bench ${Date.now()}`, owner_email: `bench-${Date.now()}@e2e.agenomic.invalid` }) })).json()) as any;
const inv = (await (await fetch(`${E}/v1/invites`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': boot.bootstrap_api_key.value }, body: JSON.stringify({ email: `b-${Date.now()}@e2e.agenomic.invalid`, role: 'owner' }) })).json()) as any;
const acc = await fetch(`${E}/v1/invites/${inv.raw_token}/accept`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: 'correct-horse-battery-staple' }) });
const cookies = acc.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
const csrf = acc.headers.getSetCookie().find((c) => c.startsWith('agenomic_csrf='))!.split(';')[0]!.split('=')[1]!;
const user = (m: string, p: string, b?: unknown) => fetch(`${E}${p}`, { method: m, headers: { cookie: cookies, 'x-csrf-token': csrf, 'content-type': 'application/json' }, body: b ? JSON.stringify(b) : undefined }).then((r) => r.json() as any);
const tok = await user('POST', '/v1/coding/runners/enrollments', {});
const en = await RunnerApi.enroll(E, { enrollment_token: tok.token, name: 'bench', kind: 'runner', os: 'linux', arch: 'x64', connector_version: '0.1.0' });
const api = new RunnerApi(E, en.credentials, false);
await api.request('POST', '/v1/coding/runner/heartbeat', { body: { boot_id: 'b', connector_version: '0.1.0', runtimes: [], workspaces: [] } });
const s = await api.request('POST', '/v1/coding/runner/sessions', { body: { runtime: 'codex', origin: 'local_connected', runtime_session_id: `bench-${Date.now()}` } });
const sid = s.session.id;
const N = 5000, B = 100, epoch = ulid();
const t0 = performance.now();
for (let i = 0; i < N; i += B) {
  const events = Array.from({ length: B }, (_, j) => ({ event_id: ulid(), schema_version: 'agenomic.coding.event/v1', type: 'tool.completed', source: 'runtime', trust: 'native', producer_epoch: epoch, producer_seq: i + j + 1, occurred_at: new Date().toISOString(), payload: { native_tool: 'Bash', duration_ms: 12, command: 'cargo test -p x' } }));
  await api.request('POST', `/v1/coding/runner/sessions/${sid}/events`, { body: { events } });
}
const ms = performance.now() - t0;
console.log(JSON.stringify({ events: N, batch: B, ms: Math.round(ms), events_per_s: Math.round(N / (ms / 1000)) }));
const mem = process.memoryUsage();
console.log(JSON.stringify({ connector_rss_mb: Math.round(mem.rss / 1e6) }));
