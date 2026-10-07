import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readJson, writeSecretFile } from './util.ts';

export type Mode = 'observe' | 'shadow' | 'enforce';

export interface Capture {
  conversation: boolean;
  commands: boolean;
  diffs: boolean;
  outputs: boolean;
}

/** Metadata only unless the workspace explicitly opts in (design §9). */
export const DEFAULT_CAPTURE: Capture = { conversation: false, commands: false, diffs: false, outputs: false };

export interface WorkspaceConfig {
  id: string;
  name: string;
  /** Absolute path of a git checkout the developer explicitly declared. */
  path: string;
  repo?: string;
  default_branch?: string;
}

export interface RuntimeConfig {
  enabled: boolean;
  /** Path to the runtime executable; default: the pinned npm package. */
  executable?: string;
  /** Names of environment variables passed to the runtime (provider auth). */
  env_passthrough: string[];
  /** Non secret variables (for example a model gateway base URL). */
  extra_env: Record<string, string>;
  /** Domains the sandbox lets the agent reach (Claude Code). */
  allowed_domains: string[];
  /** Extra `config.toml` fragment for the isolated CODEX_HOME (Codex). */
  extra_config_toml?: string;
}

export interface ConnectorConfig {
  endpoint: string;
  name: string;
  kind: 'local_machine' | 'runner';
  runner_id?: string;
  workspaces: WorkspaceConfig[];
  local_sessions: { mode: Mode; policy_refs: string[]; capture: Capture };
  runtimes: { claude_code: RuntimeConfig; codex: RuntimeConfig };
}

export interface Credentials {
  access_token: string;
  access_expires_at: string;
  refresh_token: string;
  refresh_expires_at: string;
}

/**
 * The connector's home directory (AGENOMIC_CONNECTOR_HOME, else ~/.config/agenomic/connector).
 *
 * @example
 * process.env.AGENOMIC_CONNECTOR_HOME = '/tmp/agn';
 * home(); // '/tmp/agn'
 */
export function home(): string {
  return process.env.AGENOMIC_CONNECTOR_HOME || path.join(os.homedir(), '.config', 'agenomic', 'connector');
}

export const paths = {
  config: () => path.join(home(), 'connector.json'),
  credentials: () => path.join(home(), 'credentials.json'),
  state: () => path.join(home(), 'state'),
  socket: () => path.join(home(), 'state', 'connector.sock'),
  spool: () => path.join(home(), 'state', 'spool'),
  worktrees: () => path.join(home(), 'state', 'worktrees'),
  runtimeHome: (runtime: string) => path.join(home(), 'state', 'runtime', runtime),
  sessions: () => path.join(home(), 'state', 'sessions.json'),
  /** Action outcomes the gateway had not acknowledged when the daemon stopped, delivered by the next start. */
  outcomes: () => path.join(home(), 'state', 'outcomes.json'),
  /** Fail mode of the local-session hooks, recorded with each configuration change. */
  localFailMode: () => path.join(home(), 'state', 'local-sessions.fail'),
};

/**
 * A path and, when it differs (a symlink on the way, such as macOS's
 * /tmp), its real path. A sandbox rule names every spelling, so that
 * neither one escapes it; a path that does not exist yet has one.
 *
 * @example
 * spellings('/tmp/agn'); // ['/tmp/agn', '/private/tmp/agn'] on macOS, ['/tmp/agn'] on Linux
 */
export function spellings(p: string): string[] {
  const abs = path.resolve(p);
  let real = abs;
  try {
    real = fs.realpathSync(abs);
  } catch {
    // Not created yet: only the spelling given.
  }
  return real === abs ? [abs] : [abs, real];
}

const defaultRuntime = (): RuntimeConfig => ({ enabled: true, env_passthrough: [], extra_env: {}, allowed_domains: [] });

/**
 * A configuration with no workspace, observe local sessions and both runtimes enabled.
 *
 * @example
 * const cfg = defaultConfig('https://agenomic.example.com', os.hostname());
 */
export function defaultConfig(endpoint: string, name: string): ConnectorConfig {
  return {
    endpoint,
    name,
    kind: 'local_machine',
    workspaces: [],
    local_sessions: { mode: 'observe', policy_refs: [], capture: { ...DEFAULT_CAPTURE } },
    runtimes: {
      claude_code: { ...defaultRuntime(), env_passthrough: ['ANTHROPIC_API_KEY'] },
      codex: { ...defaultRuntime(), env_passthrough: ['OPENAI_API_KEY'] },
    },
  };
}

const SECRET_NAME = /KEY|TOKEN|SECRET|PASSW|CREDENTIAL|AUTH/i;

/**
 * The whole environment of a process the connector starts for a runtime
 * (the runtime itself, or an auxiliary one such as the `hooks/list` App
 * Server): PATH, the given base variables, the configured variables
 * passed through and the configured extra_env. Nothing else of the
 * daemon's environment (its own or the developer's credentials) reaches it.
 *
 * @example
 * runtimeEnv(cfg.runtimes.codex, { HOME: paths.runtimeHome('codex'), CODEX_HOME: home }); // { PATH, HOME, CODEX_HOME, ...passthrough, ...extra_env }
 */
export function runtimeEnv(runtime: Pick<RuntimeConfig, 'env_passthrough' | 'extra_env'>, base: Record<string, string>, env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const out: Record<string, string> = { PATH: env.PATH ?? '/usr/bin:/bin', ...base };
  for (const k of runtime.env_passthrough) if (env[k]) out[k] = env[k]!;
  return Object.assign(out, runtime.extra_env);
}

/**
 * Credential values of a runtime: the variables passed through to it
 * (provider authentication) and the extra_env values whose name says they
 * are secret. They are redacted from every event before it is buffered.
 *
 * @example
 * runtimeSecrets({ enabled: true, env_passthrough: ['OPENAI_API_KEY'], extra_env: { GATEWAY_TOKEN: 't0k' }, allowed_domains: [] }); // [process.env.OPENAI_API_KEY, 't0k']
 */
export function runtimeSecrets(runtime: RuntimeConfig, env: NodeJS.ProcessEnv = process.env): string[] {
  const values = runtime.env_passthrough.map((k) => env[k] ?? '');
  for (const [k, v] of Object.entries(runtime.extra_env)) if (SECRET_NAME.test(k)) values.push(v);
  return values.filter(Boolean);
}

/**
 * Reads and validates connector.json; throws when the machine is not enrolled.
 *
 * @example
 * const cfg = loadConfig();
 * console.log(cfg.endpoint, cfg.workspaces.length);
 */
export function loadConfig(): ConnectorConfig {
  const cfg = readJson<ConnectorConfig>(paths.config());
  if (!cfg) throw new Error(`not enrolled: ${paths.config()} is missing (run "agenomic-connector enroll")`);
  validateConfig(cfg);
  return cfg;
}

/**
 * Throws when a configuration would be unsafe or ambiguous: a non-loopback http endpoint, a bad or duplicate workspace id, a relative workspace path.
 *
 * @example
 * validateConfig(defaultConfig('http://gateway.example.com', 'x')); // throws: plain http is only accepted for a loopback endpoint
 */
export function validateConfig(cfg: ConnectorConfig): void {
  if (!/^https?:\/\//.test(cfg.endpoint)) throw new Error('endpoint must be an http(s) URL');
  if (cfg.endpoint.startsWith('http://') && !/^http:\/\/(127\.0\.0\.1|localhost)(:|\/|$)/.test(cfg.endpoint)) {
    throw new Error('plain http is only accepted for a loopback endpoint');
  }
  const ids = new Set<string>();
  for (const w of cfg.workspaces) {
    if (!/^[A-Za-z0-9._-]{1,120}$/.test(w.id)) throw new Error(`invalid workspace id ${JSON.stringify(w.id)}`);
    if (ids.has(w.id)) throw new Error(`duplicate workspace id ${w.id}`);
    ids.add(w.id);
    if (!path.isAbsolute(w.path)) throw new Error(`workspace ${w.id}: path must be absolute`);
  }
}

/**
 * Validates and writes connector.json (mode 0600), with the fail mode the local hooks fall back to.
 *
 * @example
 * const cfg = loadConfig();
 * cfg.local_sessions.mode = 'shadow';
 * saveConfig(cfg);
 */
export function saveConfig(cfg: ConnectorConfig): void {
  validateConfig(cfg);
  writeSecretFile(paths.config(), JSON.stringify(cfg, null, 2) + '\n');
  writeSecretFile(paths.localFailMode(), failModeOf(cfg.local_sessions.mode) + '\n');
}

const failModeOf = (mode: Mode): 'closed' | 'open' => (mode === 'enforce' ? 'closed' : 'open');

/**
 * Fail mode of the hooks installed for the developer's own sessions,
 * resolved when a hook needs it (the daemon did not answer) from the
 * current local-sessions mode, so that `local-sessions --mode` also
 * applies to hooks installed before the change. If connector.json cannot
 * be read, the mode recorded with the last configuration change decides;
 * if that cannot be read either while a configuration exists, the hook
 * fails closed.
 *
 * @example
 * if (localFailMode() === 'closed') console.log('local hooks refuse tool calls while the daemon is down');
 */
export function localFailMode(): 'closed' | 'open' {
  try {
    const mode = JSON.parse(fs.readFileSync(paths.config(), 'utf8'))?.local_sessions?.mode;
    if (mode === 'observe' || mode === 'shadow' || mode === 'enforce') return failModeOf(mode);
  } catch {
    /* unreadable or invalid: use the recorded mode */
  }
  try {
    const recorded = fs.readFileSync(paths.localFailMode(), 'utf8').trim();
    if (recorded === 'closed' || recorded === 'open') return recorded;
  } catch {
    /* not recorded */
  }
  return fs.existsSync(paths.config()) ? 'closed' : 'open';
}

/**
 * The runner credentials, if enrolled; throws when the file is readable by other users.
 *
 * @example
 * const creds = loadCredentials(); // undefined before `enroll`
 */
export function loadCredentials(): Credentials | undefined {
  const file = paths.credentials();
  if (fs.existsSync(file) && (fs.statSync(file).mode & 0o077) !== 0) {
    throw new Error(`${file} is readable by other users; chmod 600 it`);
  }
  return readJson<Credentials>(file);
}

/**
 * Writes the runner credentials (mode 0600).
 *
 * @example
 * saveCredentials((await RunnerApi.enroll(endpoint, body)).credentials);
 */
export function saveCredentials(c: Credentials): void {
  writeSecretFile(paths.credentials(), JSON.stringify(c) + '\n');
}
