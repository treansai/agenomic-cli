import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** Monotonic-enough ULID (time prefix + 80 random bits). */
export function ulid(now = Date.now()): string {
  let time = '';
  let t = now;
  for (let i = 0; i < 10; i++) {
    time = CROCKFORD[t % 32] + time;
    t = Math.floor(t / 32);
  }
  const bytes = randomBytes(16);
  let rand = '';
  for (let i = 0; i < 16; i++) rand += CROCKFORD[bytes[i]! % 32];
  return time + rand;
}

export const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => {
      clearTimeout(t);
      resolve();
    }, { once: true });
  });

/** Write a file atomically with mode 0600 (secrets and config). */
export function writeSecretFile(file: string, content: string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, content, { mode: 0o600 });
  fs.renameSync(tmp, file);
  fs.chmodSync(file, 0o600);
}

export function readJson<T>(file: string): T | undefined {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8')) as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
}

export type Level = 'debug' | 'info' | 'warn' | 'error';
const LEVELS: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

/** Structured logs on stderr. Never pass secrets: callers log ids only. */
export function log(level: Level, msg: string, fields: Record<string, unknown> = {}): void {
  const min = (process.env.AGENOMIC_CONNECTOR_LOG as Level) || 'info';
  if (LEVELS[level] < (LEVELS[min] ?? 20)) return;
  process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields }) + '\n');
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Resolve `p` against `cwd` and report whether its real path leaves `root`. */
export function realPathEscapes(p: string, cwd: string, root: string): boolean {
  const abs = path.resolve(cwd, p);
  let probe = abs;
  // The target may not exist yet (a write): resolve the closest existing parent.
  while (!fs.existsSync(probe) && path.dirname(probe) !== probe) probe = path.dirname(probe);
  let real: string;
  try {
    real = fs.realpathSync(probe);
  } catch {
    return false;
  }
  const realRoot = (() => {
    try {
      return fs.realpathSync(root);
    } catch {
      return root;
    }
  })();
  const lexicalInside = abs === root || abs.startsWith(root + path.sep);
  const realInside = real === realRoot || real.startsWith(realRoot + path.sep);
  return lexicalInside && !realInside;
}

/** Path of an executable, looked up on PATH when it is a bare command name. */
export function resolveExecutable(exe: string): string | null {
  if (exe.includes('/')) return fs.existsSync(exe) ? path.resolve(exe) : null;
  for (const dir of (process.env.PATH ?? '').split(path.delimiter).filter(Boolean)) {
    const candidate = path.join(dir, exe);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      /* not here */
    }
  }
  return null;
}

const versions = new Map<string, string | null>();

/**
 * The version a runtime executable reports (first x.y.z of `--version`),
 * cached per file revision. Null when it cannot be run or prints no
 * version: nothing is then validated for it.
 */
export function executableVersion(exe: string): string | null {
  const file = resolveExecutable(exe);
  if (!file) return null;
  let key: string;
  try {
    const st = fs.statSync(file);
    key = `${file}\0${st.size}\0${st.mtimeMs}`;
  } catch {
    return null;
  }
  if (versions.has(key)) return versions.get(key)!;
  let version: string | null = null;
  try {
    const script = /\.[cm]?js$/.test(file);
    const out = execFileSync(script ? process.execPath : file, script ? [file, '--version'] : ['--version'], { encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'ignore'] });
    version = /\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?/.exec(out)?.[0] ?? null;
  } catch {
    version = null;
  }
  versions.set(key, version);
  return version;
}
