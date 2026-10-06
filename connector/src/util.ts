import { spawn, type ChildProcess } from 'node:child_process';
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

const VERSION = /\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?/;
const versions = new Map<string, string | null>();
const reading = new Map<string, Promise<string | null>>();

/** The executable's file and the cache key of its current revision; null when it is not found. */
function revision(exe: string): { file: string; key: string } | null {
  const file = resolveExecutable(exe);
  if (!file) return null;
  try {
    const st = fs.statSync(file);
    return { file, key: `${file}\0${st.size}\0${st.mtimeMs}` };
  } catch {
    return null;
  }
}

/**
 * The version a runtime executable reports (first x.y.z of `--version`),
 * cached per file revision. Null when it cannot be run or prints no
 * version: nothing is then validated for it. `--version` runs in a child
 * process the caller never waits for (it can take seconds, and the
 * daemon answers hooks on the same event loop): `undefined` means it has
 * not answered yet, and it is being read in the background.
 */
export function executableVersion(exe: string): string | null | undefined {
  const rev = revision(exe);
  if (!rev) return null;
  if (versions.has(rev.key)) return versions.get(rev.key)!;
  void readExecutableVersion(exe);
  return undefined;
}

/** executableVersion(), waiting for the answer; one `--version` per file revision. */
export function readExecutableVersion(exe: string): Promise<string | null> {
  const rev = revision(exe);
  if (!rev) return Promise.resolve(null);
  if (versions.has(rev.key)) return Promise.resolve(versions.get(rev.key)!);
  let p = reading.get(rev.key);
  if (!p) {
    p = runVersion(rev.file).then((version) => {
      versions.set(rev.key, version);
      reading.delete(rev.key);
      return version;
    });
    reading.set(rev.key, p);
  }
  return p;
}

function runVersion(file: string, timeoutMs = 10000): Promise<string | null> {
  return new Promise((resolve) => {
    const script = /\.[cm]?js$/.test(file);
    let child: ChildProcess;
    try {
      child = spawn(script ? process.execPath : file, script ? [file, '--version'] : ['--version'], { stdio: ['ignore', 'pipe', 'ignore'] });
    } catch {
      return resolve(null);
    }
    let out = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      child.stdout?.destroy();
      resolve(null);
    }, timeoutMs);
    child.stdout!.setEncoding('utf8');
    child.stdout!.on('data', (d: string) => {
      if (out.length < 64 * 1024) out += d;
    });
    child.on('error', () => {
      clearTimeout(timer);
      resolve(null);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve(code === 0 ? (VERSION.exec(out)?.[0] ?? null) : null);
    });
  });
}
