import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { redact } from './redact.ts';

/**
 * Git operations the connector performs on a declared workspace. It never
 * runs `reset --hard`, `clean`, `stash` or `checkout -- .` on a human
 * checkout: a launched session works in its own worktree, created from a
 * recorded base revision, and the human checkout is only read.
 */
function git(cwd: string, args: string[], maxBuffer = 16 * 1024 * 1024, opts: { env?: Record<string, string>; input?: string } = {}): string {
  return execFileSync('git', ['-C', cwd, ...args], {
    encoding: 'utf8',
    maxBuffer,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0', ...opts.env },
    input: opts.input,
    stdio: [opts.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
  });
}

/**
 * Output of a git command read up to `limit` bytes: past it, git is
 * stopped and `more` is set, so a huge output is neither buffered whole
 * nor an error. The bound is on the output only: stderr goes to a
 * temporary file, of which the start is the error's reason, so that a
 * verbose stderr never reads as a cut output.
 */
function gitBounded(cwd: string, args: string[], limit: number, env: Record<string, string> = {}): { out: string; more: boolean } {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agn-git-'));
  const errFd = fs.openSync(path.join(tmp, 'stderr'), 'w+', 0o600);
  try {
    const r = spawnSync('git', ['-C', cwd, ...args], {
      maxBuffer: limit,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0', ...env },
      stdio: ['ignore', 'pipe', errFd],
    });
    const more = (r.error as NodeJS.ErrnoException | undefined)?.code === 'ENOBUFS';
    if (r.error && !more) throw r.error;
    if (!more && r.status !== 0) {
      const reason = Buffer.alloc(500);
      const n = fs.readSync(errFd, reason, 0, reason.length, 0);
      throw new Error(`git ${args[0]} failed: ${reason.subarray(0, n).toString('utf8').trim()}`);
    }
    const out = r.stdout ?? Buffer.alloc(0);
    return { out: out.subarray(0, limit).toString('utf8'), more: more || out.length > limit };
  } finally {
    fs.closeSync(errFd);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/** The complete lines of a bounded output: a line cut at the bound is dropped. */
function lines(r: { out: string; more: boolean }): string[] {
  const text = r.more ? r.out.slice(0, r.out.lastIndexOf('\n') + 1) : r.out;
  return text.split('\n').filter(Boolean);
}

export interface WorkspaceState {
  base_revision: string | null;
  branch: string | null;
  preexisting_changes: string[];
}

/**
 * The HEAD revision, branch and uncommitted changes of a checkout; it is only read.
 *
 * @example
 * const { base_revision, branch, preexisting_changes } = inspect('/src/app');
 */
export function inspect(dir: string): WorkspaceState {
  const rev = (() => {
    try {
      return git(dir, ['rev-parse', 'HEAD']).trim();
    } catch {
      return null;
    }
  })();
  const branch = (() => {
    try {
      const b = git(dir, ['rev-parse', '--abbrev-ref', 'HEAD']).trim();
      return b === 'HEAD' ? null : b;
    } catch {
      return null;
    }
  })();
  const status = (() => {
    try {
      return git(dir, ['status', '--porcelain=v1', '--untracked-files=normal']);
    } catch {
      return '';
    }
  })();
  return {
    base_revision: rev,
    branch,
    preexisting_changes: status.split('\n').filter(Boolean).map((l) => l.slice(3)).slice(0, 500),
  };
}

const BRANCH_RE = /^(?!-)(?!.*\.\.)(?!.*[ ~^:?*[\\])[A-Za-z0-9._/-]{1,200}$/;

/**
 * A dedicated worktree for a launched session. The branch must not exist:
 * an existing branch may hold someone's work, so it is never reused or
 * reset.
 *
 * @example
 * const tree = createWorktree('/src/app', path.join(paths.worktrees(), sessionId), 'agenomic/fix-tests');
 */
export function createWorktree(workspace: string, target: string, branch: string | null): WorkspaceState & { path: string } {
  const human = inspect(workspace);
  if (!human.base_revision) throw new Error('workspace is not a git checkout with a commit');
  if (fs.existsSync(target)) throw new Error(`worktree path already exists: ${target}`);
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  if (branch) {
    if (!BRANCH_RE.test(branch)) throw new Error('invalid branch name');
    const exists = (() => {
      try {
        git(workspace, ['rev-parse', '--verify', '--quiet', `refs/heads/${branch}`]);
        return true;
      } catch {
        return false;
      }
    })();
    if (exists) throw new Error(`branch ${branch} already exists; choose a new branch so existing work is not touched`);
    git(workspace, ['worktree', 'add', '-b', branch, target, human.base_revision]);
  } else {
    git(workspace, ['worktree', 'add', '--detach', target, human.base_revision]);
  }
  return { ...inspect(target), base_revision: human.base_revision, preexisting_changes: human.preexisting_changes, path: target };
}

/**
 * Removes a dedicated worktree that createWorktree made for a launch
 * that did not start, and its new branch while it still points at
 * `base` (no commit of its own), so that nothing of the launch is left.
 * A branch that moved holds work and is kept.
 *
 * @example
 * removeWorktree('/src/app', tree.path, tree.branch, tree.base_revision);
 */
export function removeWorktree(workspace: string, target: string, branch: string | null, base: string | null): void {
  git(workspace, ['worktree', 'remove', '--force', target]);
  if (branch && base) {
    try {
      // Deleted only while it still names `base`.
      git(workspace, ['update-ref', '-d', `refs/heads/${branch}`, base]);
    } catch {
      /* the branch moved: kept */
    }
  }
}

export interface FileChange {
  path: string;
  status: 'added' | 'modified' | 'deleted' | 'renamed' | 'untracked';
  added: number | null;
  deleted: number | null;
}

/**
 * Changes in `dir` relative to `base` (committed, staged, unstaged and
 * untracked), at most 2000. Each git listing is read up to `maxBytes`:
 * a change set of any size lists the files that fit, never an error.
 *
 * @example
 * const files = changes(worktree, baseRevision); // [{ path: 'src/app.ts', status: 'modified', added: 3, deleted: 1 }, …]
 */
export function changes(dir: string, base: string, maxBytes = 4 * 1024 * 1024): FileChange[] {
  const out = new Map<string, FileChange>();
  const numstat = lines(gitBounded(dir, ['diff', '--numstat', '-M', base], maxBytes));
  const names = lines(gitBounded(dir, ['diff', '--name-status', '-M', base], maxBytes));
  const counts = new Map<string, [number | null, number | null]>();
  for (const line of numstat) {
    const [a, d, ...rest] = line.split('\t');
    counts.set(rest[rest.length - 1]!, [a === '-' ? null : Number(a), d === '-' ? null : Number(d)]);
  }
  for (const line of names) {
    const [code, ...files] = line.split('\t');
    const file = files[files.length - 1]!;
    const status = code!.startsWith('A') ? 'added' : code!.startsWith('D') ? 'deleted' : code!.startsWith('R') ? 'renamed' : 'modified';
    const [added, deleted] = counts.get(file) ?? [null, null];
    out.set(file, { path: file, status, added, deleted });
  }
  for (const file of lines(gitBounded(dir, ['ls-files', '--others', '--exclude-standard'], maxBytes))) {
    if (!out.has(file)) out.set(file, { path: file, status: 'untracked', added: null, deleted: null });
  }
  return [...out.values()].slice(0, 2000);
}

/** Text past the cap that is still redacted, so that a secret across the cut is recognised whole. */
const REDACTION_SLACK = 64 * 1024;

/**
 * Unified diff against `base`, redacted with the session's credential
 * values and the known secret patterns, then capped. Binary files are
 * summarised by git. Redaction runs before the cut, as for every other
 * captured field: a secret across the cut would otherwise leave a prefix
 * that no pattern recognises. It reads the cap plus a slack far longer
 * than any secret, so its cost stays bounded for a huge diff.
 *
 * Untracked files (those `changes()` lists, .gitignore respected) are
 * part of it as additions: they are marked intent-to-add in a temporary
 * copy of the index, so the checkout's own index is never touched. They
 * are read only up to the bytes a diff reads, in total: one larger than
 * that, or past it, is named, not read.
 *
 * @example
 * const { text, truncated } = diff(worktree, baseRevision, ctx.secrets());
 */
export function diff(dir: string, base: string, secrets: string[] = [], maxBytes = 256 * 1024): { text: string; truncated: boolean } {
  const window = maxBytes + REDACTION_SLACK;
  // git output is read only up to the window: a diff of any size costs
  // the window, never the whole diff.
  const { raw, uncaptured } = withUntracked(dir, window, (env) => gitBounded(dir, ['diff', '-M', base], window + 1, env));
  let full = raw.out;
  for (const f of uncaptured) {
    // Past the bytes read, the rest would only be cut off.
    if (raw.more || full.length > window) break;
    full += `diff --git ${quotePath(`a/${f.path}`)} ${quotePath(`b/${f.path}`)}\nnew file mode 100644\n(untracked file of ${f.size} bytes, not captured)\n`;
  }
  const cut = raw.more || full.length > window;
  const text = redact(full.length > window ? full.slice(0, window) : full, secrets);
  return text.length > maxBytes ? { text: text.slice(0, maxBytes), truncated: true } : { text, truncated: cut };
}

/**
 * Payload of a `diff.snapshot` event: the changed files against `base`
 * and, when diffs are captured, the bounded redacted diff. A diff that
 * cannot be read leaves the file list in place, with the reason; a file
 * list that cannot be read is empty, with its reason: the snapshot itself
 * is always made.
 *
 * @example
 * sink.emit('diff.snapshot', 'filesystem', 'observed', snapshot(worktree, baseRevision, capture.diffs, ctx.secrets()));
 */
export function snapshot(dir: string, base: string, captureDiff: boolean, secrets: string[] = []): Record<string, unknown> {
  const payload: Record<string, unknown> = { base_revision: base };
  try {
    payload.files = changes(dir, base);
  } catch (error) {
    payload.files = [];
    payload.files_error = redact(error instanceof Error ? error.message : String(error), secrets).slice(0, 500);
  }
  if (!captureDiff) return payload;
  try {
    const d = diff(dir, base, secrets);
    payload.diff = d.text;
    payload.truncated = d.truncated;
  } catch (error) {
    payload.diff = null;
    payload.diff_error = redact(error instanceof Error ? error.message : String(error), secrets).slice(0, 500);
  }
  return payload;
}

const C_ESCAPES: Record<number, string> = { 7: 'a', 8: 'b', 9: 't', 10: 'n', 11: 'v', 12: 'f', 13: 'r', 34: '"', 92: '\\' };

/**
 * A path as git writes it in a diff header (core.quotePath): one with a
 * control character, a quote, a backslash or a non-ASCII byte is quoted,
 * C-style, so that it cannot read as a header or a hunk of its own.
 *
 * @example
 * quotePath('a/new\nfile.txt'); // '"a/new\\nfile.txt"'
 */
export function quotePath(name: string): string {
  const bytes = Buffer.from(name, 'utf8');
  if (!bytes.some((b) => b < 0x20 || b >= 0x7f || b === 34 || b === 92)) return name;
  let out = '"';
  for (const b of bytes) {
    if (C_ESCAPES[b] !== undefined) out += `\\${C_ESCAPES[b]}`;
    else if (b < 0x20 || b >= 0x7f) out += `\\${b.toString(8).padStart(3, '0')}`;
    else out += String.fromCharCode(b);
  }
  return `${out}"`;
}

/**
 * Runs `fn` with an environment whose index also holds the untracked
 * files of `dir` as intent-to-add entries, as many as fit in `maxBytes`
 * (their sizes plus their headers), and returns the untracked files left
 * out. Many untracked files (a venv, generated data) are thereby neither
 * read nor diffed beyond what the capture keeps.
 */
function withUntracked<T>(dir: string, maxBytes: number, fn: (env: Record<string, string>) => T): { raw: T; uncaptured: { path: string; size: number }[] } {
  const included: string[] = [];
  let budget = maxBytes;
  const uncaptured: { path: string; size: number }[] = [];
  for (const file of git(dir, ['ls-files', '-z', '--others', '--exclude-standard']).split('\0').filter(Boolean)) {
    // A nested repository is listed as a directory: it has no content of its own here.
    if (file.endsWith('/')) continue;
    let size = 0;
    try {
      const st = fs.lstatSync(path.join(dir, file));
      if (st.isFile()) size = st.size;
      else if (!st.isSymbolicLink()) continue;
    } catch {
      continue;
    }
    const cost = size + 2 * file.length + 128;
    if (cost > budget) {
      uncaptured.push({ path: file, size });
    } else {
      budget -= cost;
      included.push(file);
    }
  }
  if (included.length === 0) return { raw: fn({}), uncaptured };
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agn-index-'));
  try {
    const index = path.join(tmp, 'index');
    const real = path.resolve(dir, git(dir, ['rev-parse', '--git-path', 'index']).trim());
    if (fs.existsSync(real)) fs.copyFileSync(real, index);
    const env = { GIT_INDEX_FILE: index };
    git(dir, ['add', '--intent-to-add', '--pathspec-from-file=-', '--pathspec-file-nul'], undefined, { env: { ...env, GIT_LITERAL_PATHSPECS: '1' }, input: included.join('\0') });
    return { raw: fn(env), uncaptured };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * The HEAD commit of a checkout, or null.
 *
 * @example
 * const head = headRevision(worktree);
 */
export function headRevision(dir: string): string | null {
  try {
    return git(dir, ['rev-parse', 'HEAD']).trim();
  } catch {
    return null;
  }
}
