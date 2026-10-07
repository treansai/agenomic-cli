import { execFileSync } from 'node:child_process';
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

export interface WorkspaceState {
  base_revision: string | null;
  branch: string | null;
  preexisting_changes: string[];
}

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

export interface FileChange {
  path: string;
  status: 'added' | 'modified' | 'deleted' | 'renamed' | 'untracked';
  added: number | null;
  deleted: number | null;
}

/** Changes in `dir` relative to `base` (committed, staged, unstaged and untracked). */
export function changes(dir: string, base: string): FileChange[] {
  const out = new Map<string, FileChange>();
  const numstat = git(dir, ['diff', '--numstat', '-M', base]);
  const names = git(dir, ['diff', '--name-status', '-M', base]);
  const counts = new Map<string, [number | null, number | null]>();
  for (const line of numstat.split('\n').filter(Boolean)) {
    const [a, d, ...rest] = line.split('\t');
    counts.set(rest[rest.length - 1]!, [a === '-' ? null : Number(a), d === '-' ? null : Number(d)]);
  }
  for (const line of names.split('\n').filter(Boolean)) {
    const [code, ...files] = line.split('\t');
    const file = files[files.length - 1]!;
    const status = code!.startsWith('A') ? 'added' : code!.startsWith('D') ? 'deleted' : code!.startsWith('R') ? 'renamed' : 'modified';
    const [added, deleted] = counts.get(file) ?? [null, null];
    out.set(file, { path: file, status, added, deleted });
  }
  for (const file of git(dir, ['ls-files', '--others', '--exclude-standard']).split('\n').filter(Boolean)) {
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
 */
export function diff(dir: string, base: string, secrets: string[] = [], maxBytes = 256 * 1024): { text: string; truncated: boolean } {
  const window = maxBytes + REDACTION_SLACK;
  const { raw, uncaptured } = withUntracked(dir, window, (env) => git(dir, ['diff', '-M', base], 64 * 1024 * 1024, { env }));
  let full = raw;
  for (const f of uncaptured) {
    // Past the bytes read, the rest would only be cut off.
    if (full.length > window) break;
    full += `diff --git a/${f.path} b/${f.path}\nnew file mode 100644\n(untracked file of ${f.size} bytes, not captured)\n`;
  }
  const text = redact(full.length > window ? full.slice(0, window) : full, secrets);
  return text.length > maxBytes ? { text: text.slice(0, maxBytes), truncated: true } : { text, truncated: full.length > window };
}

/**
 * Runs `fn` with an environment whose index also holds the untracked
 * files of `dir` as intent-to-add entries, as many as fit in `maxBytes`
 * (their sizes plus their headers), and returns the untracked files left
 * out. Many untracked files (a venv, generated data) are thereby neither
 * read nor diffed beyond what the capture keeps.
 */
function withUntracked(dir: string, maxBytes: number, fn: (env: Record<string, string>) => string): { raw: string; uncaptured: { path: string; size: number }[] } {
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

export function headRevision(dir: string): string | null {
  try {
    return git(dir, ['rev-parse', 'HEAD']).trim();
  } catch {
    return null;
  }
}
