import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { redact } from './redact.ts';

/**
 * Git operations the connector performs on a declared workspace. It never
 * runs `reset --hard`, `clean`, `stash` or `checkout -- .` on a human
 * checkout: a launched session works in its own worktree, created from a
 * recorded base revision, and the human checkout is only read.
 */
function git(cwd: string, args: string[], maxBuffer = 16 * 1024 * 1024): string {
  return execFileSync('git', ['-C', cwd, ...args], {
    encoding: 'utf8',
    maxBuffer,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
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
 */
export function diff(dir: string, base: string, secrets: string[] = [], maxBytes = 256 * 1024): { text: string; truncated: boolean } {
  const raw = git(dir, ['diff', '-M', base], 64 * 1024 * 1024);
  const window = maxBytes + REDACTION_SLACK;
  const text = redact(raw.length > window ? raw.slice(0, window) : raw, secrets);
  return text.length > maxBytes ? { text: text.slice(0, maxBytes), truncated: true } : { text, truncated: raw.length > window };
}

export function headRevision(dir: string): string | null {
  try {
    return git(dir, ['rev-parse', 'HEAD']).trim();
  } catch {
    return null;
  }
}
