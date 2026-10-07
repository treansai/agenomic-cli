import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { paths } from './config.ts';

/**
 * Installation of the connector's hooks into a scope the developer chose
 * explicitly. Existing hooks are preserved, the file is backed up before
 * the first change, installation is idempotent, and uninstall removes only
 * the entries this tool added.
 */

export const CLAUDE_EVENTS = [
  'SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure',
  'SubagentStart', 'SubagentStop', 'Stop', 'SessionEnd',
] as const;

export const CODEX_EVENTS = ['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop', 'SessionEnd'] as const;

/**
 * What a hook does when the daemon does not answer: `closed` refuses the
 * tool call, `open` leaves the native flow in charge, `local` follows the
 * connector's local-sessions mode at that moment (enforce: closed). The
 * hooks installed for the developer's own sessions use `local`; a launched
 * session's own hooks use the session's fixed mode.
 */
export type FailMode = 'closed' | 'open' | 'local';

const MARK = 'agenomic-connector';
const BLOCK_START = '# >>> agenomic-connector hooks (managed; remove with `agenomic-connector hooks uninstall`)';
const BLOCK_END = '# <<< agenomic-connector hooks';

export function hookCommand(runtime: 'claude-code' | 'codex', failMode: FailMode, deadlineMs = 25000, socket = paths.socket()): string {
  const bin = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'agenomic-connector.mjs');
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  return `${q(process.execPath)} ${q(bin)} hook ${runtime} --fail ${failMode} --deadline ${deadlineMs} --socket ${q(socket)}`;
}

export interface Plan {
  file: string;
  before: string | null;
  after: string;
  changed: boolean;
}

// ── Claude Code (settings.json) ─────────────────────────────────────────

export function claudeSettingsFile(scope: 'project' | 'user', dir?: string): string {
  if (scope === 'user') return path.join(process.env.CLAUDE_CONFIG_DIR ?? path.join(os.homedir(), '.claude'), 'settings.json');
  if (!dir) throw new Error('--dir is required for the project scope');
  // settings.local.json is the developer's own, not committed with the repo.
  return path.join(path.resolve(dir), '.claude', 'settings.local.json');
}

function isOurs(hook: any): boolean {
  return typeof hook?.command === 'string' && hook.command.includes(MARK) && hook.command.includes(' hook ');
}

/**
 * A matcher entry without the command hooks this tool installed: hooks
 * the developer added to the same entry stay, and only an entry left with
 * no hook at all is dropped.
 */
function withoutOurs(entry: any): any | undefined {
  if (!Array.isArray(entry?.hooks) || !entry.hooks.some(isOurs)) return entry;
  const hooks = entry.hooks.filter((h: any) => !isOurs(h));
  return hooks.length ? { ...entry, hooks } : undefined;
}

export function planClaude(file: string, failMode: FailMode, install: boolean): Plan {
  const before = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
  const settings = before ? JSON.parse(before) : {};
  if (typeof settings !== 'object' || Array.isArray(settings)) throw new Error(`${file} is not a JSON object`);
  settings.hooks ??= {};
  for (const event of CLAUDE_EVENTS) {
    const list: any[] = Array.isArray(settings.hooks[event]) ? settings.hooks[event] : [];
    const others = list.map(withoutOurs).filter((e) => e !== undefined);
    if (install) {
      others.push({
        matcher: event === 'PreToolUse' || event.startsWith('PostToolUse') ? '*' : undefined,
        // PreToolUse may wait for an approval: 600 s native timeout, the
        // hook answers within 590 s so the runtime always gets a decision.
        hooks: [{ type: 'command', command: hookCommand('claude-code', failMode, event === 'PreToolUse' ? 590000 : 10000), timeout: event === 'PreToolUse' ? 600 : 15 }],
      });
    }
    if (others.length) settings.hooks[event] = others;
    else delete settings.hooks[event];
  }
  if (Object.keys(settings.hooks).length === 0) delete settings.hooks;
  const after = JSON.stringify(settings, null, 2) + '\n';
  return { file, before, after, changed: after !== (before ?? '') && !(before === null && !install) };
}

export function apply(plan: Plan): string | null {
  if (!plan.changed) return null;
  let backup: string | null = null;
  if (plan.before !== null) {
    backup = `${plan.file}.agenomic-backup-${Date.now()}`;
    fs.writeFileSync(backup, plan.before, { mode: 0o600 });
  }
  fs.mkdirSync(path.dirname(plan.file), { recursive: true });
  const tmp = `${plan.file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, plan.after, { mode: 0o600 });
  fs.renameSync(tmp, plan.file);
  return backup;
}

// ── Codex (config.toml) ─────────────────────────────────────────────────

export function codexConfigFile(codexHome?: string): string {
  return path.join(codexHome ?? process.env.CODEX_HOME ?? path.join(os.homedir(), '.codex'), 'config.toml');
}

function stripBlock(text: string): string {
  const start = text.indexOf(BLOCK_START);
  if (start < 0) return text;
  const end = text.indexOf(BLOCK_END, start);
  if (end < 0) throw new Error('the agenomic-connector block in config.toml is not terminated; fix it by hand');
  return (text.slice(0, start).replace(/\n+$/, '\n') + text.slice(end + BLOCK_END.length).replace(/^\n+/, '')).replace(/^\n+$/, '');
}

const tomlString = (s: string) => JSON.stringify(s);

export function codexBlock(failMode: FailMode, timeoutSec: number, trust: Record<string, string> = {}, socket = paths.socket()): string {
  const lines = [BLOCK_START];
  for (const event of CODEX_EVENTS) {
    const pre = event === 'PreToolUse';
    const command = hookCommand('codex', failMode, pre ? Math.max(1000, (timeoutSec - 10) * 1000) : 10000, socket);
    lines.push(`[[hooks.${event}]]`);
    if (pre || event === 'PostToolUse') lines.push('matcher = "*"');
    lines.push(`[[hooks.${event}.hooks]]`, 'type = "command"', `command = ${tomlString(command)}`, `timeout = ${pre ? timeoutSec : 30}`);
  }
  for (const [key, hash] of Object.entries(trust)) {
    lines.push(`[hooks.state.${tomlString(key)}]`, `trusted_hash = ${tomlString(hash)}`);
  }
  lines.push(BLOCK_END, '');
  return lines.join('\n');
}

export function planCodex(file: string, failMode: FailMode, install: boolean, trust: Record<string, string> = {}, timeoutSec = 600, socket = paths.socket()): Plan {
  const before = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
  if (before && /^\s*\[hooks\]\s*$/m.test(stripBlock(before))) {
    // A `[hooks]` table elsewhere would be redefined by our array tables.
    throw new Error(`${file} already defines a [hooks] table; add the agenomic hooks by hand next to it`);
  }
  let after = before ? stripBlock(before) : '';
  if (install) after = (after && !after.endsWith('\n') ? after + '\n' : after) + (after ? '\n' : '') + codexBlock(failMode, timeoutSec, trust, socket);
  return { file, before, after, changed: after !== (before ?? '') };
}

/** Asks Codex for the hooks it sees and their hashes (`hooks/list`). */
export async function codexListHooks(exe: string, codexHome: string, cwd: string): Promise<any[]> {
  const command = exe.endsWith('.js') ? process.execPath : exe;
  const argv = exe.endsWith('.js') ? [exe, 'app-server'] : ['app-server'];
  const child = spawn(command, argv, { cwd, env: { ...process.env, CODEX_HOME: codexHome }, stdio: ['pipe', 'pipe', 'ignore'] });
  // A missing or non-executable binary emits 'error' (never 'exit'):
  // every call fails at once instead of crashing the process.
  let failure: Error | undefined;
  const waiting = new Set<(e: Error) => void>();
  child.on('error', (e) => {
    failure = new Error(`codex could not be started: ${e.message}`);
    for (const fail of waiting) fail(failure);
  });
  const rl = readline.createInterface({ input: child.stdout! });
  const replies = new Map<number, (v: any) => void>();
  rl.on('line', (l) => {
    try {
      const m = JSON.parse(l);
      if (m.id !== undefined && replies.has(m.id)) replies.get(m.id)!(m);
    } catch {
      /* ignore */
    }
  });
  const call = (id: number, method: string, params: unknown) =>
    new Promise<any>((resolve, reject) => {
      if (failure) return reject(failure);
      const settle = () => {
        clearTimeout(t);
        waiting.delete(fail);
        replies.delete(id);
      };
      const fail = (e: Error) => {
        settle();
        reject(e);
      };
      const t = setTimeout(() => fail(new Error(`${method} timed out`)), 20000);
      waiting.add(fail);
      replies.set(id, (m) => {
        settle();
        m.error ? reject(new Error(m.error.message)) : resolve(m.result);
      });
      child.stdin!.write(JSON.stringify({ id, method, params }) + '\n');
    });
  try {
    await call(1, 'initialize', { clientInfo: { name: 'agenomic-connector', version: '0.1.0' } });
    child.stdin!.write(JSON.stringify({ method: 'initialized' }) + '\n');
    const res = await call(2, 'hooks/list', { cwds: [cwd] });
    return res?.data?.[0]?.hooks ?? [];
  } finally {
    child.kill();
  }
}

/**
 * Install the Codex hooks and record the user's trust for exactly those
 * entries (Codex does not run an untrusted hook). Trust is recorded only
 * for commands this tool wrote, matched on the command string.
 */
export async function installCodex(file: string, failMode: FailMode, exe: string, cwd: string, dryRun: boolean, timeoutSec = 600, socket = paths.socket()): Promise<{ plan: Plan; backup: string | null; trusted: number }> {
  const first = planCodex(file, failMode, true, {}, timeoutSec, socket);
  if (dryRun) return { plan: first, backup: null, trusted: 0 };
  const backup = apply(first);
  const hooks = await codexListHooks(exe, path.dirname(file), cwd);
  const trust: Record<string, string> = {};
  for (const h of hooks) {
    if (h.handlerType === 'command' && typeof h.command === 'string' && h.command.includes(MARK) && h.command.includes(' hook codex ') && h.sourcePath === file) trust[h.key] = h.currentHash;
  }
  const second = planCodex(file, failMode, true, trust, timeoutSec, socket);
  apply(second);
  return { plan: second, backup, trusted: Object.keys(trust).length };
}
