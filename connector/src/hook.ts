import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { localFailMode, paths } from './config.ts';
import { clean } from './redact.ts';

/** Largest hook payload the hook reads; a larger one is not forwarded. */
const MAX_INPUT = 1024 * 1024;

/**
 * Entry point of the command hooks Claude Code and Codex run. The hook is a
 * thin client of the local connector daemon: it holds no credential, and
 * it answers within a deadline below the native hook timeout. If the daemon
 * cannot answer, a fail-closed hook refuses the tool call explicitly with
 * the structured decision both runtimes document; a fail-open hook lets the
 * native flow continue. Neither treats a transport error, an error reply
 * or a malformed reply as a decision.
 * The hooks of the developer's own sessions use `local`: the fail mode
 * follows the connector's current local-sessions mode (enforce fails
 * closed), read when it is needed rather than fixed at install time.
 *
 * @example
 * process.exitCode = await runHook('claude-code', 'local', 25000); // reads the hook payload on stdin
 */
export async function runHook(runtime: 'claude-code' | 'codex', failMode: 'closed' | 'open' | 'local', deadlineMs: number): Promise<number> {
  let raw: string;
  try {
    raw = await readStdin(MAX_INPUT);
  } catch (error) {
    // An oversized or unreadable payload is a failure like any other: in
    // fail-closed mode it gets the structured deny, never a crash exit
    // (which both runtimes treat as a non-blocking hook error).
    const e = error as InputError;
    return fallback(runtime, eventOf(e.head ?? ''), failMode, e.message);
  }
  let input: any;
  try {
    input = JSON.parse(raw);
  } catch {
    return fallback(runtime, undefined, failMode, 'invalid hook input');
  }
  const event: string | undefined = input?.hook_event_name;
  try {
    const invoker = invokingExecutable();
    const output = hookOutput(await ask({ op: 'hook', runtime, input, ...(invoker ? { invoker } : {}) }, deadlineMs));
    if (output) process.stdout.write(JSON.stringify(output));
    return 0;
  } catch (error) {
    return fallback(runtime, event, failMode, clean((error as Error).message, 300));
  }
}

/**
 * The hook output carried by a daemon reply: `{}` (no decision, the
 * native flow continues) or `{"output": {...}}`. A reply naming an error
 * (the daemon could not handle the call, for example the gateway was
 * unreachable when a new session was registered) and a malformed reply
 * are failures, routed through the fail mode like a transport error.
 *
 * @example
 * hookOutput({ output: { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'Agenomic: policy' } } });
 */
export function hookOutput(reply: unknown): Record<string, unknown> | undefined {
  if (!reply || typeof reply !== 'object' || Array.isArray(reply)) throw new Error('malformed connector reply');
  const r = reply as { output?: unknown; error?: unknown };
  if (r.error !== undefined) throw new Error(`connector error: ${typeof r.error === 'string' ? r.error : JSON.stringify(r.error)}`);
  if (r.output === undefined) return undefined;
  if (!r.output || typeof r.output !== 'object' || Array.isArray(r.output)) throw new Error('malformed connector reply');
  return r.output as Record<string, unknown>;
}

function fallback(_runtime: string, event: string | undefined, failMode: 'closed' | 'open' | 'local', why: string): number {
  if (event !== 'PreToolUse' && event !== undefined) return 0;
  if ((failMode === 'local' ? localFailMode() : failMode) === 'closed') {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: `Agenomic connector unavailable (${why}); this session is in enforce mode, so the action is refused.`,
      },
    }));
  }
  return 0;
}

/** Processes a runtime runs its command hooks through, looked past to reach the runtime. */
const WRAPPERS = new Set(['sh', 'bash', 'dash', 'zsh', 'ksh', 'mksh', 'fish', 'busybox', 'env', 'nice', 'nohup', 'timeout']);

/**
 * The executable of the runtime process that ran this hook: the first
 * ancestor that is not a shell, and for a Node or Bun process the script
 * it runs. Read from `/proc` (Linux); undefined elsewhere, or when the
 * executable was replaced since the process started, so that the daemon
 * never validates a session with another binary's version.
 *
 * @example
 * invokingExecutable(); // '/usr/lib/node_modules/@openai/codex/vendor/x86_64-unknown-linux-musl/codex/codex', or undefined
 */
export function invokingExecutable(pid = process.ppid, proc = '/proc'): string | undefined {
  for (let depth = 0; depth < 8 && pid > 1; depth++) {
    let exe: string;
    let argv: string[];
    try {
      exe = fs.readlinkSync(path.join(proc, String(pid), 'exe'));
      argv = fs.readFileSync(path.join(proc, String(pid), 'cmdline'), 'utf8').split('\0').filter(Boolean);
    } catch {
      return undefined;
    }
    if (exe.endsWith(' (deleted)')) return undefined;
    const name = path.basename(exe);
    if (WRAPPERS.has(name)) {
      try {
        const stat = fs.readFileSync(path.join(proc, String(pid), 'stat'), 'utf8');
        pid = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]);
      } catch {
        return undefined;
      }
      continue;
    }
    if (/^(node|nodejs|bun)$/.test(name)) {
      const script = argv.slice(1).find((a) => !a.startsWith('-'));
      if (!script) return undefined;
      try {
        return path.resolve(fs.readlinkSync(path.join(proc, String(pid), 'cwd')), script);
      } catch {
        return path.isAbsolute(script) ? script : undefined;
      }
    }
    return exe;
  }
  return undefined;
}

/**
 * The event name of a payload that could not be read whole, if its start names it.
 *
 * @example
 * eventOf('{"session_id":"s","hook_event_name":"PreToolUse","tool_input":{"content":"…'); // 'PreToolUse'
 */
export function eventOf(head: string): string | undefined {
  return /"hook_event_name"\s*:\s*"([A-Za-z]+)"/.exec(head)?.[1];
}

class InputError extends Error {
  readonly head: string;
  constructor(message: string, head: string) {
    super(message);
    this.head = head;
  }
}

function readStdin(max: number): Promise<string> {
  const stdin = process.stdin;
  return new Promise((resolve, reject) => {
    let data = '';
    let failed = false;
    const fail = (why: string) => {
      if (failed) return;
      failed = true;
      // Stop buffering: the rest of the payload is not needed to refuse.
      stdin.removeAllListeners('data');
      stdin.destroy();
      reject(new InputError(why, data.slice(0, 64 * 1024)));
    };
    stdin.setEncoding('utf8');
    stdin.on('data', (c: string) => {
      data += c;
      if (data.length > max) fail('hook input too large');
    });
    stdin.on('end', () => {
      if (!failed) resolve(data);
    });
    stdin.on('error', (e: Error) => fail(`hook input unreadable: ${e.message}`));
  });
}

/**
 * Sends one request to the daemon's local socket and resolves with its reply, rejecting past `deadlineMs`.
 *
 * @example
 * const reply = await ask({ op: 'hook', runtime: 'codex', input }, 25000);
 */
export function ask(request: unknown, deadlineMs: number, socketPath = paths.socket()): Promise<any> {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(socketPath);
    let buf = '';
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error('timed out'));
    }, deadlineMs);
    sock.on('connect', () => sock.write(JSON.stringify(request) + '\n'));
    sock.on('data', (d) => {
      buf += d;
      const nl = buf.indexOf('\n');
      if (nl >= 0) {
        clearTimeout(timer);
        sock.end();
        try {
          resolve(JSON.parse(buf.slice(0, nl)));
        } catch (e) {
          reject(e);
        }
      }
    });
    sock.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}
