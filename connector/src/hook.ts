import net from 'node:net';
import { localFailMode, paths } from './config.ts';

/** Largest hook payload the hook reads; a larger one is not forwarded. */
const MAX_INPUT = 1024 * 1024;

/**
 * Entry point of the command hooks Claude Code and Codex run. The hook is a
 * thin client of the local connector daemon: it holds no credential, and
 * it answers within a deadline below the native hook timeout. If the daemon
 * cannot answer, a fail-closed hook refuses the tool call explicitly with
 * the structured decision both runtimes document; a fail-open hook lets the
 * native flow continue. Neither treats a transport error as a decision.
 * The hooks of the developer's own sessions use `local`: the fail mode
 * follows the connector's current local-sessions mode (enforce fails
 * closed), read when it is needed rather than fixed at install time.
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
    const reply = await ask({ op: 'hook', runtime, input }, deadlineMs);
    if (reply?.output) process.stdout.write(JSON.stringify(reply.output));
    return 0;
  } catch (error) {
    return fallback(runtime, event, failMode, (error as Error).message);
  }
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

/** The event name of a payload that could not be read whole, if its start names it. */
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
