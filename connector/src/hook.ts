import net from 'node:net';
import { paths } from './config.ts';

/**
 * Entry point of the command hooks Claude Code and Codex run. The hook is a
 * thin client of the local connector daemon: it holds no credential, and
 * it answers within a deadline below the native hook timeout. If the daemon
 * cannot answer, a fail-closed hook refuses the tool call explicitly with
 * the structured decision both runtimes document; a fail-open hook lets the
 * native flow continue. Neither treats a transport error as a decision.
 */
export async function runHook(runtime: 'claude-code' | 'codex', failMode: 'closed' | 'open', deadlineMs: number): Promise<number> {
  const raw = await readStdin(1024 * 1024);
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

function fallback(_runtime: string, event: string | undefined, failMode: 'closed' | 'open', why: string): number {
  if (failMode === 'closed' && (event === 'PreToolUse' || event === undefined)) {
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

function readStdin(max: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => {
      data += c;
      if (data.length > max) reject(new Error('hook input too large'));
    });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
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
