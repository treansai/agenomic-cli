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
 * it runs (see `scriptOf`). Read from `/proc` (Linux); undefined
 * elsewhere, when the command line is not one whose script is known, or
 * when the executable or script was replaced or changed since the process
 * started (a deleted binary, or a file changed after the process start
 * time of `/proc/<pid>/stat`, as an npm update of a running Node CLI
 * does), so that the daemon never validates a session with another
 * binary's version.
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
    let file = exe;
    if (/^(node|nodejs|bun)$/.test(name)) {
      const script = scriptOf(name === 'bun' ? 'bun' : 'node', argv.slice(1));
      if (!script) return undefined;
      try {
        file = path.resolve(fs.readlinkSync(path.join(proc, String(pid), 'cwd')), script);
      } catch {
        if (!path.isAbsolute(script)) return undefined;
        file = script;
      }
    }
    return changedSince(file, startedAt(pid, proc)) ? undefined : file;
  }
  return undefined;
}

/** Node options whose value is the next argument (`--opt value`); `--opt=value` needs no entry. */
const NODE_VALUE_OPTIONS = new Set([
  '-r', '--require', '--import', '--loader', '--experimental-loader', '-C', '--conditions',
  '--env-file', '--env-file-if-exists', '--input-type', '--inspect-port', '--debug-port', '--title',
  '--icu-data-dir', '--openssl-config', '--redirect-warnings', '--disable-warning', '--stack-trace-limit',
  '--diagnostic-dir', '--report-dir', '--report-directory', '--report-filename', '--report-signal',
  '--secure-heap', '--secure-heap-min', '--max-http-header-size', '--heapsnapshot-signal', '--cpu-prof-dir',
  '--cpu-prof-name', '--heap-prof-dir', '--heap-prof-name', '--watch-path', '--experimental-config-file',
]);
/** Node options that run code other than a script file: no script is named. */
const NODE_NO_SCRIPT = new Set(['-e', '--eval', '-p', '--print', '-i', '--interactive', '-c', '--check', '-v', '--version', '-h', '--help', '--test', '--run', '--prof-process']);
/** Bun options whose value is the next argument. */
const BUN_VALUE_OPTIONS = new Set(['-r', '--preload', '--require', '--import', '-c', '--config', '--cwd', '--env-file', '--tsconfig-override', '--define', '-d', '--loader', '-l', '--conditions', '--main-fields', '--extension-order', '--jsx-factory', '--jsx-fragment', '--jsx-import-source', '--jsx-runtime', '--port', '--origin', '--install', '--elide-lines', '--filter', '-F']);
/** Bun subcommands other than `run`: they run no script of the command line. */
const BUN_COMMANDS = new Set(['x', 'test', 'install', 'i', 'add', 'a', 'remove', 'rm', 'update', 'link', 'unlink', 'pm', 'build', 'init', 'create', 'c', 'upgrade', 'repl', 'exec', 'outdated', 'publish', 'patch', 'patch-commit', 'audit', 'info', 'why', 'completions', 'discord', 'help']);

/**
 * The script a `node` or `bun` command line runs: the first argument that
 * is neither an option nor the value of an option given as a separate
 * argument (`node -r dotenv/config cli.js`), after `bun run`. Undefined
 * when the command line runs no script file (`node -e …`, `bun x …`), or
 * names an option this reader does not know, since its value could be
 * taken for the script.
 *
 * @example
 * scriptOf('node', ['--require', 'x.js', 'cli.js', '--flag']); // 'cli.js'
 * scriptOf('bun', ['run', 'cli.js']); // 'cli.js'
 */
export function scriptOf(runtime: 'node' | 'bun', args: string[]): string | undefined {
  const values = runtime === 'node' ? NODE_VALUE_OPTIONS : BUN_VALUE_OPTIONS;
  let command = runtime === 'node';
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') return args[i + 1];
    if (a === '-') return undefined;
    if (a.startsWith('-')) {
      const option = a.split('=')[0];
      if (runtime === 'node' && NODE_NO_SCRIPT.has(option)) return undefined;
      if (a.includes('=')) continue;
      if (values.has(a)) {
        i++;
        continue;
      }
      // A flag known to take no value: anything else might take one.
      if (runtime === 'node' ? NODE_FLAG.test(a) : BUN_FLAG.test(a)) continue;
      return undefined;
    }
    if (!command) {
      command = true;
      if (a === 'run') continue;
      if (BUN_COMMANDS.has(a)) return undefined;
    }
    return a;
  }
  return undefined;
}

/** Node flags that take no value: the boolean `--[no-]…` and `--expose-…`/`--experimental-…`/`--trace-…` switches, and `--inspect[-brk|-wait]` without a port. */
const NODE_FLAG = /^--(no-[\w-]+|experimental-[\w-]+|harmony[\w-]*|trace-[\w-]+|expose[\w-]+|inspect(-brk|-wait)?|enable-source-maps|preserve-symlinks(-main)?|pending-deprecation|throw-deprecation|abort-on-uncaught-exception|frozen-intrinsics|use-openssl-ca|use-bundled-ca|use-system-ca|insecure-http-parser|zero-fill-buffers|cpu-prof|heap-prof|watch|watch-preserve-output|report-on-signal|report-on-fatalerror|report-uncaught-exception|report-compact|force-fips|enable-fips|prof)$/;
/** Bun flags that take no value. */
const BUN_FLAG = /^(--(watch|hot|no-clear-screen|smol|bun|silent|if-present|no-install|prefer-offline|prefer-latest|no-macros|no-env-file|no-deprecation|throw-deprecation|expose-gc|inspect(-brk|-wait)?)|-b)$/;

/**
 * Milliseconds since the epoch at which process `pid` started: field 22 of
 * `/proc/<pid>/stat` (clock ticks since boot, `USER_HZ` = 100 on Linux)
 * plus the boot time `btime` of `/proc/stat`. The boot time is truncated
 * to the second, so the result is at most a second early: a file changed
 * just before the process started is taken as changed after it, which
 * only makes the version unknown. Undefined if either cannot be read.
 */
function startedAt(pid: number, proc: string): number | undefined {
  try {
    const stat = fs.readFileSync(path.join(proc, String(pid), 'stat'), 'utf8');
    const ticks = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19]);
    const boot = Number(/^btime (\d+)$/m.exec(fs.readFileSync(path.join(proc, 'stat'), 'utf8'))?.[1]);
    if (!Number.isFinite(ticks) || !Number.isFinite(boot)) return undefined;
    return boot * 1000 + ticks * 10;
  } catch {
    return undefined;
  }
}

/** Whether `file` was modified or replaced after `since` (or either is unknown). */
function changedSince(file: string, since: number | undefined): boolean {
  if (since === undefined) return true;
  try {
    const st = fs.statSync(file);
    return Math.max(st.mtimeMs, st.ctimeMs) > since;
  } catch {
    return true;
  }
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
