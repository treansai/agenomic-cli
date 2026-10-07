import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { RunnerApi } from './api.ts';
import { defaultConfig, loadConfig, paths, saveConfig, saveCredentials, validateConfig, type ConnectorConfig, type Mode } from './config.ts';
import { codexExecutable } from './codex.ts';
import { Daemon, sandboxAvailable } from './daemon.ts';
import { runHook } from './hook.ts';
import { apply, claudeSettingsFile, codexConfigFile, installCodex, planClaude, planCodex } from './hooks-install.ts';
import { loadProbes } from './capabilities.ts';
import { runProbe } from './probe.ts';

const USAGE = `agenomic-connector — connect Claude Code and Codex sessions to Agenomic

  enroll --token <agmcen_…> --endpoint <url> [--name <name>] [--kind local_machine|runner]
  workspace add --id <id> --path <dir> [--name <n>] [--repo <r>] [--branch <b>]
  workspace list | workspace remove --id <id>
  local-sessions --mode observe|shadow|enforce [--policy-ref <id@version>]... [--capture conversation,commands,diffs,outputs]
  hooks install|uninstall --runtime claude-code|codex [--scope project|user] [--dir <repo>] [--dry-run]
  run                       start the daemon (foreground)
  doctor [--probe]          check the runtimes; --probe validates capabilities with local scripted models
  status                    show enrollment, workspaces and validated capabilities

Nothing is scanned: only declared workspaces are reported, and only after
the hooks are installed in the scope you choose. Uninstall removes exactly
what install added.`;

function flags(args: string[]): { pos: string[]; f: Record<string, string[]> } {
  const pos: string[] = [];
  const f: Record<string, string[]> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = args[i + 1];
      if (next === undefined || next.startsWith('--')) (f[key] ??= []).push('true');
      else {
        (f[key] ??= []).push(next);
        i++;
      }
    } else pos.push(a);
  }
  return { pos, f };
}

const one = (f: Record<string, string[]>, k: string): string | undefined => f[k]?.[f[k]!.length - 1];
const out = (s: string) => process.stdout.write(s + '\n');

/**
 * Runs one `agenomic-connector` command and returns its exit code.
 *
 * @example
 * process.exitCode = await main(['workspace', 'add', '--id', 'app', '--path', '/src/app']);
 */
export async function main(argv: string[]): Promise<number> {
  const { pos, f } = flags(argv);
  const cmd = pos[0];
  switch (cmd) {
    case 'hook': {
      const runtime = pos[1] === 'codex' ? 'codex' : 'claude-code';
      if (one(f, 'socket')) process.env.AGENOMIC_CONNECTOR_SOCKET = one(f, 'socket');
      const socket = one(f, 'socket');
      if (socket) {
        // The hook only needs the socket; keep paths.socket() pointing at it.
        const home = path.dirname(path.dirname(socket));
        process.env.AGENOMIC_CONNECTOR_HOME = home;
      }
      const fail = one(f, 'fail');
      return runHook(runtime, fail === 'closed' || fail === 'open' ? fail : 'local', Number(one(f, 'deadline') ?? 25000));
    }
    case 'enroll': {
      const token = one(f, 'token') ?? process.env.AGENOMIC_ENROLLMENT_TOKEN;
      const endpoint = one(f, 'endpoint');
      if (!token || !endpoint) throw new Error('--token and --endpoint are required');
      const name = one(f, 'name') ?? os.hostname();
      const kind = (one(f, 'kind') as ConnectorConfig['kind']) ?? 'local_machine';
      const cfg = fs.existsSync(paths.config()) ? loadConfig() : defaultConfig(endpoint, name);
      cfg.endpoint = endpoint;
      cfg.name = name;
      cfg.kind = kind;
      // The one time token only goes to an endpoint the saved configuration
      // would accept (https, or plain http on loopback).
      validateConfig(cfg);
      const r = await RunnerApi.enroll(endpoint, { enrollment_token: token, name, kind, os: process.platform, arch: process.arch, connector_version: '0.1.0' });
      cfg.runner_id = r.runner.id;
      saveConfig(cfg);
      saveCredentials(r.credentials);
      out(`enrolled runner ${r.runner.id} (${name}); credentials stored in ${paths.credentials()} (mode 600)`);
      out('next: declare a workspace (workspace add), then start the daemon (run)');
      return 0;
    }
    case 'workspace': {
      const cfg = loadConfig();
      if (pos[1] === 'add') {
        const id = one(f, 'id');
        const dir = one(f, 'path');
        if (!id || !dir) throw new Error('--id and --path are required');
        const abs = fs.realpathSync(path.resolve(dir));
        if (!fs.existsSync(path.join(abs, '.git'))) throw new Error(`${abs} is not a git checkout`);
        cfg.workspaces = cfg.workspaces.filter((w) => w.id !== id);
        cfg.workspaces.push({ id, name: one(f, 'name') ?? path.basename(abs), path: abs, repo: one(f, 'repo'), default_branch: one(f, 'branch') });
        saveConfig(cfg);
        out(`workspace ${id} -> ${abs}`);
      } else if (pos[1] === 'remove') {
        cfg.workspaces = cfg.workspaces.filter((w) => w.id !== one(f, 'id'));
        saveConfig(cfg);
      } else {
        for (const w of cfg.workspaces) out(`${w.id}\t${w.path}\t${w.repo ?? ''}`);
      }
      return 0;
    }
    case 'local-sessions': {
      const cfg = loadConfig();
      const mode = one(f, 'mode') as Mode | undefined;
      if (mode && !['observe', 'shadow', 'enforce'].includes(mode)) throw new Error('--mode must be observe, shadow or enforce');
      if (mode) cfg.local_sessions.mode = mode;
      if (f['policy-ref']) cfg.local_sessions.policy_refs = f['policy-ref'];
      if (one(f, 'capture') !== undefined) {
        const set = new Set(one(f, 'capture')!.split(',').map((s) => s.trim()));
        cfg.local_sessions.capture = { conversation: set.has('conversation'), commands: set.has('commands'), diffs: set.has('diffs'), outputs: set.has('outputs') };
      }
      saveConfig(cfg);
      out(JSON.stringify(cfg.local_sessions));
      // Installed hooks read the mode when they need it; the daemon reads
      // its configuration when it starts.
      if (mode) out('installed hooks follow this mode now; restart the daemon (run) to apply it to new sessions');
      return 0;
    }
    case 'hooks': {
      const install = pos[1] === 'install';
      if (!install && pos[1] !== 'uninstall') throw new Error('hooks install|uninstall');
      const runtime = one(f, 'runtime');
      const dry = one(f, 'dry-run') === 'true';
      const cfg = fs.existsSync(paths.config()) ? loadConfig() : undefined;
      // Not fixed at install time: the hooks follow `local-sessions --mode`.
      const failMode = 'local' as const;
      if (runtime === 'claude-code') {
        const scope = (one(f, 'scope') ?? 'project') as 'project' | 'user';
        const file = claudeSettingsFile(scope, one(f, 'dir'));
        const plan = planClaude(file, failMode, install);
        if (dry || !plan.changed) {
          out(plan.changed ? `would write ${file}:\n${plan.after}` : `${file}: nothing to change`);
          return 0;
        }
        const backup = apply(plan);
        out(`${install ? 'installed' : 'removed'} Claude Code hooks in ${file}${backup ? ` (backup: ${backup})` : ''}`);
        if (install) out('sessions already open are not connected: restart them to load the hooks');
        return 0;
      }
      if (runtime === 'codex') {
        const file = codexConfigFile(one(f, 'codex-home'));
        if (!install) {
          const plan = planCodex(file, failMode, false);
          if (dry || !plan.changed) return out(plan.changed ? `would write ${file}` : `${file}: nothing to change`), 0;
          const backup = apply(plan);
          out(`removed Codex hooks from ${file}${backup ? ` (backup: ${backup})` : ''}`);
          return 0;
        }
        const exe = codexExecutable(cfg?.runtimes.codex ?? { enabled: true, env_passthrough: [], extra_env: {}, allowed_domains: [] });
        const r = await installCodex(file, failMode, exe, one(f, 'dir') ?? process.cwd(), dry);
        out(dry ? `would write ${file}:\n${r.plan.after}` : `installed Codex hooks in ${file}; trusted ${r.trusted} hook entries${r.backup ? ` (backup: ${r.backup})` : ''}`);
        return 0;
      }
      throw new Error('--runtime claude-code|codex');
    }
    case 'run': {
      const cfg = loadConfig();
      const daemon = new Daemon(cfg);
      await daemon.start();
      await new Promise<void>((resolve) => {
        const stop = () => void daemon.stop().then(resolve);
        process.once('SIGINT', stop);
        process.once('SIGTERM', stop);
      });
      return 0;
    }
    case 'doctor': {
      const sb = sandboxAvailable();
      out(`sandbox: ${sb.ok ? 'available' : 'unavailable'} (${sb.detail})`);
      if (one(f, 'probe') === 'true') {
        // The runtimes this machine runs: its configuration once enrolled.
        const cfg = fs.existsSync(paths.config()) ? loadConfig() : defaultConfig('http://127.0.0.1:9', os.hostname());
        if (!fs.existsSync(paths.config())) out('not enrolled: probing the default runtime configuration');
        for (const runtime of ['claude_code', 'codex'] as const) {
          if (!cfg.runtimes[runtime].enabled) out(`${runtime}: disabled in ${paths.config()}, not probed`);
        }
        for (const r of await runProbe(cfg)) {
          out(`${r.runtime}/${r.surface} ${r.version}:`);
          for (const [k, v] of Object.entries(r.results)) out(`  ${v!.ok ? 'ok  ' : 'FAIL'} ${k}: ${v!.detail}`);
        }
      }
      return 0;
    }
    case 'status': {
      const cfg = loadConfig();
      out(`endpoint: ${cfg.endpoint}\nrunner: ${cfg.runner_id ?? '(not enrolled)'}\nlocal sessions: ${cfg.local_sessions.mode}`);
      for (const w of cfg.workspaces) out(`workspace ${w.id}: ${w.path}`);
      for (const p of loadProbes()) out(`validated ${p.runtime}/${p.surface} ${p.version} at ${p.at}`);
      return 0;
    }
    default:
      out(USAGE);
      return cmd ? 2 : 0;
  }
}
