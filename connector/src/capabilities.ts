import fs from 'node:fs';
import path from 'node:path';
import { paths } from './config.ts';
import { readJson, writeSecretFile } from './util.ts';

export type CapState = 'supported_tested' | 'partial' | 'experimental' | 'unsupported' | 'unknown';
export type CapName =
  | 'observe' | 'converse' | 'remote_approval' | 'pre_tool_control' | 'interrupt_turn'
  | 'stop_process' | 'resume' | 'file_diffs' | 'user_questions' | 'subagent_tracking';

export interface CapEntry {
  announced: CapState;
  validated: CapState;
  detail?: string;
}

type Announced = Record<CapName, [CapState, string]>;

/**
 * What each surface of each runtime can do through this connector, as
 * implemented and tested against the pinned versions. `validated` comes
 * from `agenomic-connector doctor --probe` on this machine; without a
 * probe result for the installed version it is `unknown`, and the cockpit
 * never enables an operation on `unknown`.
 */
export const ANNOUNCED: Record<string, Announced> = {
  'claude_code:sdk': {
    observe: ['supported_tested', 'Agent SDK message stream and hook callbacks'],
    converse: ['supported_tested', 'streaming input to the SDK query'],
    remote_approval: ['supported_tested', 'canUseTool waits for the Agenomic approval'],
    pre_tool_control: ['supported_tested', 'PreToolUse callback + canUseTool; sandbox bounds Bash'],
    interrupt_turn: ['supported_tested', 'Query.interrupt()'],
    stop_process: ['supported_tested', 'process exit verified before reporting'],
    resume: ['partial', 'resume by explicit native session id; same worktree'],
    file_diffs: ['supported_tested', 'git diff of the session worktree against its base revision'],
    user_questions: ['supported_tested', 'AskUserQuestion answered from Agenomic'],
    subagent_tracking: ['partial', 'SubagentStart/SubagentStop hooks; per-subagent budgets not enforced by the runtime'],
  },
  'claude_code:cli_hooks': {
    observe: ['supported_tested', 'command hooks of a developer CLI session'],
    converse: ['unsupported', 'a terminal session cannot receive messages from Agenomic'],
    remote_approval: ['partial', 'the PreToolUse hook waits for an approval up to its timeout'],
    pre_tool_control: ['partial', 'cooperative: same-user processes and disabled hooks bypass it'],
    interrupt_turn: ['unsupported', 'no supported API to interrupt a terminal session'],
    stop_process: ['unsupported', 'the connector does not own the process'],
    resume: ['unsupported', 'resume happens in the terminal'],
    file_diffs: ['unsupported', 'the developer checkout is not snapshotted'],
    user_questions: ['unsupported', 'questions are answered in the terminal'],
    subagent_tracking: ['partial', 'SubagentStart/SubagentStop hooks'],
  },
  'codex:cli_hooks': {
    observe: ['partial', 'command hooks of a developer Codex CLI session: prompts, shell calls, turn and session ends; no assistant messages, no apply_patch'],
    converse: ['unsupported', 'a terminal session cannot receive messages from Agenomic'],
    remote_approval: ['partial', 'the PreToolUse hook holds a shell call until its approval, up to the hook timeout'],
    pre_tool_control: ['partial', 'cooperative PreToolUse hook on shell calls only (apply_patch, write_stdin, MCP and web search are not checked); same-user processes and disabled hooks bypass it'],
    interrupt_turn: ['unsupported', 'no supported API to interrupt a terminal session'],
    stop_process: ['unsupported', 'the connector does not own the process'],
    resume: ['unsupported', 'resume happens in the terminal'],
    file_diffs: ['unsupported', 'the developer checkout is not snapshotted'],
    user_questions: ['unsupported', 'questions are answered in the terminal'],
    subagent_tracking: ['unsupported', 'Codex hooks report no subagent lifecycle'],
  },
  'codex:app_server': {
    observe: ['supported_tested', 'App Server notifications'],
    converse: ['supported_tested', 'turn/start and turn/steer with expectedTurnId'],
    remote_approval: ['supported_tested', 'commandExecution and fileChange approval requests'],
    pre_tool_control: ['supported_tested', 'trusted PreToolUse command hook on shell calls + approval requests'],
    interrupt_turn: ['supported_tested', 'turn/interrupt'],
    stop_process: ['supported_tested', 'process exit verified before reporting'],
    resume: ['partial', 'thread/resume by explicit thread id'],
    file_diffs: ['supported_tested', 'git diff of the session worktree against its base revision'],
    user_questions: ['experimental', 'item/tool/requestUserInput'],
    subagent_tracking: ['experimental', 'collab agent items'],
  },
};

const ORDER: CapName[] = ['observe', 'converse', 'remote_approval', 'pre_tool_control', 'interrupt_turn', 'stop_process', 'resume', 'file_diffs', 'user_questions', 'subagent_tracking'];

export interface ProbeResult {
  runtime: string;
  surface: string;
  version: string;
  at: string;
  results: Partial<Record<CapName, { ok: boolean; detail: string }>>;
}

function probeFile(): string {
  return path.join(paths.state(), 'validation.json');
}

/**
 * The probe results `doctor --probe` saved on this machine.
 *
 * @example
 * for (const p of loadProbes()) console.log(`${p.runtime}/${p.surface} ${p.version} validated at ${p.at}`);
 */
export function loadProbes(): ProbeResult[] {
  return readJson<ProbeResult[]>(probeFile()) ?? [];
}

/**
 * Records a probe result, replacing the previous one of the same runtime and surface.
 *
 * @example
 * saveProbe({ runtime: 'codex', surface: 'cli_hooks', version: '0.160.1', at: new Date().toISOString(), results: { observe: { ok: true, detail: 'hooks reported' } } });
 */
export function saveProbe(p: ProbeResult): void {
  const all = loadProbes().filter((x) => !(x.runtime === p.runtime && x.surface === p.surface));
  all.push(p);
  fs.mkdirSync(paths.state(), { recursive: true, mode: 0o700 });
  writeSecretFile(probeFile(), JSON.stringify(all, null, 2));
}

/**
 * The capability manifest of a runtime surface: announced states, validated by a probe of this exact version.
 *
 * @example
 * const caps = manifest('codex', 'app_server', '0.160.1');
 * caps.pre_tool_control.validated; // 'unknown' until `doctor --probe` validated it
 */
export function manifest(runtime: string, surface: string, version: string | null): Record<string, CapEntry> {
  const announced = ANNOUNCED[`${runtime}:${surface}`];
  if (!announced) return {};
  // A binary whose version is unknown is never matched with a probe.
  const probe = version && version !== 'unknown' ? loadProbes().find((p) => p.runtime === runtime && p.surface === surface && p.version === version) : undefined;
  const out: Record<string, CapEntry> = {};
  for (const name of ORDER) {
    const [state, detail] = announced[name];
    let validated: CapState = 'unknown';
    if (state === 'unsupported') validated = 'unsupported';
    else if (probe?.results[name]) validated = probe.results[name]!.ok ? state : 'unsupported';
    out[name] = { announced: state, validated, detail: probe?.results[name]?.detail ?? detail };
  }
  return out;
}
