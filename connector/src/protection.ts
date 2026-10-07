import type { Mode } from './config.ts';
import type { Runtime } from './session.ts';

/** The closed coding tool vocabulary of coding-action.schema.json. */
export const TOOL_IDS = [
  'coding.fs.read',
  'coding.fs.write',
  'coding.fs.delete',
  'coding.shell.exec',
  'coding.shell.interactive_input',
  'coding.git.read',
  'coding.git.commit',
  'coding.git.push',
  'coding.git.destructive',
  'coding.dependency.install',
  'coding.network.fetch',
  'coding.mcp.call',
  'coding.agent_config.modify',
  'coding.subagent.spawn',
  'coding.web.search',
  'coding.unknown',
] as const;

export type ToolId = (typeof TOOL_IDS)[number];
export type Surface = 'sdk' | 'app_server' | 'cli_hooks';

/**
 * What a session's decision point covers, reported in its state. Only
 * enforce gates calls: `protected` lists the tool ids every native route
 * of which passes a binding Agenomic pre-execution decision in enforce,
 * `not_covered` the others. In observe and shadow nothing is gated, so
 * `protected` is empty and every tool id is `not_covered`; what shadow
 * evaluates before a call runs (recorded as would_have_been) is described
 * in `notes`. `notes` describe the mechanisms behind the coverage and
 * `limitations` what is not covered; neither changes the badge, which
 * only reads `protected` together with the effective mode.
 */
export interface Protection {
  protected: ToolId[];
  not_covered: ToolId[];
  notes: string[];
  limitations: string[];
}

/** Tool ids whose only route in Codex is a shell call, which the PreToolUse hook decides. */
const CODEX_SHELL: ToolId[] = [
  'coding.shell.exec', 'coding.git.read', 'coding.git.commit', 'coding.git.push', 'coding.git.destructive',
  'coding.dependency.install', 'coding.network.fetch',
];

/** Codex edits: shell writes (PreToolUse) and apply_patch (fileChange approval request, enforce only). */
const CODEX_PATCH: ToolId[] = ['coding.fs.write', 'coding.fs.delete', 'coding.agent_config.modify'];

const SHADOW_NOTE = 'shadow mode: Agenomic records what it would have decided; the runtime\'s own permission flow decides';
const COOPERATIVE = [
  'hooks are cooperative: a disabled, removed or killed hook, or a process of the same user, bypasses them',
  'no Agenomic sandbox around a developer terminal session',
];

/**
 * The coverage of a decision point as reported in `mode`: `covered` is
 * protected in enforce only. In shadow the same tool ids are evaluated
 * before they run without being gated, which a note says.
 */
function split(mode: Mode, covered: ToolId[], notes: string[], limitations: string[]): Protection {
  const set = new Set(mode === 'enforce' ? covered : []);
  const evaluated = mode === 'shadow' && covered.length
    ? [`shadow evaluates ${covered.length === TOOL_IDS.length ? 'every tool call' : covered.join(', ')} before it runs, without gating it`]
    : [];
  return {
    protected: TOOL_IDS.filter((id) => set.has(id)),
    not_covered: TOOL_IDS.filter((id) => !set.has(id)),
    notes: [...notes, ...evaluated],
    limitations,
  };
}

export function protection(runtime: Runtime, surface: Surface, mode: Mode): Protection {
  if (mode === 'observe') {
    return split(mode, [], ['native protections remain active (sandbox, native permission rules)'], ['observe mode: Agenomic records, it adds no blocking']);
  }
  const shadow = mode === 'shadow' ? [SHADOW_NOTE] : [];
  if (runtime === 'claude_code' && surface === 'sdk') {
    return split(mode, [...TOOL_IDS], [
      'pre-tool decision on every native tool call (PreToolUse callback and canUseTool)',
      'Bash writes limited to the session worktree by the Claude Code sandbox',
      'network limited to the allowed domains by the sandbox proxy',
      'repository settings, hooks and MCP servers are not loaded',
      ...shadow,
    ], [
      'data sent to an allowed domain is not inspected (an allow list does not prevent exfiltration to it)',
      'effects of a script beyond its first command are not inspected one by one',
      'file checkpoints are not a rollback of shell side effects',
    ]);
  }
  if (runtime === 'claude_code') {
    // cli_hooks: the PreToolUse command hook matches every tool.
    return split(mode, [...TOOL_IDS], ['pre-tool decision on every native tool call from the PreToolUse command hook of this session', ...shadow], COOPERATIVE);
  }
  const notCheckedByHook = 'view_image, write_stdin (input to a running process), MCP, web search and subagent tool calls are not checked by the Codex PreToolUse hook';
  if (surface === 'app_server') {
    const enforce = mode === 'enforce';
    return split(mode, enforce ? [...CODEX_SHELL, ...CODEX_PATCH] : CODEX_SHELL, [
      'pre-tool decision on shell calls (trusted PreToolUse hook)',
      ...(enforce
        ? [
            'native approval requests for commands and patches answered by Agenomic, one request at a time',
            'approvals are never granted for the whole session (no acceptForSession)',
          ]
        : []),
      'workspace-write sandbox: writes limited to the worktree, network disabled',
      ...shadow,
    ], [
      notCheckedByHook,
      enforce
        ? 'apply_patch is covered by the fileChange approval request, not by PreToolUse'
        : 'shadow mode: apply_patch edits get no decision before they apply (Codex sends no approval requests); they are observed as file changes',
    ]);
  }
  // Codex cli_hooks: shell calls only, nothing answers apply_patch.
  return split(mode, CODEX_SHELL, ['pre-tool decision on shell calls from the PreToolUse command hook of this session', ...shadow], [
    ...COOPERATIVE,
    notCheckedByHook,
    'apply_patch edits get no decision before they apply',
  ]);
}

/**
 * The coverage reported for a blocked session: the requested mode could
 * not be established and the gateway refuses every call, so no tool id is
 * protected; `reason` says why.
 */
export function blockedProtection(p: Protection, reason: string): Protection {
  return { protected: [], not_covered: [...TOOL_IDS], notes: [...p.notes, `blocked: ${reason}`], limitations: p.limitations };
}
