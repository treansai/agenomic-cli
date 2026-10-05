import http from 'node:http';

/**
 * Scripted model endpoints for validation and tests. They let the real
 * Claude Code and Codex runtimes run their real agent loops, tools,
 * hooks, approvals and sandboxes without a model provider: the "model"
 * plays a fixed list of tool calls embedded in the user message as
 * `AGN_SCRIPT:[{"tool": "...", "input": {...}}, ...]END`, one per model
 * call, then answers "done". They never call out to the network.
 */

export interface ScriptStep {
  tool: string;
  input: unknown;
  custom?: boolean;
}

const MARK = /AGN_SCRIPT:(\[.*\])END/s;

/** Raw text of a message content (string, or text / input_text blocks). */
function textOf(content: unknown): string {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.map((c: any) => (typeof c?.text === 'string' ? c.text : '')).join('\n');
  return '';
}

function findScript(content: unknown): ScriptStep[] | null {
  const m = textOf(content).match(MARK);
  if (!m) return null;
  try {
    return JSON.parse(m[1]!);
  } catch {
    return null;
  }
}

export interface FakeServer {
  port: number;
  url: string;
  requests: number;
  close(): Promise<void>;
}

function serve(handler: (body: any, url: string, res: http.ServerResponse) => void): Promise<FakeServer> {
  const state = { requests: 0 };
  const srv = http.createServer((req, res) => {
    let d = '';
    req.on('data', (c) => (d += c));
    req.on('end', () => {
      state.requests++;
      let body: any = {};
      try {
        body = d ? JSON.parse(d) : {};
      } catch {
        /* ignore */
      }
      handler(body, req.url ?? '', res);
    });
  });
  return new Promise((resolve) => {
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as { port: number }).port;
      resolve({
        port,
        url: `http://127.0.0.1:${port}`,
        get requests() {
          return state.requests;
        },
        close: () => new Promise((r) => srv.close(() => r())),
      } as FakeServer);
    });
  });
}

/** Anthropic Messages API (streaming). */
export function fakeAnthropic(): Promise<FakeServer> {
  return serve((body, url, res) => {
    if (!url.startsWith('/v1/messages') || url.includes('count_tokens')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ input_tokens: 10 }));
    }
    const messages: any[] = body.messages ?? [];
    let scriptAt = -1;
    let script: ScriptStep[] | null = null;
    messages.forEach((m, i) => {
      if (m.role !== 'user') return;
      const s = findScript(m.content);
      if (s) {
        script = s;
        scriptAt = i;
      }
    });
    let done = 0;
    for (const m of messages.slice(scriptAt + 1)) {
      if (Array.isArray(m.content)) done += m.content.filter((c: any) => c.type === 'tool_result').length;
    }
    const step = (script as ScriptStep[] | null)?.[done];
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    const ev = (t: string, o: object) => res.write(`event: ${t}\ndata: ${JSON.stringify({ type: t, ...o })}\n\n`);
    ev('message_start', { message: { id: `msg_${Date.now()}`, type: 'message', role: 'assistant', model: body.model, content: [], stop_reason: null, usage: { input_tokens: 12, output_tokens: 0 } } });
    if (step) {
      const id = `toolu_${Date.now()}_${done}`;
      ev('content_block_start', { index: 0, content_block: { type: 'tool_use', id, name: step.tool, input: {} } });
      ev('content_block_delta', { index: 0, delta: { type: 'input_json_delta', partial_json: JSON.stringify(step.input) } });
    } else {
      ev('content_block_start', { index: 0, content_block: { type: 'text', text: '' } });
      ev('content_block_delta', { index: 0, delta: { type: 'text_delta', text: 'done' } });
    }
    ev('content_block_stop', { index: 0 });
    ev('message_delta', { delta: { stop_reason: step ? 'tool_use' : 'end_turn' }, usage: { output_tokens: 7 } });
    ev('message_stop', {});
    res.end();
  });
}

/** OpenAI Responses API (streaming), as Codex uses it. */
export function fakeResponses(): Promise<FakeServer> {
  return serve((body, url, res) => {
    if (!url.includes('/responses')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end('{"data":[],"models":[]}');
    }
    const input: any[] = body.input ?? [];
    let scriptAt = -1;
    let script: ScriptStep[] | null = null;
    input.forEach((item, i) => {
      if (item.type !== 'message' || item.role !== 'user') return;
      const s = findScript(item.content);
      if (s) {
        script = s;
        scriptAt = i;
      }
    });
    const done = input.slice(scriptAt + 1).filter((x) => x.type === 'function_call_output' || x.type === 'custom_tool_call_output').length;
    const step = (script as ScriptStep[] | null)?.[done];
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    const ev = (o: any) => res.write(`event: ${o.type}\ndata: ${JSON.stringify(o)}\n\n`);
    const rid = `resp_${Date.now()}`;
    ev({ type: 'response.created', response: { id: rid } });
    const callId = `call_${Date.now()}_${done}`;
    const item = step
      ? step.custom
        ? { type: 'custom_tool_call', id: `ctc_${done}`, call_id: callId, name: step.tool, input: step.input, status: 'completed' }
        : { type: 'function_call', id: `fc_${done}`, call_id: callId, name: step.tool, arguments: JSON.stringify(step.input), status: 'completed' }
      : { type: 'message', role: 'assistant', id: `msg_${done}`, content: [{ type: 'output_text', text: 'done' }] };
    ev({ type: 'response.output_item.done', item });
    ev({ type: 'response.completed', response: { id: rid, usage: { input_tokens: 12, input_tokens_details: null, output_tokens: 7, output_tokens_details: null, total_tokens: 19 } } });
    res.end();
  });
}

export function script(steps: ScriptStep[], text = 'scripted task'): string {
  return `${text} AGN_SCRIPT:${JSON.stringify(steps)}END`;
}

export function codexProviderToml(url: string): string {
  return [
    'model = "scripted-model"',
    'include_apply_patch_tool = true',
    'model_provider = "agenomic_scripted"',
    '[model_providers.agenomic_scripted]',
    'name = "agenomic scripted"',
    `base_url = "${url}/v1"`,
    'wire_api = "responses"',
    'env_key = "AGENOMIC_SCRIPTED_KEY"',
  ].join('\n');
}
