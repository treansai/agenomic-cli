//! `google-adk` target: a Google Agent Development Kit (ADK) agent exposing the
//! conventional `root_agent`, runnable with `adk run` / `adk web` and
//! deployable through Google's `agents-cli`.
//!
//! ADK models an agent as a single [`Agent`](https://github.com/google/adk-python)
//! (`LlmAgent`) carrying a name, model, description, instruction, and a list of
//! tool callables. We fold the system prompt and every declared skill prompt
//! into the agent instruction, and emit each declared MCP tool as a typed stub
//! callable (server/version recorded) for the operator to wire to a live MCP
//! server. Gemini models bind natively; non-Gemini providers are routed through
//! ADK's `LiteLlm` wrapper.

use crate::artifact::CompiledArtifact;
use crate::codegen::common::{api_key_env, banner, provider_for, temperature_literal};
use crate::genome::{py_ident, Genome};
use crate::target::CompileTarget;

pub(crate) fn generate(genome: &Genome) -> CompiledArtifact {
    let mut a = CompiledArtifact::new(CompileTarget::GoogleAdk);
    let provider = provider_for(&genome.spec.runtime.model_provider);
    let key_env = api_key_env(&genome.spec.runtime.model_provider);

    a.insert("agent.py", agent_py(genome, key_env));
    // ADK discovers `root_agent` by importing the package's agent module.
    a.insert("__init__.py", "from . import agent\n".to_string());
    a.insert(
        "requirements.txt",
        requirements(&genome.spec.runtime.model_provider),
    );
    a.insert("README.md", readme(genome, provider.label, key_env));
    a
}

/// `true` when the provider binds to a Gemini model natively (no LiteLlm shim).
fn is_gemini(provider: &str) -> bool {
    matches!(
        provider.trim().to_ascii_lowercase().as_str(),
        "google" | "google-generativeai" | "google-genai" | "vertexai" | "gemini"
    )
}

/// The value the generated `MODEL` constant takes. Gemini providers use the
/// bare model id; everything else is given a LiteLlm `provider/model` string.
fn model_literal(provider: &str, model_id: &str) -> String {
    let p = provider.trim().to_ascii_lowercase();
    if is_gemini(&p) {
        model_id.to_string()
    } else {
        format!("{p}/{model_id}")
    }
}

fn requirements(provider: &str) -> String {
    if is_gemini(provider) {
        "google-adk>=1.0\n".to_string()
    } else {
        // LiteLlm pulls in `litellm`; ship it so non-Gemini providers run.
        "google-adk>=1.0\nlitellm>=1.40\n".to_string()
    }
}

fn agent_py(genome: &Genome, key_env: &str) -> String {
    let provider = genome.spec.runtime.model_provider.to_ascii_lowercase();
    let gemini = is_gemini(&provider);

    let litellm_import = if gemini {
        String::new()
    } else {
        "from google.adk.models.lite_llm import LiteLlm\n".to_string()
    };
    let model_arg = if gemini {
        "MODEL".to_string()
    } else {
        "LiteLlm(model=MODEL)".to_string()
    };

    // ADK requires `name` to be a valid Python identifier.
    let agent_name = py_ident(&genome.agent_slug());

    // Build the skill registry (name -> prompt file under prompts/skills/) and
    // the tool stub functions.
    let skills = skills_dict(genome);
    let (tool_defs, tool_list) = tool_stubs(genome);

    format!(
        r###"{banner}
import os
from pathlib import Path

from google.adk.agents import Agent
{litellm_import}
PROMPT_DIR = Path(__file__).parent / "prompts"
MODEL = {model:?}
TEMPERATURE = {temperature}
AGENT_ID = {agent_id:?}

# ADK reads provider credentials from the environment ({key_env}).

# Skill name -> prompt file, relative to prompts/.
SKILLS = {skills}


def _load(rel: str) -> str:
    path = PROMPT_DIR / rel
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _instruction() -> str:
    parts = [_load("system.md")]
    for name, rel in SKILLS.items():
        body = _load(rel)
        if body:
            parts.append(f"## Skill: {{name}}\n\n{{body}}")
    joined = "\n\n".join(p for p in parts if p).strip()
    return joined or "You are a helpful assistant."

{tool_defs}
root_agent = Agent(
    name={agent_name:?},
    model={model_arg},
    description={description:?},
    instruction=_instruction(),
    tools=[{tool_list}],
)


if __name__ == "__main__":
    # `adk run .` (CLI) or `adk web` (browser) discovers `root_agent`.
    print(f"Loaded ADK agent {{root_agent.name!r}} (model: {{MODEL}}).")
"###,
        banner = banner(genome, "google-adk"),
        litellm_import = litellm_import,
        model = model_literal(&provider, &genome.spec.runtime.model_id),
        temperature = temperature_literal(genome),
        agent_id = genome.spec.agent.id,
        key_env = key_env,
        skills = skills,
        tool_defs = tool_defs,
        agent_name = agent_name,
        model_arg = model_arg,
        description = genome
            .spec
            .agent
            .description
            .clone()
            .unwrap_or_else(|| format!("{} agent.", genome.spec.agent.name)),
        tool_list = tool_list,
    )
}

/// Render the skills registry as a Python dict literal mapping skill name →
/// prompt file path (relative to `prompts/`). Deterministic (declaration order).
fn skills_dict(genome: &Genome) -> String {
    if genome.skill_prompts.is_empty() {
        return "{}".to_string();
    }
    let mut s = String::from("{\n");
    for skill in &genome.skill_prompts {
        s.push_str(&format!(
            "    {:?}: {:?},\n",
            skill.name,
            format!("skills/{}.md", py_ident(&skill.name))
        ));
    }
    s.push('}');
    s
}

/// Emit one stub callable per declared tool plus the list of their identifiers
/// for the `tools=[...]` argument. Stubs record the declared binding and raise
/// `NotImplementedError` until the operator wires them to a live MCP server.
fn tool_stubs(genome: &Genome) -> (String, String) {
    if genome.spec.tools.is_empty() {
        return (String::new(), String::new());
    }
    let mut defs = String::new();
    let mut names = Vec::new();
    for tool in &genome.spec.tools {
        let ident = py_ident(&tool.name);
        let protocol = tool.protocol.clone().unwrap_or_default();
        let server = tool.server.clone().unwrap_or_default();
        let version = tool.version.clone().unwrap_or_default();
        let not_impl = format!(
            "tool {:?} is a generated stub (protocol={:?}, server={:?}, version={:?}); wire it to your MCP server",
            tool.name, protocol, server, version
        );
        defs.push_str(&format!(
            "def {ident}(request: str) -> str:\n\
             \x20   \"\"\"Stub binding for tool {name:?} (protocol={protocol:?}, server={server:?}, version={version:?}).\n\n\
             \x20   Auto-generated by agenomic-compile. Replace the body with a real\n\
             \x20   MCP call to make this tool live.\n\
             \x20   \"\"\"\n\
             \x20   raise NotImplementedError({not_impl:?})\n\n\n",
            ident = ident,
            name = tool.name,
            protocol = protocol,
            server = server,
            version = version,
            not_impl = not_impl,
        ));
        names.push(ident);
    }
    (defs, names.join(", "))
}

fn readme(genome: &Genome, provider_label: &str, key_env: &str) -> String {
    format!(
        "# {name} — Google ADK runtime adapter\n\n\
         Auto-generated by `agenomic compile --target google-adk` from `{agent_id}`.\n\n\
         Provider: **{provider_label}**, model `{model}`. The system prompt and each\n\
         declared skill are folded into the agent instruction; declared MCP tools are\n\
         emitted as typed stub callables to wire to your MCP servers.\n\n\
         ## Run\n\n\
         ```bash\n\
         pip install -r requirements.txt\n\
         export {key_env}=...\n\
         adk run .        # interactive CLI\n\
         adk web          # browser UI (run from the parent directory)\n\
         ```\n\n\
         Deploy and publish with Google's [`agents-cli`](https://github.com/google/agents-cli):\n\n\
         ```bash\n\
         uvx google-agents-cli deploy\n\
         ```\n\n\
         `manifest.json` pins the BLAKE3 of every generated file and the source genome hash.\n",
        name = genome.spec.agent.name,
        agent_id = genome.spec.agent.id,
        provider_label = provider_label,
        model = genome.spec.runtime.model_id,
        key_env = key_env,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genome::Genome;

    const GENOME: &str = r#"
spec_version: '0.1'
agent:
  id: 'agent://treans/claims-agent'
  name: 'Claims Agent'
  description: 'Triages claims.'
runtime:
  model_provider: 'google'
  model_id: 'gemini-1.5-pro'
  temperature: 0.0
tools:
  - name: 'classify_claim'
    protocol: 'mcp'
    server: 'mcp://internal/claims'
    version: '1.2.0'
skills:
  - name: 'classify_claim'
    prompt: 'prompts/skills/classify_claim.md'
knowledge: []
policies: []
"#;

    fn genome() -> Genome {
        Genome::from_yaml(GENOME, std::path::Path::new(".")).unwrap()
    }

    #[test]
    fn gemini_binds_natively_without_litellm() {
        let art = generate(&genome());
        let agent = art.files.get("agent.py").unwrap();
        assert!(agent.contains("from google.adk.agents import Agent"));
        assert!(agent.contains("model=MODEL"));
        assert!(!agent.contains("LiteLlm"));
        assert!(agent.contains("gemini-1.5-pro"));
        assert!(art.files["requirements.txt"].contains("google-adk"));
        assert!(!art.files["requirements.txt"].contains("litellm"));
        // Package exposes root_agent via __init__.
        assert_eq!(
            art.files.get("__init__.py").unwrap(),
            "from . import agent\n"
        );
        assert!(agent.contains("root_agent = Agent("));
        assert!(agent.contains("name=\"claims_agent\""));
    }

    #[test]
    fn non_gemini_provider_routes_through_litellm() {
        let g = GENOME
            .replace("model_provider: 'google'", "model_provider: 'openai'")
            .replace("model_id: 'gemini-1.5-pro'", "model_id: 'gpt-4o'");
        let genome = Genome::from_yaml(&g, std::path::Path::new(".")).unwrap();
        let art = generate(&genome);
        let agent = art.files.get("agent.py").unwrap();
        assert!(agent.contains("from google.adk.models.lite_llm import LiteLlm"));
        assert!(agent.contains("LiteLlm(model=MODEL)"));
        assert!(agent.contains("\"openai/gpt-4o\""));
        assert!(art.files["requirements.txt"].contains("litellm"));
    }

    #[test]
    fn declared_tools_become_stub_callables() {
        let art = generate(&genome());
        let agent = art.files.get("agent.py").unwrap();
        assert!(agent.contains("def classify_claim(request: str) -> str:"));
        assert!(agent.contains("raise NotImplementedError"));
        assert!(agent.contains("tools=[classify_claim]"));
    }
}
