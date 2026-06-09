//! `langgraph` target: a `StateGraph` with one node per skill, run in sequence.

use crate::artifact::CompiledArtifact;
use crate::codegen::common::{api_key_env, banner, provider_for, temperature_literal};
use crate::genome::{py_ident, Genome};
use crate::target::CompileTarget;

pub(crate) fn generate(genome: &Genome) -> CompiledArtifact {
    let mut a = CompiledArtifact::new(CompileTarget::LangGraph);
    let provider = provider_for(&genome.spec.runtime.model_provider);
    let key_env = api_key_env(&genome.spec.runtime.model_provider);

    a.insert("graph.py", graph_py(genome, key_env));
    a.insert(
        "requirements.txt",
        format!(
            "langgraph>=0.2\nlangchain-core>=0.3\n{}\n",
            langchain_provider(&genome.spec.runtime.model_provider)
        ),
    );
    a.insert("README.md", readme(genome, provider.label, key_env));
    a
}

fn langchain_provider(name: &str) -> &'static str {
    match name.trim().to_ascii_lowercase().as_str() {
        "anthropic" => "langchain-anthropic>=0.2",
        "google" | "google-generativeai" | "vertexai" => "langchain-google-genai>=2.0",
        _ => "langchain-openai>=0.2",
    }
}

fn chat_model_ctor(name: &str) -> &'static str {
    match name.trim().to_ascii_lowercase().as_str() {
        "anthropic" => "from langchain_anthropic import ChatAnthropic as _Chat",
        "google" | "google-generativeai" | "vertexai" => {
            "from langchain_google_genai import ChatGoogleGenerativeAI as _Chat"
        }
        _ => "from langchain_openai import ChatOpenAI as _Chat",
    }
}

fn graph_py(genome: &Genome, key_env: &str) -> String {
    // One node function per skill; the entry node loads the system prompt.
    let mut nodes = String::new();
    let mut wiring = String::new();
    let mut prev = "__start__".to_string();

    if genome.skill_prompts.is_empty() {
        nodes.push_str(&node_fn("respond", None));
        wiring.push_str("    graph.add_node(\"respond\", respond)\n");
        wiring.push_str("    graph.add_edge(START, \"respond\")\n");
        wiring.push_str("    graph.add_edge(\"respond\", END)\n");
    } else {
        for (i, skill) in genome.skill_prompts.iter().enumerate() {
            let fname = py_ident(&skill.name);
            nodes.push_str(&node_fn(&fname, Some(&skill.name)));
            wiring.push_str(&format!("    graph.add_node({fname:?}, {fname})\n"));
            if i == 0 {
                wiring.push_str(&format!("    graph.add_edge(START, {fname:?})\n"));
            } else {
                wiring.push_str(&format!("    graph.add_edge({prev:?}, {fname:?})\n"));
            }
            prev = fname;
        }
        wiring.push_str(&format!("    graph.add_edge({prev:?}, END)\n"));
    }

    format!(
        r#"{banner}
import os
from pathlib import Path
from typing import TypedDict

from langgraph.graph import StateGraph, START, END
{chat_import}

PROMPT_DIR = Path(__file__).parent / "prompts"
MODEL = {model:?}
TEMPERATURE = {temperature}
AGENT_ID = {agent_id:?}


def _load(name: str) -> str:
    path = PROMPT_DIR / name
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _model():
    # Reads {key_env} from the environment.
    return _Chat(model=MODEL, temperature=TEMPERATURE)


class AgentState(TypedDict, total=False):
    input: str
    output: str


SYSTEM_PROMPT = _load("system.md")


{nodes}
def build_graph():
    graph = StateGraph(AgentState)
{wiring}    return graph.compile()


# Module-level compiled graph for `langgraph` tooling / `import graph`.
app = build_graph()


if __name__ == "__main__":
    import sys

    user_input = sys.argv[1] if len(sys.argv) > 1 else ""
    result = app.invoke({{"input": user_input}})
    print(result.get("output", ""))
"#,
        banner = banner(genome, "langgraph"),
        chat_import = chat_model_ctor(&genome.spec.runtime.model_provider),
        model = genome.spec.runtime.model_id,
        temperature = temperature_literal(genome),
        agent_id = genome.spec.agent.id,
        key_env = key_env,
        nodes = nodes,
        wiring = wiring,
    )
}

/// A node function. When `skill` is set the node prepends that skill's prompt
/// to the system prompt. Built by joining lines so every body statement keeps a
/// consistent 4-space indent (no line-continuation whitespace surprises).
fn node_fn(fname: &str, skill: Option<&str>) -> String {
    let mut lines = vec![format!("def {fname}(state: AgentState) -> AgentState:")];
    match skill {
        Some(name) => {
            lines.push(format!(
                "    skill_prompt = _load(\"skills/{}.md\")",
                py_ident(name)
            ));
            lines.push(
                "    system = (SYSTEM_PROMPT + \"\\n\\n\" + skill_prompt).strip()".to_string(),
            );
        }
        None => lines.push("    system = SYSTEM_PROMPT".to_string()),
    }
    lines.push(
        "    messages = [(\"system\", system), (\"user\", state.get(\"input\", \"\"))]".to_string(),
    );
    lines.push("    response = _model().invoke(messages)".to_string());
    lines.push("    return {\"output\": response.content}".to_string());
    let mut body = lines.join("\n");
    body.push_str("\n\n\n");
    body
}

fn readme(genome: &Genome, provider_label: &str, key_env: &str) -> String {
    format!(
        "# {name} — LangGraph runtime adapter\n\n\
         Auto-generated by `agenomic compile --target langgraph` from `{agent_id}`.\n\n\
         Provider: **{provider_label}**, model `{model}`. One graph node per declared skill, run in declaration order.\n\n\
         ## Run\n\n\
         ```bash\n\
         pip install -r requirements.txt\n\
         export {key_env}=...\n\
         python graph.py \"your input\"\n\
         ```\n\n\
         `graph.app` is the compiled `StateGraph`, ready for LangGraph tooling.\n",
        name = genome.spec.agent.name,
        agent_id = genome.spec.agent.id,
        provider_label = provider_label,
        model = genome.spec.runtime.model_id,
        key_env = key_env,
    )
}
