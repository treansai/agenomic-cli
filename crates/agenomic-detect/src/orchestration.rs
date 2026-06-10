//! Orchestration detection: workflow topology, multi-agent systems, and
//! environment variables, recovered from project source (spec 0.2, RFC 0009).
//!
//! Same invariants as the rest of the crate: offline, deterministic
//! (files scanned in sorted order, results sorted), bounded (directory
//! denylist, file count and size caps), regex/heuristic based — no code
//! execution.
//!
//! What it recovers today:
//! - **LangGraph** builders: `add_node`, `add_edge`, `add_conditional_edges`,
//!   `set_entry_point`, `START`/`END` — one [`DetectedWorkflow`] per builder
//!   function containing at least one node.
//! - **Temporal (Python)**: `@workflow.defn` classes and `@workflow.signal`
//!   handlers — workflow names, signal names, and the `temporal` engine hint.
//! - **Multi-agent synthesis**: two or more graphs, or a graph plus Temporal,
//!   yield a [`DetectedSystem`] whose roles are the union of graph nodes.
//! - **Environment variables**: `os.environ[...]` / `os.getenv(...)` /
//!   `process.env.X` / `std::env::var("X")` plus `.env.example` keys.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use agenomic_core::CliResult;

/// Directories never scanned.
const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    ".agenomic",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
];

/// Hard caps so detection stays fast on monorepos.
const MAX_FILES: usize = 4000;
const MAX_FILE_BYTES: u64 = 512 * 1024;

/// Ambient variables that are never part of an agent's contract.
const ENV_DENYLIST: &[&str] = &[
    "PATH",
    "HOME",
    "PWD",
    "TERM",
    "SHELL",
    "USER",
    "LANG",
    "LC_ALL",
    "TZ",
    "CI",
    "PYTHONPATH",
    "PYTHONUNBUFFERED",
    "VIRTUAL_ENV",
    "TMPDIR",
    "HOSTNAME",
    "SOURCE_DATE_EPOCH",
];

/// One conditional or unconditional hand-off inside a graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedEdge {
    pub from: String,
    pub to: String,
    /// Router function name for conditional edges, `None` for plain edges.
    pub router: Option<String>,
}

/// One workflow recovered from source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedWorkflow {
    /// Kebab-case slug derived from the builder function or class name.
    pub slug: String,
    /// Engine hint: `langgraph` or `temporal`.
    pub engine: String,
    /// Nodes in declaration order.
    pub nodes: Vec<String>,
    pub edges: Vec<DetectedEdge>,
    pub entry: Option<String>,
    /// Signals (Temporal workflows only).
    pub signals: Vec<String>,
    /// `path:function` or `path:Class` the workflow was recovered from.
    pub origin: String,
}

/// A multi-agent system synthesized from several graphs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedSystem {
    /// Sorted distinct node names across all graphs.
    pub roles: Vec<String>,
    pub edges: Vec<DetectedEdge>,
    pub entrypoint: Option<String>,
    pub signals: Vec<String>,
    /// `temporal` when Temporal is present, else `langgraph`.
    pub engine: String,
}

/// Environment variables referenced by the project source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectedEnv {
    /// Read without a fallback (`os.environ[...]`, `std::env::var(..)?`).
    pub required: Vec<String>,
    /// Read with a fallback (`os.getenv`, `.get(...)`) or listed in `.env.example`.
    pub optional: Vec<String>,
}

/// Full result of the orchestration pass.
#[derive(Debug, Clone, Default)]
pub struct DetectedOrchestration {
    pub workflows: Vec<DetectedWorkflow>,
    pub system: Option<DetectedSystem>,
    pub env: DetectedEnv,
}

impl DetectedOrchestration {
    pub fn is_empty(&self) -> bool {
        self.workflows.is_empty()
            && self.system.is_none()
            && self.env.required.is_empty()
            && self.env.optional.is_empty()
    }
}

/// Run the orchestration pass over a project directory.
pub fn detect_orchestration(root: &Path) -> CliResult<DetectedOrchestration> {
    let files = collect_files(root);

    let mut workflows: Vec<DetectedWorkflow> = Vec::new();
    let mut temporal_signals: BTreeSet<String> = BTreeSet::new();
    let mut temporal_present = false;
    let mut env_required: BTreeSet<String> = BTreeSet::new();
    let mut env_optional: BTreeSet<String> = BTreeSet::new();

    for path in &files {
        let Ok(meta) = std::fs::metadata(path) else {
            continue;
        };
        if meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        let ext = path
            .extension()
            .and_then(|x| x.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let name = path.file_name().and_then(|x| x.to_str()).unwrap_or("");

        if name == ".env.example" || name == ".env.sample" || name == ".env.template" {
            scan_env_file(&text, &mut env_optional);
            continue;
        }
        match ext.as_str() {
            "py" => {
                if text.contains("temporalio") || text.contains("from temporal") {
                    temporal_present = true;
                }
                scan_langgraph(&text, &rel, &mut workflows);
                scan_temporal(&text, &rel, &mut workflows, &mut temporal_signals);
                scan_env_python(&text, &mut env_required, &mut env_optional);
            }
            "js" | "ts" | "mjs" | "cjs" | "tsx" => {
                scan_env_node(&text, &mut env_required, &mut env_optional);
            }
            "rs" => {
                scan_env_rust(&text, &mut env_required);
            }
            _ => {}
        }
    }

    // A variable read anywhere without a fallback is required.
    let optional: Vec<String> = env_optional.difference(&env_required).cloned().collect();
    let env = DetectedEnv {
        required: env_required.into_iter().collect(),
        optional,
    };

    // Propagate temporal signals onto temporal workflows.
    for wf in workflows.iter_mut().filter(|w| w.engine == "temporal") {
        if wf.signals.is_empty() {
            wf.signals = temporal_signals.iter().cloned().collect();
        }
    }

    // Disambiguate duplicate slugs (two builders reducing to the same name).
    {
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for wf in workflows.iter_mut() {
            let n = seen.entry(wf.slug.clone()).or_insert(0);
            *n += 1;
            if *n > 1 {
                wf.slug = format!("{}-{}", wf.slug, n);
            }
        }
    }

    // Classify graphs as *macro* (their nodes name other detected graphs —
    // that is the multi-agent topology) or *micro* (one agent's internal
    // pipeline). A node "names an agent" when it matches another graph's slug
    // or the package directory its builder lives in.
    let graph_workflows: Vec<&DetectedWorkflow> = workflows
        .iter()
        .filter(|w| w.engine == "langgraph" && !w.nodes.is_empty())
        .collect();
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for wf in &graph_workflows {
        candidates.insert(wf.slug.clone());
        if let Some(pkg) = origin_package(&wf.origin) {
            candidates.insert(pkg);
        }
    }
    let macro_graphs: Vec<&DetectedWorkflow> = graph_workflows
        .iter()
        .filter(|wf| {
            let matches = wf
                .nodes
                .iter()
                .filter(|n| node_names_agent(n, &candidates, &wf.slug))
                .count();
            matches >= 2 && matches * 2 >= wf.nodes.len()
        })
        .copied()
        .collect();

    let mut roles: BTreeSet<String> = BTreeSet::new();
    let mut edges: Vec<DetectedEdge> = Vec::new();
    for wf in &macro_graphs {
        roles.extend(wf.nodes.iter().cloned());
        for e in &wf.edges {
            if !edges.contains(e) {
                edges.push(e.clone());
            }
        }
    }
    let system = if roles.len() >= 2 {
        let entrypoint = macro_graphs.iter().find_map(|w| w.entry.clone());
        Some(DetectedSystem {
            roles: roles.into_iter().collect(),
            edges,
            entrypoint,
            signals: temporal_signals.iter().cloned().collect(),
            engine: if temporal_present {
                "temporal"
            } else {
                "langgraph"
            }
            .to_string(),
        })
    } else {
        None
    };

    Ok(DetectedOrchestration {
        workflows,
        system,
        env,
    })
}

/// Normalized name of the directory a graph builder lives in
/// (`packages/agents/src/agents/intake/graph.py:_build_graph` → `intake`).
fn origin_package(origin: &str) -> Option<String> {
    let path = origin.split(':').next()?;
    let mut parts = path.rsplit('/');
    let _file = parts.next()?;
    let dir = parts.next()?;
    let slug = slug_from_fn(dir);
    if slug.is_empty() {
        None
    } else {
        Some(slug)
    }
}

/// True when `node` matches some other graph's slug or package — i.e. the
/// node is a hand-off to another agent rather than an internal pipeline step.
fn node_names_agent(node: &str, candidates: &BTreeSet<String>, own_slug: &str) -> bool {
    let k = slug_from_fn(node);
    candidates
        .iter()
        .any(|c| c != own_slug && (k == *c || k.starts_with(&format!("{c}-"))))
}

fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut children: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
        children.sort();
        for child in children {
            if files.len() >= MAX_FILES {
                return files;
            }
            let name = child.file_name().and_then(|x| x.to_str()).unwrap_or("");
            if child.is_dir() {
                if !SKIP_DIRS.contains(&name) && !name.starts_with('.') || name == ".env.d" {
                    stack.push(child);
                }
            } else {
                files.push(child);
            }
        }
    }
    files.sort();
    files
}

// ---------------------------------------------------------------------------
// LangGraph
// ---------------------------------------------------------------------------

/// Extract one quoted string starting at `s` (after skipping whitespace).
fn leading_quoted(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    let quote = s.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let rest = &s[1..];
    let end = rest.find(quote)?;
    Some((rest[..end].to_string(), &rest[end + 1..]))
}

fn all_quoted(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        if c == '"' || c == '\'' {
            if let Some(end) = s[i + 1..].find(c) {
                out.push(s[i + 1..i + 1 + end].to_string());
                // Skip past the closing quote.
                for _ in 0..end + 1 {
                    chars.next();
                }
            }
        }
    }
    out
}

fn slug_from_fn(name: &str) -> String {
    let trimmed = name
        .trim_start_matches("build_")
        .trim_start_matches("make_")
        .trim_start_matches("create_")
        .trim_end_matches("_graph")
        .trim_end_matches("_workflow");
    let base = if trimmed.is_empty() { name } else { trimmed };
    let mut slug: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    slug.trim_matches('-').to_string()
}

/// Slug for a graph builder, falling back to the file stem and then the
/// parent directory when the function name is degenerate (`_build_graph`,
/// `build_graph`, …) — common in per-agent packages where every agent
/// exposes the same builder name.
fn slug_for(fn_name: &str, rel: &str) -> String {
    let s = slug_from_fn(fn_name);
    if !s.is_empty() && !matches!(s.as_str(), "build" | "make" | "create" | "graph") {
        return s;
    }
    let mut parts = rel.rsplit('/');
    let stem = parts.next().unwrap_or(rel).trim_end_matches(".py");
    if !stem.is_empty() && stem != "graph" && stem != "workflow" {
        return slug_from_fn(stem);
    }
    parts
        .next()
        .map(slug_from_fn)
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "graph".to_string())
}

fn wf_entry<'a>(
    map: &'a mut BTreeMap<String, DetectedWorkflow>,
    key: &str,
    rel: &str,
) -> &'a mut DetectedWorkflow {
    map.entry(key.to_string())
        .or_insert_with(|| DetectedWorkflow {
            slug: slug_for(key, rel),
            engine: "langgraph".to_string(),
            nodes: Vec::new(),
            edges: Vec::new(),
            entry: None,
            signals: Vec::new(),
            origin: format!("{rel}:{key}"),
        })
}

/// Scan one Python file for LangGraph builders. Nodes/edges are grouped by
/// the enclosing `def`; module level declarations group under the file stem.
fn scan_langgraph(text: &str, rel: &str, out: &mut Vec<DetectedWorkflow>) {
    if !text.contains("add_node") {
        return;
    }
    let stem = rel
        .rsplit('/')
        .next()
        .unwrap_or(rel)
        .trim_end_matches(".py")
        .to_string();

    // Builder-function grouping: (origin key, workflow under construction).
    let mut current_fn = stem.clone();
    let mut by_fn: BTreeMap<String, DetectedWorkflow> = BTreeMap::new();
    // Joined-line buffer so calls split across lines still match.
    let mut pending = String::new();

    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("def ") {
            if let Some(name) = rest.split('(').next() {
                current_fn = name.trim().to_string();
            }
            pending.clear();
        }

        let joined = if pending.is_empty() {
            line.to_string()
        } else {
            format!("{pending} {line}")
        };
        // Keep buffering while a call of interest has unbalanced parens.
        let interesting = joined.contains("add_node(")
            || joined.contains("add_edge(")
            || joined.contains("add_conditional_edges(")
            || joined.contains("set_entry_point(");
        if interesting
            && joined.matches('(').count() > joined.matches(')').count()
            && pending.len() < 2000
        {
            pending = joined;
            continue;
        }
        pending.clear();

        if let Some(idx) = joined.find("add_node(") {
            if let Some((node, _)) = leading_quoted(&joined[idx + "add_node(".len()..]) {
                let w = wf_entry(&mut by_fn, &current_fn, rel);
                if !w.nodes.contains(&node) {
                    w.nodes.push(node);
                }
            }
        }
        if let Some(idx) = joined.find("set_entry_point(") {
            if let Some((node, _)) = leading_quoted(&joined[idx + "set_entry_point(".len()..]) {
                wf_entry(&mut by_fn, &current_fn, rel).entry = Some(node);
            }
        }
        if let Some(idx) = joined.find("add_edge(") {
            let args = &joined[idx + "add_edge(".len()..];
            if let Some((from, rest)) = leading_quoted(args) {
                let rest = rest.trim_start().trim_start_matches(',');
                if let Some((to, _)) = leading_quoted(rest) {
                    let w = wf_entry(&mut by_fn, &current_fn, rel);
                    let e = DetectedEdge {
                        from,
                        to,
                        router: None,
                    };
                    if !w.edges.contains(&e) {
                        w.edges.push(e);
                    }
                } else if rest.trim_start().starts_with("END") {
                    let w = wf_entry(&mut by_fn, &current_fn, rel);
                    let e = DetectedEdge {
                        from,
                        to: "END".to_string(),
                        router: None,
                    };
                    if !w.edges.contains(&e) {
                        w.edges.push(e);
                    }
                }
            } else if args.trim_start().starts_with("START") {
                let rest = args.trim_start()["START".len()..]
                    .trim_start()
                    .trim_start_matches(',');
                if let Some((to, _)) = leading_quoted(rest) {
                    wf_entry(&mut by_fn, &current_fn, rel).entry = Some(to);
                }
            }
        }
        if let Some(idx) = joined.find("add_conditional_edges(") {
            let args = &joined[idx + "add_conditional_edges(".len()..];
            if let Some((from, rest)) = leading_quoted(args) {
                let rest = rest.trim_start().trim_start_matches(',').trim_start();
                let router = rest
                    .split([',', ')'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                // Targets: quoted strings in the mapping (skip keys == values
                // duplicates via contains), plus the END sentinel.
                let mapping = rest.split_once(',').map(|x| x.1).unwrap_or("");
                let w = wf_entry(&mut by_fn, &current_fn, rel);
                let mut targets: Vec<String> = all_quoted(mapping);
                if mapping.contains("END") {
                    targets.push("END".to_string());
                }
                targets.dedup();
                for to in targets {
                    let e = DetectedEdge {
                        from: from.clone(),
                        to,
                        router: if router.is_empty() {
                            None
                        } else {
                            Some(router.clone())
                        },
                    };
                    if !w.edges.contains(&e) {
                        w.edges.push(e);
                    }
                }
            }
        }
    }

    for (_, wf) in by_fn {
        if !wf.nodes.is_empty() {
            out.push(wf);
        }
    }
}

// ---------------------------------------------------------------------------
// Temporal (Python SDK)
// ---------------------------------------------------------------------------

fn scan_temporal(
    text: &str,
    rel: &str,
    out: &mut Vec<DetectedWorkflow>,
    signals: &mut BTreeSet<String>,
) {
    if !text.contains("@workflow.") {
        return;
    }
    let mut pending_defn = false;
    let mut pending_signal: Option<Option<String>> = None; // Some(name_override)
    let mut const_strings: BTreeMap<String, String> = BTreeMap::new();

    for raw in text.lines() {
        let line = raw.trim();
        // CONST = "value" (used by @workflow.signal(name=CONST)).
        if let Some((lhs, rhs)) = line.split_once('=') {
            let lhs = lhs.trim();
            if lhs
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
                && !lhs.is_empty()
            {
                if let Some((v, _)) = leading_quoted(rhs) {
                    const_strings.insert(lhs.to_string(), v);
                }
            }
        }
        if line.starts_with("@workflow.defn") {
            pending_defn = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("@workflow.signal") {
            let name_override = rest
                .split_once("name=")
                .map(|(_, v)| v.trim_end_matches([')', ',']).trim().to_string());
            pending_signal = Some(name_override);
            continue;
        }
        if pending_defn {
            if let Some(rest) = line.strip_prefix("class ") {
                let name = rest.split([':', '(']).next().unwrap_or("").trim();
                if !name.is_empty() {
                    let slug = camel_to_kebab(name);
                    out.push(DetectedWorkflow {
                        slug,
                        engine: "temporal".to_string(),
                        nodes: Vec::new(),
                        edges: Vec::new(),
                        entry: None,
                        signals: Vec::new(),
                        origin: format!("{rel}:{name}"),
                    });
                }
                pending_defn = false;
            } else if !line.is_empty() && !line.starts_with('@') && !line.starts_with('#') {
                pending_defn = false;
            }
            continue;
        }
        if let Some(name_override) = pending_signal.take() {
            let resolved = match name_override {
                Some(token) => {
                    if let Some((v, _)) = leading_quoted(&token) {
                        Some(v)
                    } else {
                        const_strings.get(token.trim()).cloned()
                    }
                }
                None => None,
            };
            if let Some(name) = resolved {
                signals.insert(name);
            } else if let Some(rest) = line.strip_prefix("def ") {
                if let Some(name) = rest.split('(').next() {
                    signals.insert(name.trim().to_string());
                }
            } else if line.starts_with('@') || line.starts_with("async def") {
                if let Some(rest) = line.strip_prefix("async def ") {
                    if let Some(name) = rest.split('(').next() {
                        signals.insert(name.trim().to_string());
                    }
                } else {
                    pending_signal = Some(None);
                }
            }
        }
    }
}

fn camel_to_kebab(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('-');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Environment variables
// ---------------------------------------------------------------------------

fn valid_env_name(name: &str) -> bool {
    name.len() >= 2
        && name.len() <= 64
        && name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && !ENV_DENYLIST.contains(&name)
}

/// Collect `marker("NAME"` occurrences into `out`.
fn collect_calls(text: &str, marker: &str, out: &mut BTreeSet<String>) {
    let mut rest = text;
    while let Some(idx) = rest.find(marker) {
        let after = &rest[idx + marker.len()..];
        if let Some((name, _)) = leading_quoted(after) {
            if valid_env_name(&name) {
                out.insert(name);
            }
        }
        rest = after;
    }
}

fn scan_env_python(text: &str, required: &mut BTreeSet<String>, optional: &mut BTreeSet<String>) {
    collect_calls(text, "os.environ[", required);
    collect_calls(text, "environ[", required);
    collect_calls(text, "os.environ.get(", optional);
    collect_calls(text, "os.getenv(", optional);
    collect_calls(text, "getenv(", optional);
}

fn scan_env_node(text: &str, required: &mut BTreeSet<String>, optional: &mut BTreeSet<String>) {
    collect_calls(text, "process.env[", required);
    // process.env.NAME — dotted access; treat `||`/`??` fallbacks as optional.
    let mut rest = text;
    while let Some(idx) = rest.find("process.env.") {
        let after = &rest[idx + "process.env.".len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let tail = after[name.len()..].trim_start();
        if valid_env_name(&name) {
            if tail.starts_with("||") || tail.starts_with("??") {
                optional.insert(name);
            } else {
                required.insert(name);
            }
        }
        rest = after;
    }
}

fn scan_env_rust(text: &str, required: &mut BTreeSet<String>) {
    collect_calls(text, "std::env::var(", required);
    collect_calls(text, "env::var(", required);
}

fn scan_env_file(text: &str, optional: &mut BTreeSet<String>) {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((name, _)) = line.split_once('=') {
            let name = name.trim();
            if valid_env_name(name) {
                optional.insert(name.to_string());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Emission (spec 0.2 manifests)
// ---------------------------------------------------------------------------

fn org_and_repo(agent_id: &str) -> (String, String) {
    let rest = agent_id.trim_start_matches("agent://");
    let mut parts = rest.splitn(2, '/');
    let org = parts.next().unwrap_or("example").to_string();
    let repo = parts.next().unwrap_or("new").to_string();
    (org, repo)
}

fn kebab(name: &str) -> String {
    name.replace('_', "-")
}

fn yaml_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Render a detected workflow as a spec-0.2 `workflow.yaml` document.
///
/// With `multi_agent` set, graph nodes are treated as member agents of a
/// system (`agent://<org>/<node>`); otherwise they are skills of the single
/// agent `agent_id`.
pub fn emit_workflow_yaml(wf: &DetectedWorkflow, agent_id: &str, multi_agent: bool) -> String {
    let (org, _) = org_and_repo(agent_id);
    let mut s = String::new();
    s.push_str(&format!(
        "# Generated by `agm` from {} — review, then refine with `agm enrich`.\n",
        wf.origin
    ));
    s.push_str("spec_version: '0.2'\n");
    s.push_str("workflow:\n");
    s.push_str(&format!(
        "  id: {}\n",
        yaml_quote(&format!("workflow://{org}/{}", wf.slug))
    ));
    s.push_str(&format!(
        "  name: {}\n",
        yaml_quote(&wf.slug.replace('-', " "))
    ));
    s.push_str("  domain: 'general'\n");
    s.push_str("  criticality: 'low'\n");
    s.push_str("engine:\n");
    s.push_str(&format!("  kind: {}\n", yaml_quote(&wf.engine)));

    if wf.nodes.is_empty() {
        // Temporal workflow recovered from a @workflow.defn class: the run
        // body is opaque to static detection, so emit a single placeholder
        // step plus the signal wait points we did recover.
        s.push_str("steps:\n");
        s.push_str("  - id: run\n");
        s.push_str("    type: agent\n");
        s.push_str(&format!("    agent: {}\n", yaml_quote(agent_id)));
        s.push_str(&format!(
            "    description: {}\n",
            yaml_quote("Durable workflow body (static detection cannot expand it; see origin)")
        ));
        let mut prev = "run".to_string();
        for sig in &wf.signals {
            let id = format!("await_{sig}");
            s.push_str(&format!("  - id: {id}\n"));
            s.push_str("    type: wait\n");
            s.push_str(&format!("    depends_on: [{prev}]\n"));
            s.push_str("    wait_for:\n");
            s.push_str(&format!("      signals: [{sig}]\n"));
            prev = id;
        }
    } else {
        s.push_str("steps:\n");
        for node in &wf.nodes {
            s.push_str(&format!("  - id: {node}\n"));
            s.push_str("    type: agent\n");
            if multi_agent {
                s.push_str(&format!(
                    "    agent: {}\n",
                    yaml_quote(&format!("agent://{org}/{}", kebab(node)))
                ));
            } else {
                s.push_str(&format!("    agent: {}\n", yaml_quote(agent_id)));
                s.push_str(&format!("    skill: {}\n", yaml_quote(node)));
            }
            let deps: Vec<&DetectedEdge> = wf
                .edges
                .iter()
                .filter(|e| &e.to == node && e.from != "START")
                .collect();
            if !deps.is_empty() {
                let names: BTreeSet<&str> = deps.iter().map(|e| e.from.as_str()).collect();
                let list: Vec<&str> = names.into_iter().collect();
                s.push_str(&format!("    depends_on: [{}]\n", list.join(", ")));
                if let Some(router) = deps.iter().find_map(|e| e.router.as_deref()) {
                    s.push_str(&format!(
                        "    when: {}\n",
                        yaml_quote(&format!("{router} -> {node}"))
                    ));
                }
            }
        }
    }

    if !wf.signals.is_empty() {
        s.push_str("signals:\n");
        for sig in &wf.signals {
            s.push_str(&format!("  - name: {sig}\n"));
        }
    }
    s
}

/// Render a detected system as a spec-0.2 `system.yaml` document.
pub fn emit_system_yaml(
    sys: &DetectedSystem,
    agent_id: &str,
    workflows: &[(String, String)],
) -> String {
    let (org, repo) = org_and_repo(agent_id);
    let mut s = String::new();
    s.push_str("# Generated by `agm` — review, then refine with `agm enrich`.\n");
    s.push_str("spec_version: '0.2'\n");
    s.push_str("system:\n");
    s.push_str(&format!(
        "  id: {}\n",
        yaml_quote(&format!("system://{org}/{repo}"))
    ));
    s.push_str(&format!("  name: {}\n", yaml_quote(&repo)));
    s.push_str("  domain: 'general'\n");
    s.push_str("  criticality: 'low'\n");
    s.push_str("agents:\n");
    for role in &sys.roles {
        s.push_str(&format!("  - role: {role}\n"));
        s.push_str(&format!(
            "    id: {}\n",
            yaml_quote(&format!("agent://{org}/{}", kebab(role)))
        ));
    }
    s.push_str("orchestration:\n");
    s.push_str("  style: graph\n");
    s.push_str("  engine:\n");
    s.push_str(&format!("    kind: {}\n", yaml_quote(&sys.engine)));
    if let Some(entry) = &sys.entrypoint {
        s.push_str(&format!("  entrypoint: {entry}\n"));
    }
    if !sys.edges.is_empty() {
        s.push_str("  edges:\n");
        for e in &sys.edges {
            if e.from == "START" {
                continue;
            }
            s.push_str(&format!("    - from: {}\n", e.from));
            s.push_str(&format!("      to: {}\n", e.to));
            if let Some(router) = &e.router {
                s.push_str(&format!(
                    "      when: {}\n",
                    yaml_quote(&format!("{router} -> {}", e.to))
                ));
            }
        }
    }
    if !sys.signals.is_empty() {
        s.push_str("signals:\n");
        for sig in &sys.signals {
            s.push_str(&format!("  - name: {sig}\n"));
        }
    }
    if !workflows.is_empty() {
        s.push_str("workflows:\n");
        for (slug, path) in workflows {
            s.push_str(&format!(
                "  - id: {}\n",
                yaml_quote(&format!("workflow://{org}/{slug}"))
            ));
            s.push_str(&format!("    path: {path}\n"));
        }
    }
    s
}

/// Write detected orchestration manifests into the bundle directory.
///
/// Existing files are never overwritten unless `force`, so hand edits to a
/// generated `system.yaml` / `workflows/*.yaml` survive `agm update`. Returns
/// the bundle-relative paths actually written.
pub fn write_orchestration(
    dir: &Path,
    orch: &DetectedOrchestration,
    agent_id: &str,
    force: bool,
) -> CliResult<Vec<String>> {
    let mut written = Vec::new();
    let multi = orch.system.is_some();
    let mut wf_index: Vec<(String, String)> = Vec::new();
    for wf in &orch.workflows {
        let rel = format!("workflows/{}.yaml", wf.slug);
        wf_index.push((wf.slug.clone(), rel.clone()));
        let path = dir.join(&rel);
        if force || !path.exists() {
            agenomic_fs::write_atomic(&path, emit_workflow_yaml(wf, agent_id, multi).as_bytes())?;
            written.push(rel);
        }
    }
    if let Some(sys) = &orch.system {
        let rel = "system.yaml".to_string();
        let path = dir.join(&rel);
        if force || !path.exists() {
            agenomic_fs::write_atomic(
                &path,
                emit_system_yaml(sys, agent_id, &wf_index).as_bytes(),
            )?;
            written.push(rel);
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LANGGRAPH_SRC: &str = r#"
from langgraph.graph import StateGraph, END

def build_claim_graph():
    graph = StateGraph(ClaimState)
    graph.add_node("intake", intake_node)
    graph.add_node("document", document_node)
    graph.add_node("completeness", completeness_node)
    graph.set_entry_point("intake")
    graph.add_edge("intake", "document")
    graph.add_edge("document", "completeness")
    graph.add_edge("completeness", END)
    return graph.compile()

def build_v2_analysis_graph():
    graph = StateGraph(ClaimState)
    graph.add_node("coverage", coverage_node)
    graph.add_node("triage", triage_node)
    graph.add_node("decision_pack", decision_pack_node)
    graph.set_entry_point("coverage")
    graph.add_edge("coverage", "triage")
    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        {"decision_pack": "decision_pack", END: END},
    )
    graph.add_edge("decision_pack", END)
    return graph.compile()
"#;

    #[test]
    fn langgraph_topology_recovered() {
        let mut wfs = Vec::new();
        scan_langgraph(LANGGRAPH_SRC, "graph.py", &mut wfs);
        assert_eq!(wfs.len(), 2);
        let claim = wfs.iter().find(|w| w.slug == "claim").unwrap();
        assert_eq!(claim.nodes, vec!["intake", "document", "completeness"]);
        assert_eq!(claim.entry.as_deref(), Some("intake"));
        assert!(claim.edges.contains(&DetectedEdge {
            from: "intake".into(),
            to: "document".into(),
            router: None
        }));

        let v2 = wfs.iter().find(|w| w.slug == "v2-analysis").unwrap();
        assert_eq!(v2.entry.as_deref(), Some("coverage"));
        let cond: Vec<&DetectedEdge> = v2.edges.iter().filter(|e| e.router.is_some()).collect();
        assert!(cond
            .iter()
            .any(|e| e.from == "triage" && e.to == "decision_pack"));
        assert!(cond.iter().any(|e| e.from == "triage" && e.to == "END"));
        assert!(cond
            .iter()
            .all(|e| e.router.as_deref() == Some("route_after_triage")));
    }

    #[test]
    fn temporal_workflow_and_signals_recovered() {
        let src = r#"
from temporalio import workflow

EXPERT_REPORT_SIGNAL_NAME = "expert_report_received"

@workflow.defn
class ClaimWorkflow:
    @workflow.signal
    def documents_received(self) -> None:
        ...

    @workflow.signal(name=EXPERT_REPORT_SIGNAL_NAME)
    def expert_report(self, payload: dict) -> None:
        ...
"#;
        let mut wfs = Vec::new();
        let mut signals = BTreeSet::new();
        scan_temporal(src, "wf.py", &mut wfs, &mut signals);
        assert_eq!(wfs.len(), 1);
        assert_eq!(wfs[0].slug, "claim-workflow");
        assert!(signals.contains("documents_received"));
        assert!(signals.contains("expert_report_received"));
    }

    #[test]
    fn env_vars_split_required_optional() {
        let mut req = BTreeSet::new();
        let mut opt = BTreeSet::new();
        scan_env_python(
            r#"
key = os.environ["OPENAI_API_KEY"]
url = os.environ.get("BASE_URL", "http://x")
debug = os.getenv("DEBUG")
"#,
            &mut req,
            &mut opt,
        );
        assert!(req.contains("OPENAI_API_KEY"));
        assert!(opt.contains("BASE_URL"));
        assert!(opt.contains("DEBUG"));
    }

    #[test]
    fn emitted_workflow_lists_steps_with_dependencies() {
        let mut wfs = Vec::new();
        scan_langgraph(LANGGRAPH_SRC, "graph.py", &mut wfs);
        let v2 = wfs.iter().find(|w| w.slug == "v2-analysis").unwrap();
        let yaml = emit_workflow_yaml(v2, "agent://acme/claims", true);
        let doc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(doc["spec_version"].as_str(), Some("0.2"));
        let steps = doc["steps"].as_sequence().unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[2]["depends_on"][0].as_str(), Some("triage"));
        assert_eq!(
            steps[1]["agent"].as_str(),
            Some("agent://acme/triage"),
            "multi-agent mode maps nodes to member agents"
        );
    }

    #[test]
    fn emitted_system_covers_roles_edges_signals() {
        let sys = DetectedSystem {
            roles: vec!["intake".into(), "triage".into()],
            edges: vec![DetectedEdge {
                from: "intake".into(),
                to: "triage".into(),
                router: None,
            }],
            entrypoint: Some("intake".into()),
            signals: vec!["documents_received".into()],
            engine: "temporal".into(),
        };
        let yaml = emit_system_yaml(
            &sys,
            "agent://acme/claims",
            &[("claim".into(), "workflows/claim.yaml".into())],
        );
        let doc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(doc["system"]["id"].as_str(), Some("system://acme/claims"));
        assert_eq!(doc["agents"].as_sequence().unwrap().len(), 2);
        assert_eq!(doc["orchestration"]["entrypoint"].as_str(), Some("intake"));
        assert_eq!(
            doc["workflows"][0]["path"].as_str(),
            Some("workflows/claim.yaml")
        );
    }
}
