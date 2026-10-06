use crate::canonical::{
    ajs_integer, canonical_json, check_ajs_string, code_points, ensure_ajs, ensure_ajs_at, pointer,
    prompt_digest, sort_utf16, sorted_keys, AjsError,
};
use crate::digest::{CONTENT_SCHEMA, RENDERED_PROMPT_SCHEMA};
use crate::error::{
    PromptError, PROMPT_CONTENT_TOO_LARGE, PROMPT_KIND_MISMATCH, PROMPT_RENDER_ERROR,
    PROMPT_SECRET_DETECTED, PROMPT_TEMPLATE_INVALID,
};
use crate::refs::{is_name, is_prompt_id, is_sha256_digest, version_key, MAX_VERSION};
use crate::secrets;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap, HashSet};

pub const TEMPLATE_FORMAT: &str = "agenomic-fstring/v1";
pub const RENDERER_VERSION: &str = "1";
pub const SUPPORTED_RENDERER_VERSIONS: &[&str] = &[RENDERER_VERSION];

pub const MAX_CONTENT_BYTES: usize = 262_144;
pub const MAX_TEMPLATE_CODE_POINTS: usize = 65_536;
pub const MAX_MESSAGES: usize = 256;
pub const MAX_VARIABLES: usize = 128;
pub const MAX_FRAGMENTS: usize = 32;
pub const MAX_OUTPUT_CONTRACT_BYTES: usize = 65_536;
pub const MAX_OUTPUT_CONTRACT_DEPTH: usize = 32;
pub const MAX_FRAGMENT_DEPTH: usize = 8;
pub const MAX_FRAGMENT_EXPANSIONS: usize = 256;
pub const MAX_EXPANDED_CODE_POINTS: usize = 1_048_576;
pub const MAX_RENDERED_CODE_POINTS: usize = 4_194_304;

pub const SYNTAX_REASONS: [&str; 13] = [
    "unmatched_closing_brace",
    "unclosed_brace",
    "empty_placeholder",
    "positional_placeholder",
    "whitespace_in_placeholder",
    "attribute_access",
    "index_access",
    "conversion",
    "format_spec",
    "nested_placeholder",
    "invalid_placeholder_name",
    "placeholder_name_too_long",
    "invalid_fragment_name",
];

const CONTENT_MEMBERS: [&str; 9] = [
    "schema",
    "template_format",
    "renderer_version",
    "kind",
    "body",
    "variables",
    "partials",
    "output_contract",
    "fragments",
];

const VARIABLE_TYPES: [&str; 5] = ["string", "integer", "boolean", "json", "messages"];
const MESSAGE_ROLES: [&str; 4] = ["system", "user", "assistant", "tool"];
const TEMPLATE_ROLES: [&str; 3] = ["system", "user", "assistant"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Literal(String),
    Var { name: String, offset: usize },
    Include { name: String, offset: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("syntax_error: {syntax} at offset {offset} (line {line}, column {column})")]
pub struct SyntaxError {
    pub syntax: &'static str,
    pub offset: usize,
    pub line: usize,
    pub column: usize,
}

impl SyntaxError {
    fn at(syntax: &'static str, offset: usize, chars: &[char]) -> Self {
        let mut line = 1;
        let mut column = offset + 1;
        for (index, ch) in chars.iter().enumerate().take(offset) {
            if *ch == '\n' {
                line += 1;
                column = offset - index;
            }
        }
        Self {
            syntax,
            offset,
            line,
            column,
        }
    }
}

pub fn tokenize(template: &str) -> Result<Vec<Token>, SyntaxError> {
    let chars: Vec<char> = template.chars().collect();
    let length = chars.len();
    let mut tokens = Vec::new();
    let mut literal = String::new();
    let mut index = 0;
    while index < length {
        let ch = chars[index];
        if ch == '{' {
            if index + 1 < length && chars[index + 1] == '{' {
                literal.push('{');
                index += 2;
                continue;
            }
            let Some(close) = (index + 1..length).find(|k| chars[*k] == '}') else {
                return Err(SyntaxError::at("unclosed_brace", index, &chars));
            };
            let inner = &chars[index + 1..close];
            flush_literal(&mut literal, &mut tokens);
            if inner.first() == Some(&'>') {
                let name: String = inner[1..].iter().collect();
                if !is_name(&name) {
                    return Err(SyntaxError::at("invalid_fragment_name", index, &chars));
                }
                tokens.push(Token::Include {
                    name,
                    offset: index,
                });
            } else {
                let name = classify(inner, index, &chars)?;
                tokens.push(Token::Var {
                    name,
                    offset: index,
                });
            }
            index = close + 1;
            continue;
        }
        if ch == '}' {
            if index + 1 < length && chars[index + 1] == '}' {
                literal.push('}');
                index += 2;
                continue;
            }
            return Err(SyntaxError::at("unmatched_closing_brace", index, &chars));
        }
        literal.push(ch);
        index += 1;
    }
    flush_literal(&mut literal, &mut tokens);
    Ok(tokens)
}

fn flush_literal(literal: &mut String, tokens: &mut Vec<Token>) {
    if !literal.is_empty() {
        tokens.push(Token::Literal(std::mem::take(literal)));
    }
}

fn classify(inner: &[char], offset: usize, chars: &[char]) -> Result<String, SyntaxError> {
    let fail = |syntax| Err(SyntaxError::at(syntax, offset, chars));
    if inner.is_empty() {
        return fail("empty_placeholder");
    }
    if inner.contains(&'{') {
        return fail("nested_placeholder");
    }
    for ch in inner {
        match ch {
            ch if ch.is_ascii_alphanumeric() || *ch == '_' => {}
            '!' => return fail("conversion"),
            ':' => return fail("format_spec"),
            '.' => return fail("attribute_access"),
            '[' => return fail("index_access"),
            '\t'..='\r' | ' ' => return fail("whitespace_in_placeholder"),
            _ => return fail("invalid_placeholder_name"),
        }
    }
    if inner.iter().all(char::is_ascii_digit) {
        return fail("positional_placeholder");
    }
    if inner[0].is_ascii_digit() {
        return fail("invalid_placeholder_name");
    }
    if inner.len() > 64 {
        return fail("placeholder_name_too_long");
    }
    Ok(inner.iter().collect())
}

pub fn source(tokens: &[Token]) -> String {
    let mut out = String::new();
    for token in tokens {
        match token {
            Token::Literal(text) => push_escaped(&mut out, text),
            Token::Var { name, .. } => {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
            Token::Include { name, .. } => {
                out.push_str("{>");
                out.push_str(name);
                out.push('}');
            }
        }
    }
    out
}

fn push_escaped(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '{' => out.push_str("{{"),
            '}' => out.push_str("}}"),
            other => out.push(other),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syntax: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment: Option<String>,
}

impl Issue {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            ..Self::default()
        }
    }

    fn at(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    fn var(mut self, name: &str) -> Self {
        self.variable = Some(name.to_string());
        self
    }

    fn value_at(mut self, value_path: impl Into<String>) -> Self {
        self.value_path = Some(value_path.into());
        self
    }

    fn in_fragment(mut self, key: Option<&str>) -> Self {
        self.fragment = key.map(str::to_string);
        self
    }

    fn syntax(mut self, error: &SyntaxError) -> Self {
        self.syntax = Some(error.syntax);
        self.offset = Some(error.offset);
        self.line = Some(error.line);
        self.column = Some(error.column);
        self
    }

    fn from_ajs(error: AjsError) -> Self {
        Self::new(error.reason).value_at(error.value_path)
    }

    pub fn describe(&self) -> String {
        let mut parts = vec![self.code.to_string()];
        if let Some(syntax) = self.syntax {
            parts.push(format!("syntax {syntax}"));
        }
        if let Some(variable) = &self.variable {
            parts.push(format!("variable {variable}"));
        }
        if let Some(path) = &self.path {
            parts.push(format!("at {path}"));
        }
        if let Some(value_path) = &self.value_path {
            parts.push(format!("value {value_path}"));
        }
        if let Some(offset) = self.offset {
            parts.push(format!("offset {offset}"));
        }
        if let Some(pattern) = self.pattern {
            parts.push(format!("pattern {pattern}"));
        }
        if let Some(fragment) = &self.fragment {
            parts.push(format!("fragment {fragment}"));
        }
        parts.join(", ")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContentSecretFinding {
    pub pattern: &'static str,
    pub path: String,
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct VariableSummary {
    pub declared: Vec<String>,
    pub referenced: Vec<String>,
    pub placeholders: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VersionEntry {
    pub prompt_kind: Option<String>,
    pub content: Value,
}

pub trait FragmentSource {
    fn get(&self, prompt_id: &str, version: u32) -> Option<VersionEntry>;
}

impl FragmentSource for HashMap<String, VersionEntry> {
    fn get(&self, prompt_id: &str, version: u32) -> Option<VersionEntry> {
        HashMap::get(self, &version_key(prompt_id, version)).cloned()
    }
}

pub struct NoFragments;

impl FragmentSource for NoFragments {
    fn get(&self, _prompt_id: &str, _version: u32) -> Option<VersionEntry> {
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Expanded {
    Literal(String),
    Var {
        name: String,
        fragment_type: Option<(String, Option<Value>)>,
    },
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ValidationReport {
    pub errors: Vec<Issue>,
    pub warnings: Vec<Issue>,
    pub secret_findings: Vec<ContentSecretFinding>,
    pub variables: Option<VariableSummary>,
    pub content_digest: Option<String>,
    expanded: HashMap<String, Vec<Expanded>>,
}

const CONTENT_TOO_LARGE_REASONS: [&str; 5] = [
    "content_too_large",
    "template_too_large",
    "too_many_messages",
    "too_many_variables",
    "too_many_fragments",
];

impl ValidationReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn to_error(&self) -> Option<PromptError> {
        let first = self.errors.first()?;
        let reason = first.code;
        if !self.secret_findings.is_empty() {
            let patterns: BTreeSet<&str> = self.secret_findings.iter().map(|f| f.pattern).collect();
            let patterns: Vec<&str> = patterns.into_iter().collect();
            return Some(
                PromptError::new(
                    PROMPT_SECRET_DETECTED,
                    format!(
                        "prompt content contains a secret-shaped value ({})",
                        patterns.join(", ")
                    ),
                )
                .with_detail("findings", json!(self.secret_findings)),
            );
        }
        let code = if CONTENT_TOO_LARGE_REASONS.contains(&reason) {
            PROMPT_CONTENT_TOO_LARGE
        } else if reason == PROMPT_KIND_MISMATCH {
            PROMPT_KIND_MISMATCH
        } else {
            PROMPT_TEMPLATE_INVALID
        };
        Some(
            PromptError::new(
                code,
                format!("prompt content is invalid ({})", first.describe()),
            )
            .with_reason(reason)
            .with_offset(first.offset)
            .with_detail("errors", json!(self.errors)),
        )
    }
}

pub fn validate(content: &Value, fragments: &dyn FragmentSource) -> ValidationReport {
    Validator::new(fragments).run(content, None)
}

pub fn validate_version(
    content: &Value,
    prompt_kind: &str,
    fragments: &dyn FragmentSource,
) -> ValidationReport {
    Validator::new(fragments).run(content, Some(prompt_kind))
}

pub fn validate_version_lenient(
    content: &Value,
    prompt_kind: &str,
    fragments: &dyn FragmentSource,
) -> ValidationReport {
    let mut validator = Validator::new(fragments);
    validator.tolerate_unresolved = true;
    validator.run(content, Some(prompt_kind))
}

fn message_code_points(message: &Value) -> usize {
    match message.get("content") {
        Some(Value::String(text)) => code_points(text),
        Some(other) => code_points(&other.to_string()),
        None => 0,
    }
}

pub fn content_kind_for(prompt_kind: &str) -> Option<&'static str> {
    match prompt_kind {
        "text" | "fragment" => Some("text"),
        "chat" => Some("chat"),
        _ => None,
    }
}

struct Template<'a> {
    path: String,
    text: Option<&'a str>,
}

fn content_templates(content: &Value) -> Vec<Template<'_>> {
    match (
        content.get("kind").and_then(Value::as_str),
        content.get("body"),
    ) {
        (Some("text"), Some(body)) => vec![Template {
            path: "/body".to_string(),
            text: body.as_str(),
        }],
        (_, Some(Value::Array(entries))) => entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let entry = entry.as_object()?;
                entry.contains_key("role").then(|| Template {
                    path: format!("/body/{index}/content"),
                    text: entry.get("content").and_then(Value::as_str),
                })
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn object_of<'a>(value: &'a Value, member: &str) -> Option<&'a Map<String, Value>> {
    value.get(member).and_then(Value::as_object)
}

fn pin_key(pin: &Value) -> Option<(String, u32)> {
    let pin = pin.as_object()?;
    if pin.len() != 3 {
        return None;
    }
    let prompt_id = pin.get("prompt_id")?.as_str()?;
    let version = ajs_integer(pin.get("version")?.as_number()?).ok()?;
    let digest = pin.get("content_digest")?.as_str()?;
    if !is_prompt_id(prompt_id) || !is_sha256_digest(digest) {
        return None;
    }
    let version = u32::try_from(version)
        .ok()
        .filter(|v| (1..=MAX_VERSION).contains(v))?;
    Some((prompt_id.to_string(), version))
}

fn pin_digest(pin: &Value) -> Option<&str> {
    pin.get("content_digest").and_then(Value::as_str)
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn fragment_kind_issue(entry: &VersionEntry, path: &str, key: &str) -> Option<Issue> {
    let code = if entry
        .prompt_kind
        .as_deref()
        .is_some_and(|kind| kind != "fragment")
    {
        "fragment_not_fragment"
    } else if entry.content.get("kind").and_then(Value::as_str) != Some("text") {
        "fragment_not_text"
    } else if !object_of(&entry.content, "partials").is_some_and(Map::is_empty) {
        "fragment_has_partials"
    } else if entry.content.get("output_contract") != Some(&Value::Null) {
        "fragment_has_output_contract"
    } else {
        return None;
    };
    Some(Issue::new(code).at(path).in_fragment(Some(key)))
}

struct VariableUse {
    used: BTreeSet<String>,
    placeholders: BTreeSet<String>,
    placeholder_entries: Vec<(usize, String, bool)>,
}

struct Validator<'a> {
    source: &'a dyn FragmentSource,
    tolerate_unresolved: bool,
    errors: Vec<Issue>,
    warnings: Vec<Issue>,
}

impl<'a> Validator<'a> {
    fn new(source: &'a dyn FragmentSource) -> Self {
        Self {
            source,
            tolerate_unresolved: false,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn error(&mut self, issue: Issue) {
        self.errors.push(issue);
    }

    fn finish(self, secret_findings: Vec<ContentSecretFinding>) -> ValidationReport {
        ValidationReport {
            errors: self.errors,
            warnings: self.warnings,
            secret_findings,
            ..ValidationReport::default()
        }
    }

    fn run(mut self, content: &Value, prompt_kind: Option<&str>) -> ValidationReport {
        self.check_shape(content);
        if !self.errors.is_empty() {
            return self.finish(Vec::new());
        }
        self.check_limits(content);
        if !self.errors.is_empty() {
            return self.finish(Vec::new());
        }
        let secret_findings = scan_content_secrets(content);
        self.check_entries(content);
        if !self.errors.is_empty() {
            return self.finish(secret_findings);
        }

        let templates = content_templates(content);
        let mut token_lists: HashMap<String, Vec<Token>> = HashMap::new();
        for template in &templates {
            match tokenize(template.text.unwrap_or_default()) {
                Ok(tokens) => {
                    token_lists.insert(template.path.clone(), tokens);
                }
                Err(error) => {
                    self.error(Issue::new("syntax_error").at(&template.path).syntax(&error))
                }
            }
        }
        if !self.errors.is_empty() {
            return self.finish(secret_findings);
        }

        let fragments_map = object_of(content, "fragments");
        self.check_pins(fragments_map);
        if !self.errors.is_empty() {
            return self.finish(secret_findings);
        }

        let mut budget = 0usize;
        let mut expanded: HashMap<String, Vec<Expanded>> = HashMap::new();
        for template in &templates {
            let tokens = token_lists
                .get(&template.path)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let mut stack = Vec::new();
            let mut walk = Walk {
                stack: &mut stack,
                budget: &mut budget,
                path: &template.path,
            };
            match self.expand(tokens, fragments_map, 0, &mut walk, None) {
                Ok(list) => {
                    expanded.insert(template.path.clone(), list);
                }
                Err(issue) => {
                    self.error(*issue);
                    break;
                }
            }
        }
        if !self.errors.is_empty() {
            return self.finish(secret_findings);
        }

        let included: HashSet<&str> = token_lists
            .values()
            .flatten()
            .filter_map(|token| match token {
                Token::Include { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        if let Some(map) = fragments_map {
            for name in sorted_keys(map) {
                if !included.contains(name.as_str()) {
                    self.warnings
                        .push(Issue::new("fragment_unused").at(pointer("/fragments", name)));
                }
            }
        }

        let empty = Map::new();
        let declared = object_of(content, "variables").unwrap_or(&empty);
        let partials = object_of(content, "partials").unwrap_or(&empty);
        let VariableUse {
            used,
            placeholders,
            placeholder_entries,
        } = self.check_variable_use(content, declared, &expanded);
        if !self.errors.is_empty() {
            return self.finish(secret_findings);
        }
        for name in sorted_keys(declared) {
            if !used.contains(name.as_str()) && !placeholders.contains(name.as_str()) {
                self.warnings.push(
                    Issue::new("variable_unused")
                        .at(pointer("/variables", name))
                        .var(name),
                );
            }
        }

        self.check_required(declared, partials, &placeholder_entries);
        if !self.errors.is_empty() {
            return self.finish(secret_findings);
        }
        self.check_partials(declared, partials);
        if !self.errors.is_empty() {
            return self.finish(secret_findings);
        }
        self.check_output_contract(content);
        if !self.errors.is_empty() {
            return self.finish(secret_findings);
        }

        for finding in &secret_findings {
            self.errors.push(Issue {
                pattern: Some(finding.pattern),
                offset: Some(finding.offset),
                ..Issue::new("secret_detected").at(&finding.path)
            });
        }
        for name in sorted_keys(declared) {
            if secrets::secret_shaped_key(name) {
                self.warnings.push(
                    Issue::new("secret_shaped_variable_name")
                        .at(pointer("/variables", name))
                        .var(name),
                );
            }
        }
        if !self.errors.is_empty() {
            return self.finish(secret_findings);
        }

        if let Some(kind) = prompt_kind {
            if content.get("kind").and_then(Value::as_str) != content_kind_for(kind) {
                self.error(Issue::new(PROMPT_KIND_MISMATCH).at("/kind"));
                return self.finish(secret_findings);
            }
        }

        let mut declared_names: Vec<String> = declared.keys().cloned().collect();
        sort_utf16(&mut declared_names);
        let mut referenced: Vec<String> = used.into_iter().collect();
        sort_utf16(&mut referenced);
        let mut placeholder_names: Vec<String> = placeholders.into_iter().collect();
        sort_utf16(&mut placeholder_names);
        let mut report = self.finish(secret_findings);
        report.variables = Some(VariableSummary {
            declared: declared_names,
            referenced,
            placeholders: placeholder_names,
        });
        report.content_digest = prompt_digest(content).ok();
        report.expanded = expanded;
        report
    }

    fn check_shape(&mut self, content: &Value) {
        let Value::Object(map) = content else {
            self.error(Issue::new("invalid_field_type").at(""));
            return;
        };
        let Some(schema) = map.get("schema") else {
            self.error(Issue::new("missing_field").at("/schema"));
            return;
        };
        if schema.as_str() != Some(CONTENT_SCHEMA) {
            self.error(Issue::new("unsupported_schema").at("/schema"));
            return;
        }
        if let Err(error) = ensure_ajs(content) {
            self.error(Issue::from_ajs(error));
            return;
        }
        let mut structural = false;
        for member in CONTENT_MEMBERS {
            if !map.contains_key(member) {
                self.error(Issue::new("missing_field").at(format!("/{member}")));
                structural = true;
            }
        }
        for key in sorted_keys(map) {
            if !CONTENT_MEMBERS.contains(&key.as_str()) {
                self.error(Issue::new("unknown_field").at(pointer("", key)));
                structural = true;
            }
        }
        if structural {
            return;
        }
        if map["template_format"].as_str() != Some(TEMPLATE_FORMAT) {
            self.error(Issue::new("unsupported_template_format").at("/template_format"));
        }
        if map["renderer_version"].as_str() != Some(RENDERER_VERSION) {
            self.error(Issue::new("unsupported_renderer_version").at("/renderer_version"));
        }
        match (map["kind"].as_str(), &map["body"]) {
            (Some("text"), Value::String(_)) => {}
            (Some("text"), _) => self.error(Issue::new("invalid_body").at("/body")),
            (Some("chat"), Value::Array(entries)) if entries.is_empty() => {
                self.error(Issue::new("empty_chat").at("/body"))
            }
            (Some("chat"), Value::Array(entries)) if entries.len() > MAX_MESSAGES => {
                self.error(Issue::new("too_many_messages").at("/body"))
            }
            (Some("chat"), Value::Array(_)) => {}
            (Some("chat"), _) => self.error(Issue::new("invalid_body").at("/body")),
            _ => self.error(Issue::new("invalid_field_type").at("/kind")),
        }
        match &map["variables"] {
            Value::Object(variables) => self.check_declarations(variables),
            _ => self.error(Issue::new("invalid_field_type").at("/variables")),
        }
        if !map["partials"].is_object() {
            self.error(Issue::new("invalid_field_type").at("/partials"));
        }
        match &map["fragments"] {
            Value::Object(fragments) if fragments.len() > MAX_FRAGMENTS => {
                self.error(Issue::new("too_many_fragments").at("/fragments"))
            }
            Value::Object(_) => {}
            _ => self.error(Issue::new("invalid_field_type").at("/fragments")),
        }
    }

    fn check_declarations(&mut self, variables: &Map<String, Value>) {
        if variables.len() > MAX_VARIABLES {
            self.error(Issue::new("too_many_variables").at("/variables"));
        }
        for name in sorted_keys(variables) {
            let path = pointer("/variables", name);
            if !is_name(name) {
                self.error(Issue::new("invalid_variable_name").at(&path));
                continue;
            }
            let Value::Object(declaration) = &variables[name] else {
                self.error(Issue::new("invalid_field_type").at(&path));
                continue;
            };
            for member in ["type", "required"] {
                if !declaration.contains_key(member) {
                    self.error(Issue::new("missing_field").at(pointer(&path, member)));
                }
            }
            for member in sorted_keys(declaration) {
                if member != "type" && member != "required" {
                    self.error(Issue::new("unknown_field").at(pointer(&path, member)));
                }
            }
            if let Some(var_type) = declaration.get("type") {
                let known = var_type
                    .as_str()
                    .is_some_and(|text| VARIABLE_TYPES.contains(&text));
                if !known {
                    self.error(Issue::new("invalid_variable_type").at(pointer(&path, "type")));
                }
            }
            if declaration
                .get("required")
                .is_some_and(|value| !value.is_boolean())
            {
                self.error(Issue::new("invalid_field_type").at(pointer(&path, "required")));
            }
        }
    }

    fn check_limits(&mut self, content: &Value) {
        for template in content_templates(content) {
            if let Some(text) = template.text {
                if code_points(text) > MAX_TEMPLATE_CODE_POINTS {
                    self.error(Issue::new("template_too_large").at(template.path));
                }
            }
        }
        if canonical_json(content).len() > MAX_CONTENT_BYTES {
            self.error(Issue::new("content_too_large").at(""));
        }
    }

    fn check_entries(&mut self, content: &Value) {
        if content.get("kind").and_then(Value::as_str) != Some("chat") {
            return;
        }
        let Some(entries) = content.get("body").and_then(Value::as_array) else {
            return;
        };
        for (index, entry) in entries.iter().enumerate() {
            let path = format!("/body/{index}");
            if let Some(issue) = entry_issue(entry, &path) {
                self.error(issue);
            }
        }
    }

    fn check_pins(&mut self, fragments: Option<&Map<String, Value>>) {
        let Some(map) = fragments else {
            return;
        };
        for name in sorted_keys(map) {
            let path = pointer("/fragments", name);
            let pin = &map[name];
            let key = match pin_key(pin) {
                Some(key) if is_name(name) => key,
                _ => {
                    self.error(Issue::new("invalid_fragment_pin").at(&path));
                    continue;
                }
            };
            let ref_key = version_key(&key.0, key.1);
            let Some(entry) = self.source.get(&key.0, key.1) else {
                if self.tolerate_unresolved {
                    continue;
                }
                self.error(
                    Issue::new("fragment_not_found")
                        .at(&path)
                        .in_fragment(Some(&ref_key)),
                );
                continue;
            };
            if prompt_digest(&entry.content).ok().as_deref() != pin_digest(pin) {
                self.error(
                    Issue::new("fragment_digest_mismatch")
                        .at(&path)
                        .in_fragment(Some(&ref_key)),
                );
                continue;
            }
            if let Some(issue) = fragment_kind_issue(&entry, &path, &ref_key) {
                self.error(issue);
            }
        }
    }

    fn expand(
        &self,
        tokens: &[Token],
        fragments: Option<&Map<String, Value>>,
        depth: usize,
        walk: &mut Walk<'_>,
        origin: Option<(&str, Option<&Map<String, Value>>)>,
    ) -> Result<Vec<Expanded>, Box<Issue>> {
        let path = walk.path;
        let origin_key = origin.map(|(key, _)| key);
        let mut out = Vec::new();
        for token in tokens {
            let (name, offset) = match token {
                Token::Literal(text) => {
                    out.push(Expanded::Literal(text.clone()));
                    continue;
                }
                Token::Var { name, .. } => {
                    let fragment_type = origin.and_then(|(key, variables)| {
                        variables?
                            .get(name)
                            .map(|declaration| (key.to_string(), declaration.get("type").cloned()))
                    });
                    out.push(Expanded::Var {
                        name: name.clone(),
                        fragment_type,
                    });
                    continue;
                }
                Token::Include { name, offset } => (name, *offset),
            };
            let Some(pin) = fragments.and_then(|map| map.get(name)) else {
                let mut issue = Issue::new("fragment_not_declared")
                    .at(path)
                    .in_fragment(origin_key);
                issue.offset = Some(offset);
                return Err(Box::new(issue));
            };
            let Some((prompt_id, version)) = pin_key(pin) else {
                return Err(Box::new(
                    Issue::new("invalid_fragment_pin")
                        .at(path)
                        .in_fragment(origin_key),
                ));
            };
            let key = version_key(&prompt_id, version);
            let fail = |code| Err(Box::new(Issue::new(code).at(path).in_fragment(Some(&key))));
            if walk.stack.contains(&key) {
                return fail("fragment_cycle");
            }
            if depth + 1 > MAX_FRAGMENT_DEPTH {
                return fail("fragment_depth_exceeded");
            }
            *walk.budget += 1;
            if *walk.budget > MAX_FRAGMENT_EXPANSIONS {
                return fail("fragment_expansion_limit");
            }
            let Some(entry) = self.source.get(&prompt_id, version) else {
                if self.tolerate_unresolved {
                    continue;
                }
                return fail("fragment_not_found");
            };
            if prompt_digest(&entry.content).ok().as_deref() != pin_digest(pin) {
                return fail("fragment_digest_mismatch");
            }
            if let Some(issue) = fragment_kind_issue(&entry, path, &key) {
                return Err(Box::new(issue));
            }
            let body = entry
                .content
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let fragment_tokens = tokenize(body).map_err(|error| {
                Box::new(
                    Issue::new("syntax_error")
                        .at(path)
                        .syntax(&error)
                        .in_fragment(Some(&key)),
                )
            })?;
            walk.stack.push(key.clone());
            let inner = self.expand(
                &fragment_tokens,
                object_of(&entry.content, "fragments"),
                depth + 1,
                walk,
                Some((&key, object_of(&entry.content, "variables"))),
            );
            walk.stack.pop();
            out.extend(inner?);
        }
        let merged = merge_literals(out);
        if code_points(&expanded_source(&merged)) > MAX_EXPANDED_CODE_POINTS {
            return Err(Box::new(Issue::new("expanded_template_too_large").at(path)));
        }
        Ok(merged)
    }

    fn check_variable_use(
        &mut self,
        content: &Value,
        declared: &Map<String, Value>,
        expanded: &HashMap<String, Vec<Expanded>>,
    ) -> VariableUse {
        let mut used = BTreeSet::new();
        let mut placeholders = BTreeSet::new();
        let mut placeholder_entries = Vec::new();
        let is_text = content.get("kind").and_then(Value::as_str) == Some("text");
        if is_text {
            if let Some(tokens) = expanded.get("/body") {
                self.check_tokens(tokens, "/body", declared, &mut used);
            }
        } else if let Some(entries) = content.get("body").and_then(Value::as_array) {
            for (index, entry) in entries.iter().enumerate() {
                if entry.get("role").is_some() {
                    let path = format!("/body/{index}/content");
                    if let Some(tokens) = expanded.get(&path) {
                        self.check_tokens(tokens, &path, declared, &mut used);
                    }
                    continue;
                }
                let path = format!("/body/{index}");
                let name = entry
                    .get("placeholder")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                match declared.get(name) {
                    None => self.error(Issue::new("undeclared_variable").at(&path).var(name)),
                    Some(declaration) if declaration_type(declaration) != Some("messages") => {
                        self.error(Issue::new("placeholder_type_mismatch").at(&path).var(name))
                    }
                    Some(_) => {}
                }
                if !placeholders.insert(name.to_string()) {
                    self.error(Issue::new("duplicate_placeholder").at(&path).var(name));
                }
                let optional = entry
                    .get("optional")
                    .and_then(Value::as_bool)
                    .unwrap_or_default();
                placeholder_entries.push((index, name.to_string(), optional));
            }
        }
        if is_text {
            for name in sorted_keys(declared) {
                if declaration_type(&declared[name]) == Some("messages") {
                    self.error(
                        Issue::new("messages_outside_placeholder")
                            .at(pointer("/variables", name))
                            .var(name),
                    );
                }
            }
        }
        VariableUse {
            used,
            placeholders,
            placeholder_entries,
        }
    }

    fn check_tokens(
        &mut self,
        tokens: &[Expanded],
        path: &str,
        declared: &Map<String, Value>,
        used: &mut BTreeSet<String>,
    ) {
        for token in tokens {
            let Expanded::Var {
                name,
                fragment_type,
            } = token
            else {
                continue;
            };
            used.insert(name.clone());
            let Some(declaration) = declared.get(name) else {
                self.error(Issue::new("undeclared_variable").at(path).var(name));
                continue;
            };
            if declaration_type(declaration) == Some("messages") {
                self.error(
                    Issue::new("messages_outside_placeholder")
                        .at(path)
                        .var(name),
                );
                continue;
            }
            if let Some((key, fragment_type)) = fragment_type {
                if fragment_type.as_ref() != declaration.get("type") {
                    self.error(
                        Issue::new("fragment_variable_type_mismatch")
                            .at(path)
                            .var(name)
                            .in_fragment(Some(key)),
                    );
                }
            }
        }
    }

    fn check_required(
        &mut self,
        declared: &Map<String, Value>,
        partials: &Map<String, Value>,
        placeholder_entries: &[(usize, String, bool)],
    ) {
        for (index, name, optional) in placeholder_entries {
            let required = declared
                .get(name)
                .and_then(|declaration| declaration.get("required"))
                .and_then(Value::as_bool)
                .unwrap_or_default();
            if required == *optional {
                self.error(
                    Issue::new("placeholder_required_mismatch")
                        .at(format!("/body/{index}"))
                        .var(name),
                );
            }
        }
        for name in sorted_keys(declared) {
            let declaration = &declared[name];
            if declaration_type(declaration) == Some("messages") {
                continue;
            }
            let required = declaration
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or_default();
            let has_partial = partials.contains_key(name);
            let path = pointer("/variables", name);
            if has_partial && required {
                self.error(Issue::new("partial_required_mismatch").at(&path).var(name));
            }
            if !has_partial && !required {
                self.error(Issue::new("optional_without_partial").at(&path).var(name));
            }
        }
    }

    fn check_partials(&mut self, declared: &Map<String, Value>, partials: &Map<String, Value>) {
        for name in sorted_keys(partials) {
            let path = pointer("/partials", name);
            let value = &partials[name];
            let Some(declaration) = declared.get(name) else {
                self.error(
                    Issue::new("partial_for_unknown_variable")
                        .at(&path)
                        .var(name),
                );
                continue;
            };
            let var_type = declaration_type(declaration);
            if var_type == Some("messages") {
                self.error(
                    Issue::new("partial_for_messages_variable")
                        .at(&path)
                        .var(name),
                );
                continue;
            }
            if value.is_array() || value.is_object() {
                self.error(Issue::new("partial_not_scalar").at(&path).var(name));
                continue;
            }
            let matches = match var_type {
                Some("string") => value.is_string(),
                Some("integer") => value.is_number(),
                Some("boolean") => value.is_boolean(),
                Some("json") => true,
                _ => false,
            };
            if !matches {
                self.error(Issue::new("partial_type_mismatch").at(&path).var(name));
            }
        }
    }

    fn check_output_contract(&mut self, content: &Value) {
        let contract = content.get("output_contract").unwrap_or(&Value::Null);
        if contract.is_null() {
            return;
        }
        let valid = contract.as_object().is_some_and(|map| {
            map.len() == 2
                && map.get("type").and_then(Value::as_str) == Some("json_schema")
                && map.get("json_schema").is_some_and(|schema| {
                    schema.is_object()
                        && canonical_json(schema).len() <= MAX_OUTPUT_CONTRACT_BYTES
                        && json_depth(schema) <= MAX_OUTPUT_CONTRACT_DEPTH
                })
        });
        if !valid {
            self.error(Issue::new("output_contract_invalid").at("/output_contract"));
        }
    }
}

struct Walk<'w> {
    stack: &'w mut Vec<String>,
    budget: &'w mut usize,
    path: &'w str,
}

fn declaration_type(declaration: &Value) -> Option<&str> {
    declaration.get("type").and_then(Value::as_str)
}

fn entry_issue(entry: &Value, path: &str) -> Option<Issue> {
    let invalid = |path: String| Some(Issue::new("invalid_message_entry").at(path));
    let Value::Object(map) = entry else {
        return invalid(path.to_string());
    };
    let has_role = map.contains_key("role");
    let has_placeholder = map.contains_key("placeholder");
    if has_role && has_placeholder {
        return invalid(path.to_string());
    }
    if has_role {
        if map.len() != 2 || !map.contains_key("content") {
            return invalid(path.to_string());
        }
        let role = map["role"].as_str().unwrap_or_default();
        if !TEMPLATE_ROLES.contains(&role) {
            return Some(Issue::new("unsupported_role").at(format!("{path}/role")));
        }
        return match &map["content"] {
            Value::String(_) => None,
            Value::Array(_) => {
                Some(Issue::new("unsupported_content_block").at(format!("{path}/content")))
            }
            _ => invalid(format!("{path}/content")),
        };
    }
    if has_placeholder {
        if map.len() != 2 || !map.contains_key("optional") {
            return invalid(path.to_string());
        }
        if !map["placeholder"].as_str().is_some_and(is_name) {
            return invalid(format!("{path}/placeholder"));
        }
        if !map["optional"].is_boolean() {
            return invalid(format!("{path}/optional"));
        }
        return None;
    }
    invalid(path.to_string())
}

fn scan_content_secrets(content: &Value) -> Vec<ContentSecretFinding> {
    let mut findings = Vec::new();
    let mut push = |text: &str, path: &str| {
        for finding in secrets::scan(text) {
            findings.push(ContentSecretFinding {
                pattern: finding.pattern,
                path: path.to_string(),
                offset: finding.offset,
                length: finding.length,
            });
        }
    };
    match (
        content.get("kind").and_then(Value::as_str),
        content.get("body"),
    ) {
        (Some("text"), Some(Value::String(body))) => push(body, "/body"),
        (Some("chat"), Some(Value::Array(entries))) => {
            for (index, entry) in entries.iter().enumerate() {
                if let Some(text) = entry.get("content").and_then(Value::as_str) {
                    push(text, &format!("/body/{index}/content"));
                }
            }
        }
        _ => {}
    }
    if let Some(partials) = object_of(content, "partials") {
        for name in sorted_keys(partials) {
            if let Some(text) = partials[name].as_str() {
                push(text, &pointer("/partials", name));
            }
        }
    }
    if let Some(contract) = content
        .get("output_contract")
        .filter(|value| !value.is_null())
    {
        walk_strings(contract, "/output_contract", &mut push);
    }
    findings
}

fn walk_strings(value: &Value, path: &str, visit: &mut dyn FnMut(&str, &str)) {
    match value {
        Value::String(text) => visit(text, path),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk_strings(item, &pointer(path, &index.to_string()), visit);
            }
        }
        Value::Object(map) => {
            for key in sorted_keys(map) {
                walk_strings(&map[key], &pointer(path, key), visit);
            }
        }
        _ => {}
    }
}

fn merge_literals(tokens: Vec<Expanded>) -> Vec<Expanded> {
    let mut out: Vec<Expanded> = Vec::with_capacity(tokens.len());
    for token in tokens {
        match token {
            Expanded::Literal(text) if text.is_empty() => {}
            Expanded::Literal(text) => match out.last_mut() {
                Some(Expanded::Literal(last)) => last.push_str(&text),
                _ => out.push(Expanded::Literal(text)),
            },
            var => out.push(var),
        }
    }
    out
}

fn expanded_source(tokens: &[Expanded]) -> String {
    let mut out = String::new();
    for token in tokens {
        match token {
            Expanded::Literal(text) => push_escaped(&mut out, text),
            Expanded::Var { name, .. } => {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SecretPolicy {
    #[default]
    Off,
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenderOptions {
    pub strict: bool,
    pub history: Option<Vec<Value>>,
    pub allow_duplicate_system: bool,
    pub secret_policy: SecretPolicy,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            strict: true,
            history: None,
            allow_duplicate_system: false,
            secret_policy: SecretPolicy::Off,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rendered {
    pub kind: &'static str,
    pub text: Option<String>,
    pub messages: Option<Vec<Value>>,
    pub expanded_template: Value,
    pub rendered_document: Value,
    pub rendered_hash: String,
    pub content_digest: String,
    pub warnings: Vec<Issue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderError {
    pub errors: Vec<Issue>,
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{PROMPT_RENDER_ERROR}: {}", self.reason())
    }
}

impl std::error::Error for RenderError {}

impl RenderError {
    fn of(issue: Issue) -> Self {
        Self {
            errors: vec![issue],
        }
    }

    pub fn item(&self) -> Option<&Issue> {
        self.errors.first()
    }

    pub fn reason(&self) -> &'static str {
        self.errors
            .first()
            .map_or(PROMPT_RENDER_ERROR, |issue| issue.code)
    }
}

impl From<RenderError> for PromptError {
    fn from(error: RenderError) -> Self {
        let reason = error.reason();
        let described = error
            .item()
            .map_or_else(|| reason.to_string(), Issue::describe);
        PromptError::new(
            PROMPT_RENDER_ERROR,
            format!("prompt render failed ({described})"),
        )
        .with_reason(reason)
        .with_offset(error.item().and_then(|issue| issue.offset))
        .with_detail("errors", json!(error.errors))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Any,
    Text,
    Messages,
}

pub fn render(
    content: &Value,
    variables: &Map<String, Value>,
    fragments: &dyn FragmentSource,
    options: &RenderOptions,
) -> Result<Rendered, RenderError> {
    render_as(Method::Any, content, variables, fragments, options)
}

pub fn render_text(
    content: &Value,
    variables: &Map<String, Value>,
    fragments: &dyn FragmentSource,
    options: &RenderOptions,
) -> Result<Rendered, RenderError> {
    render_as(Method::Text, content, variables, fragments, options)
}

pub fn render_messages(
    content: &Value,
    variables: &Map<String, Value>,
    fragments: &dyn FragmentSource,
    options: &RenderOptions,
) -> Result<Rendered, RenderError> {
    render_as(Method::Messages, content, variables, fragments, options)
}

fn render_as(
    method: Method,
    content: &Value,
    variables: &Map<String, Value>,
    fragments: &dyn FragmentSource,
    options: &RenderOptions,
) -> Result<Rendered, RenderError> {
    let report = validate(content, fragments);
    if !report.errors.is_empty() {
        return Err(RenderError {
            errors: report.errors,
        });
    }
    let is_chat = content.get("kind").and_then(Value::as_str) == Some("chat");
    let mismatch = match method {
        Method::Any => false,
        Method::Text => is_chat,
        Method::Messages => !is_chat,
    };
    if mismatch {
        return Err(RenderError::of(Issue::new("kind_mismatch")));
    }

    let empty = Map::new();
    let declared = object_of(content, "variables").unwrap_or(&empty);
    let partials = object_of(content, "partials").unwrap_or(&empty);
    let mut warnings = report.warnings.clone();
    for name in sorted_keys(variables) {
        if !declared.contains_key(name) {
            if options.strict {
                return Err(RenderError::of(Issue::new("unknown_variable").var(name)));
            }
            warnings.push(Issue::new("strict_disabled").var(name));
        }
    }

    let mut values: HashMap<&str, Value> = HashMap::new();
    let empty_messages = Value::Array(Vec::new());
    for name in sorted_keys(declared) {
        let declaration = &declared[name];
        let var_type = declaration_type(declaration).unwrap_or_default();
        let required = declaration
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or_default();
        let value = if let Some(value) = variables.get(name) {
            value
        } else if let Some(value) = partials.get(name) {
            value
        } else if var_type == "messages" && !required {
            &empty_messages
        } else {
            return Err(RenderError::of(Issue::new("missing_variable").var(name)));
        };
        check_value(var_type, value, &pointer("/variables", name), name)
            .map_err(|issue| RenderError::of(*issue))?;
        values.insert(name.as_str(), value.clone());
    }

    if options.secret_policy == SecretPolicy::Error {
        for name in sorted_keys(declared) {
            let var_type = declaration_type(&declared[name]);
            if var_type != Some("string") && var_type != Some("json") {
                continue;
            }
            let mut hit: Option<Issue> = None;
            let mut visit = |text: &str, path: &str| {
                if hit.is_none() {
                    if let Some(finding) = secrets::scan(text).first() {
                        hit = Some(Issue {
                            pattern: Some(finding.pattern),
                            ..Issue::new("secret_in_variables").var(name).value_at(path)
                        });
                    }
                }
            };
            if let Some(value) = values.get(name.as_str()) {
                walk_strings(value, &pointer("/variables", name), &mut visit);
            }
            if let Some(issue) = hit {
                return Err(RenderError::of(issue));
            }
        }
    }

    let body = content.get("body").unwrap_or(&Value::Null);
    let entries: &[Value] = body.as_array().map(Vec::as_slice).unwrap_or_default();
    let has_placeholder = entries
        .iter()
        .any(|entry| entry.get("placeholder").is_some());
    if let Some(history) = &options.history {
        if !is_chat {
            return Err(RenderError::of(Issue::new("history_not_supported")));
        }
        if has_placeholder {
            return Err(RenderError::of(Issue::new("history_conflict")));
        }
        for (index, item) in history.iter().enumerate() {
            check_message_value(item, &pointer("/history", &index.to_string()), None)
                .map_err(|issue| RenderError::of(*issue))?;
        }
    }

    let render_tokens = |tokens: &[Expanded]| -> String {
        let mut out = String::new();
        for token in tokens {
            match token {
                Expanded::Literal(text) => out.push_str(text),
                Expanded::Var { name, .. } => {
                    let var_type = declared.get(name).and_then(declaration_type);
                    if let Some(value) = values.get(name.as_str()) {
                        out.push_str(&render_scalar(var_type.unwrap_or_default(), value));
                    }
                }
            }
        }
        out
    };

    let no_tokens: Vec<Expanded> = Vec::new();
    let tokens_at = |path: &str| report.expanded.get(path).unwrap_or(&no_tokens);
    let history = options.history.as_deref().unwrap_or_default();
    let mut rendered_size = 0usize;
    let (kind, text, messages, document_messages, expanded_template) = if !is_chat {
        let tokens = tokens_at("/body");
        let text = render_tokens(tokens);
        rendered_size = code_points(&text);
        (
            "text",
            Some(text),
            None,
            Value::Null,
            Value::String(expanded_source(tokens)),
        )
    } else {
        let mut messages = Vec::new();
        let mut document_messages = Vec::new();
        let mut expanded_entries = Vec::new();
        let mut system_contents: HashSet<String> = HashSet::new();
        for (index, entry) in entries.iter().enumerate() {
            if let Some(role) = entry.get("role") {
                let tokens = tokens_at(&format!("/body/{index}/content"));
                let rendered = render_tokens(tokens);
                rendered_size += code_points(&rendered);
                if role.as_str() == Some("system") {
                    system_contents.insert(rendered.clone());
                }
                messages.push(json!({ "role": role, "content": rendered }));
                document_messages.push(json!({ "role": role, "content": rendered }));
                expanded_entries.push(json!({ "role": role, "content": expanded_source(tokens) }));
            } else {
                let name = entry
                    .get("placeholder")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let items: &[Value] = values
                    .get(name)
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                rendered_size += items.iter().map(message_code_points).sum::<usize>();
                messages.extend(items.iter().cloned());
                document_messages.push(json!({ "placeholder": name, "count": items.len() }));
                expanded_entries.push(json!({
                    "placeholder": name,
                    "optional": entry.get("optional").cloned().unwrap_or(Value::Bool(false)),
                }));
            }
        }
        messages.extend(history.iter().cloned());
        if !options.allow_duplicate_system {
            let duplicates = |item: &Value| {
                item.get("role").and_then(Value::as_str) == Some("system")
                    && item
                        .get("content")
                        .and_then(Value::as_str)
                        .is_some_and(|text| system_contents.contains(text))
            };
            for entry in entries {
                let Some(name) = entry.get("placeholder").and_then(Value::as_str) else {
                    continue;
                };
                let items = values.get(name).and_then(Value::as_array);
                for (index, item) in items.into_iter().flatten().enumerate() {
                    if duplicates(item) {
                        let path = pointer(&pointer("/variables", name), &index.to_string());
                        return Err(RenderError::of(
                            Issue::new("duplicate_system_message").value_at(path),
                        ));
                    }
                }
            }
            for (index, item) in history.iter().enumerate() {
                if duplicates(item) {
                    return Err(RenderError::of(
                        Issue::new("duplicate_system_message")
                            .value_at(pointer("/history", &index.to_string())),
                    ));
                }
            }
        }
        (
            "chat",
            None,
            Some(messages),
            Value::Array(document_messages),
            Value::Array(expanded_entries),
        )
    };
    if rendered_size > MAX_RENDERED_CODE_POINTS {
        return Err(RenderError::of(Issue::new("rendered_output_too_large")));
    }

    let content_digest = report.content_digest.clone().unwrap_or_default();
    let rendered_document = json!({
        "schema": RENDERED_PROMPT_SCHEMA,
        "content_digest": content_digest,
        "kind": kind,
        "text": text,
        "messages": document_messages,
        "history_count": history.len(),
    });
    let rendered_hash = prompt_digest(&rendered_document)
        .map_err(|error| RenderError::of(Issue::from_ajs(error)))?;
    Ok(Rendered {
        kind,
        text,
        messages,
        expanded_template,
        rendered_document,
        rendered_hash,
        content_digest,
        warnings,
    })
}

fn check_value(var_type: &str, value: &Value, path: &str, name: &str) -> Result<(), Box<Issue>> {
    let issue = |code| Box::new(Issue::new(code).var(name).value_at(path));
    match var_type {
        "string" => {
            let Value::String(text) = value else {
                return Err(issue("type_mismatch"));
            };
            check_ajs_string(text, path).map_err(|error| issue(error.reason))
        }
        "integer" => {
            let Value::Number(number) = value else {
                return Err(issue("type_mismatch"));
            };
            ajs_integer(number).map(|_| ()).map_err(issue)
        }
        "boolean" => {
            if value.is_boolean() {
                Ok(())
            } else {
                Err(issue("type_mismatch"))
            }
        }
        "json" => ensure_ajs_at(value, path).map_err(|error| {
            Box::new(
                Issue::new(error.reason)
                    .var(name)
                    .value_at(error.value_path),
            )
        }),
        _ => {
            let Value::Array(items) = value else {
                return Err(issue("placeholder_not_list"));
            };
            for (index, item) in items.iter().enumerate() {
                check_message_value(item, &pointer(path, &index.to_string()), Some(name))?;
            }
            Ok(())
        }
    }
}

fn check_message_value(item: &Value, path: &str, variable: Option<&str>) -> Result<(), Box<Issue>> {
    let fail = |path: String| {
        let mut issue = Issue::new("invalid_message_value").value_at(path);
        issue.variable = variable.map(str::to_string);
        Err(Box::new(issue))
    };
    let Value::Object(map) = item else {
        return fail(path.to_string());
    };
    let (Some(role), Some(content)) = (map.get("role"), map.get("content")) else {
        return fail(path.to_string());
    };
    if !role
        .as_str()
        .is_some_and(|role| MESSAGE_ROLES.contains(&role))
    {
        return fail(format!("{path}/role"));
    }
    if !(content.is_string() || content.is_array() || content.is_null()) {
        return fail(format!("{path}/content"));
    }
    Ok(())
}

fn render_scalar(var_type: &str, value: &Value) -> String {
    match (var_type, value) {
        ("string", Value::String(text)) => text.clone(),
        ("integer", Value::Number(number)) => ajs_integer(number)
            .map(|integer| integer.to_string())
            .unwrap_or_default(),
        ("boolean", Value::Bool(flag)) => flag.to_string(),
        _ => canonical_json(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_content(body: &str) -> Value {
        json!({
            "schema": CONTENT_SCHEMA,
            "template_format": TEMPLATE_FORMAT,
            "renderer_version": RENDERER_VERSION,
            "kind": "text",
            "body": body,
            "variables": {},
            "partials": {},
            "output_contract": null,
            "fragments": {},
        })
    }

    #[test]
    fn lenient_validation_keeps_checking_after_an_unresolved_pin() {
        let digest = format!("sha256:{}", "0".repeat(64));
        let mut content = text_content("{>intro} {missing}");
        content["fragments"] = json!({
            "intro": { "prompt_id": "prm_intro", "version": 1, "content_digest": digest },
        });
        let strict = validate_version(&content, "text", &NoFragments);
        assert_eq!(strict.errors[0].code, "fragment_not_found");
        let lenient = validate_version_lenient(&content, "text", &NoFragments);
        let codes: Vec<&str> = lenient.errors.iter().map(|item| item.code).collect();
        assert_eq!(codes, ["undeclared_variable"]);
    }

    #[test]
    fn spliced_messages_count_toward_the_rendered_output_limit() {
        let content = json!({
            "schema": CONTENT_SCHEMA,
            "template_format": TEMPLATE_FORMAT,
            "renderer_version": RENDERER_VERSION,
            "kind": "chat",
            "body": [{ "role": "system", "content": "hi" }, { "placeholder": "turns", "optional": false }],
            "variables": { "turns": { "type": "messages", "required": true } },
            "partials": {},
            "output_contract": null,
            "fragments": {},
        });
        let big = "x".repeat(MAX_RENDERED_CODE_POINTS);
        let mut variables = Map::new();
        variables.insert(
            "turns".to_string(),
            json!([{ "role": "user", "content": big }]),
        );
        let error = render(
            &content,
            &variables,
            &NoFragments,
            &RenderOptions::default(),
        );
        let error = error.unwrap_err();
        assert_eq!(error.errors[0].code, "rendered_output_too_large");
    }

    #[test]
    fn every_syntax_reason_is_reachable() {
        let long_name = format!("{{{}}}", "a".repeat(65));
        let cases = [
            ("a } b", "unmatched_closing_brace"),
            ("a { b", "unclosed_brace"),
            ("{}", "empty_placeholder"),
            ("{0}", "positional_placeholder"),
            ("{ x}", "whitespace_in_placeholder"),
            ("{x.y}", "attribute_access"),
            ("{x[0]}", "index_access"),
            ("{x!r}", "conversion"),
            ("{x:>10}", "format_spec"),
            ("{x{y}}", "nested_placeholder"),
            ("{a-b}", "invalid_placeholder_name"),
            (long_name.as_str(), "placeholder_name_too_long"),
            ("{>a.b}", "invalid_fragment_name"),
        ];
        let seen: Vec<&str> = cases
            .iter()
            .map(|(template, reason)| {
                let error = tokenize(template).unwrap_err();
                assert_eq!(error.syntax, *reason, "{template}");
                error.syntax
            })
            .collect();
        assert_eq!(seen, SYNTAX_REASONS);
    }

    #[test]
    fn syntax_positions_count_code_points_and_lines() {
        let error = tokenize("\u{1f600}\r\nab {x:1}").unwrap_err();
        assert_eq!(
            (error.syntax, error.offset, error.line, error.column),
            ("format_spec", 6, 2, 4)
        );
        assert_eq!(source(&tokenize("{{{x}}}").unwrap()), "{{{x}}}");
    }

    #[test]
    fn missing_variable_fails_before_any_output() {
        let mut content = text_content("Hello {name}");
        content["variables"] = json!({ "name": { "type": "string", "required": true } });
        let error = render(
            &content,
            &Map::new(),
            &NoFragments,
            &RenderOptions::default(),
        )
        .unwrap_err();
        assert_eq!(error.reason(), "missing_variable");
        let error = PromptError::from(error);
        assert_eq!(error.code, PROMPT_RENDER_ERROR);
        assert_eq!(error.details["errors"][0]["variable"], "name");
    }

    #[test]
    fn secret_in_content_wins_over_the_first_error_code() {
        let secret = format!("sk-{}", "a1B2".repeat(6));
        let content = text_content(&format!("{secret} {{x:1}}"));
        let report = validate(&content, &NoFragments);
        assert_eq!(report.errors[0].code, "syntax_error");
        let error = report.to_error().unwrap();
        assert_eq!(error.code, PROMPT_SECRET_DETECTED);
        assert!(!error.details.to_string().contains(&secret));
        assert_eq!(error.details["findings"][0]["pattern"], "openai_key");
    }

    #[test]
    fn prompt_level_kind_must_fit_the_content_kind() {
        let content = text_content("plain");
        assert!(validate_version(&content, "fragment", &NoFragments).ok());
        let report = validate_version(&content, "chat", &NoFragments);
        assert_eq!(report.errors[0].code, PROMPT_KIND_MISMATCH);
        assert_eq!(report.to_error().unwrap().code, PROMPT_KIND_MISMATCH);
    }
}
