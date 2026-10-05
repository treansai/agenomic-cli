use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};

use agenomic_cloud_client::{AgentSelector, CloudClient, MovePreview, PromptListQuery};
use agenomic_core::{io_at, CliError, CliResult, ExitCode, Severity, ValidationIssue};
use agenomic_prompt::refs::{is_channel_name, is_slot_path};
use agenomic_prompt::{
    prompt_digest, render, validate_version, verify_content, verifying_key_from_pem,
    FragmentSource, LoadOptions, NoFragments, PromptBundle, PromptError, PromptRef, RefContext,
    RenderOptions, Rendered, VerifyingKey, VersionEntry, CONTENT_SCHEMA, PROMPT_FILE_SCHEMA,
};
use chrono::Utc;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::cli::{
    ChannelsCommand, ChannelsSub, OutputFormat, PromptsCommand, PromptsExportArgs, PromptsGetArgs,
    PromptsListArgs, PromptsPullArgs, PromptsPushArgs, PromptsRenderArgs, PromptsSub,
};
use crate::commands::{cloud_client_from_profile, print_value};

const MAX_PAGES: usize = 1000;

struct Cloud {
    client: CloudClient,
    runtime: tokio::runtime::Runtime,
}

impl Cloud {
    fn connect(profile: Option<&str>) -> CliResult<Self> {
        let client = cloud_client_from_profile(profile)?;
        let runtime =
            tokio::runtime::Runtime::new().map_err(|e| CliError::Internal(format!("{e}")))?;
        Ok(Self { client, runtime })
    }

    fn block<T>(&self, future: impl Future<Output = CliResult<T>>) -> CliResult<T> {
        self.runtime.block_on(future)
    }

    fn workspace_id(&self) -> CliResult<Uuid> {
        let whoami = self.block(self.client.whoami())?;
        Uuid::parse_str(&whoami.org_id).map_err(|_| {
            CliError::Network(format!(
                "whoami returned an invalid org id {}",
                whoami.org_id
            ))
        })
    }
}

pub fn cmd_prompts(
    args: &PromptsCommand,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    match &args.command {
        PromptsSub::List(list) => prompts_list(list, format, profile),
        PromptsSub::Get(get) => prompts_get(get, format, profile),
        PromptsSub::Push(push) => prompts_push(push, format, profile),
        PromptsSub::Pull(pull) => prompts_pull(pull, format, profile),
        PromptsSub::Render(render) => prompts_render(render, format, profile),
        PromptsSub::Export(export) => prompts_export(export, format, profile),
    }
}

pub fn cmd_channels(
    args: &ChannelsCommand,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    match &args.command {
        ChannelsSub::List { agent } => channels_list(agent, format, profile),
        ChannelsSub::History {
            agent,
            channel,
            after,
            limit,
        } => channels_history(agent, channel, *after, *limit, format, profile),
        ChannelsSub::Promote {
            agent,
            channel,
            release,
            web_url,
        } => {
            let release_id = normalize_uuid(release, "--release")?;
            channels_hand_off(
                agent,
                channel,
                MovePreview::Promote { release_id },
                web_url.as_deref(),
                format,
                profile,
            )
        }
        ChannelsSub::Rollback {
            agent,
            channel,
            to_release,
            web_url,
        } => {
            let to_release_id = to_release
                .as_deref()
                .map(|release| normalize_uuid(release, "--to-release"))
                .transpose()?;
            channels_hand_off(
                agent,
                channel,
                MovePreview::Rollback { to_release_id },
                web_url.as_deref(),
                format,
                profile,
            )
        }
    }
}

fn issue(code: &str, message: impl Into<String>, path: Option<String>) -> ValidationIssue {
    ValidationIssue {
        code: format!("agenomic::prompts::{code}"),
        severity: Severity::High,
        message: message.into(),
        path,
        hint: None,
        doc: None,
    }
}

fn validation_failed(issues: Vec<ValidationIssue>) -> CliError {
    for item in &issues {
        match &item.path {
            Some(path) => eprintln!("{}: {} ({path})", item.code, item.message),
            None => eprintln!("{}: {}", item.code, item.message),
        }
    }
    CliError::ValidationFailed { reports: issues }
}

fn usage(code: &str, message: impl Into<String>) -> CliError {
    validation_failed(vec![issue(code, message, None)])
}

fn detail_text(error: &PromptError, member: &str) -> String {
    match error.details.get(member) {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Null) | None => "<none>".to_string(),
        Some(other) => other.to_string(),
    }
}

fn prompt_failure(error: PromptError) -> CliError {
    if error.is_integrity() {
        eprintln!("{}: {}", error.code, error.message);
        return CliError::HashMismatch {
            expected: detail_text(&error, "expected"),
            actual: detail_text(&error, "actual"),
        };
    }
    if error.is_authenticity() {
        return CliError::AttestationVerificationFailed(format!(
            "{}: {}",
            error.code, error.message
        ));
    }
    let items: Vec<ValidationIssue> = error
        .details
        .get("errors")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let code = item
                        .get("code")
                        .and_then(Value::as_str)
                        .unwrap_or(error.code);
                    let path = item
                        .get("path")
                        .or_else(|| item.get("value_path"))
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    issue(
                        code,
                        format!("{} ({})", error.code, describe_item(item)),
                        path,
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    if items.is_empty() {
        let path = error
            .details
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_string);
        return validation_failed(vec![issue(error.code, error.message, path)]);
    }
    validation_failed(items)
}

fn describe_item(item: &Value) -> String {
    let Some(map) = item.as_object() else {
        return item.to_string();
    };
    map.iter()
        .map(|(key, value)| match value {
            Value::String(text) => format!("{key} {text}"),
            other => format!("{key} {other}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_reference(text: &str, context: RefContext) -> CliResult<PromptRef> {
    let reference =
        PromptRef::parse(text).map_err(|error| prompt_failure(PromptError::from(error)))?;
    reference
        .require(context, None)
        .map_err(|error| prompt_failure(PromptError::from(error)))?;
    Ok(reference)
}

fn normalize_uuid(text: &str, flag: &str) -> CliResult<String> {
    Uuid::parse_str(text)
        .map(|id| id.to_string())
        .map_err(|_| usage("invalid_uuid", format!("{flag} must be a uuid, got {text}")))
}

fn checked_channel(name: &str) -> CliResult<&str> {
    if is_channel_name(name) {
        Ok(name)
    } else {
        Err(usage(
            "channel_name_invalid",
            format!("channel names match ^[a-z][a-z0-9-]{{0,31}}$, got {name}"),
        ))
    }
}

fn read_json_file(path: &Path) -> CliResult<Value> {
    let bytes = std::fs::read(path).map_err(|e| io_at(path, e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| usage("invalid_json", format!("{}: {e}", path.display())))
}

fn write_json_file(path: &Path, value: &Value) -> CliResult<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|e| io_at(parent, e))?;
    }
    let mut text =
        serde_json::to_string_pretty(value).map_err(|e| CliError::Internal(format!("{e}")))?;
    text.push('\n');
    std::fs::write(path, text).map_err(|e| io_at(path, e))
}

fn check_schema(kind: agenomic_spec::SchemaKind, document: &Value, label: &str) -> CliResult<()> {
    let validator = agenomic_spec::validator(kind)?;
    if let Err(errors) = validator.validate(document) {
        let issues: Vec<ValidationIssue> = errors
            .map(|error| {
                issue(
                    "schema",
                    error.to_string(),
                    Some(format!("{label}{}", error.instance_path)),
                )
            })
            .collect();
        return Err(validation_failed(issues));
    }
    Ok(())
}

fn version_number(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
        .filter(|number| *number > 0)
}

fn text_of<'a>(value: &'a Value, member: &str) -> CliResult<&'a str> {
    value.get(member).and_then(Value::as_str).ok_or_else(|| {
        CliError::Network(format!("the cloud response has no string member {member}"))
    })
}

fn verify_downloaded(document: &Value) -> CliResult<(String, u32)> {
    let prompt_id = text_of(document, "prompt_id")?.to_string();
    let version = document
        .get("version")
        .and_then(version_number)
        .ok_or_else(|| CliError::Network("the cloud response has no version number".into()))?;
    let expected = text_of(document, "content_digest")?;
    let content = document.get("content").unwrap_or(&Value::Null);
    verify_content(&prompt_id, version, content, expected).map_err(prompt_failure)?;
    Ok((prompt_id, version))
}

struct Downloaded {
    prompt: Value,
    version: Value,
    fragments: HashMap<String, VersionEntry>,
}

impl Downloaded {
    fn prompt_id(&self) -> &str {
        self.version
            .get("prompt_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    fn version_number(&self) -> u32 {
        self.version
            .get("version")
            .and_then(version_number)
            .unwrap_or_default()
    }

    fn content(&self) -> &Value {
        self.version.get("content").unwrap_or(&Value::Null)
    }
}

fn select_version(cloud: &Cloud, reference: &PromptRef, detail: &Value) -> CliResult<u32> {
    match reference {
        PromptRef::PromptId { prompt_id } => detail
            .get("prompt")
            .and_then(|prompt| prompt.get("latest_version"))
            .and_then(version_number)
            .ok_or_else(|| {
                usage(
                    "prompt_has_no_version",
                    format!("{prompt_id} has no published version yet"),
                )
            }),
        PromptRef::Version { version, .. } | PromptRef::Uri { version, .. } => Ok(*version),
        PromptRef::Alias { prompt_id, .. } => {
            let resolved = cloud.block(cloud.client.resolve_prompt_ref(&reference.to_string()))?;
            if resolved.get("prompt_id").and_then(Value::as_str) != Some(prompt_id.as_str()) {
                return Err(CliError::Network(
                    "the alias resolved to another prompt".to_string(),
                ));
            }
            resolved
                .get("version")
                .and_then(version_number)
                .ok_or_else(|| CliError::Network("the alias resolution has no version".into()))
        }
    }
}

fn download(cloud: &Cloud, reference: &PromptRef) -> CliResult<Downloaded> {
    if let PromptRef::Uri { .. } = reference {
        let workspace = cloud.workspace_id()?;
        reference
            .require(RefContext::Management, Some(workspace))
            .map_err(|error| prompt_failure(PromptError::from(error)))?;
    }
    let prompt_id = reference.prompt_id();
    let detail = cloud.block(cloud.client.get_prompt(prompt_id))?;
    let version = select_version(cloud, reference, &detail)?;
    let response = cloud.block(cloud.client.get_prompt_version(prompt_id, version, true))?;
    let version_doc = response.get("version").cloned().unwrap_or(Value::Null);
    let (returned_id, returned_version) = verify_downloaded(&version_doc)?;
    if returned_id != prompt_id || returned_version != version {
        return Err(CliError::Network(format!(
            "asked for {prompt_id}:{version}, the cloud returned {returned_id}:{returned_version}"
        )));
    }
    let mut fragments = HashMap::new();
    for fragment in response
        .get("fragments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (fragment_id, fragment_version) = verify_downloaded(fragment)?;
        fragments.insert(
            format!("{fragment_id}:{fragment_version}"),
            VersionEntry {
                prompt_kind: None,
                content: fragment.get("content").cloned().unwrap_or(Value::Null),
            },
        );
    }
    Ok(Downloaded {
        prompt: detail.get("prompt").cloned().unwrap_or(Value::Null),
        version: version_doc,
        fragments,
    })
}

fn prompt_kind_of(prompt: &Value, content: &Value) -> String {
    prompt
        .get("kind")
        .and_then(Value::as_str)
        .or_else(|| content.get("kind").and_then(Value::as_str))
        .unwrap_or("text")
        .to_string()
}

fn check_usable(downloaded: &Downloaded) -> CliResult<()> {
    let kind = prompt_kind_of(&downloaded.prompt, downloaded.content());
    let report = validate_version(downloaded.content(), &kind, &downloaded.fragments);
    match report.to_error() {
        Some(error) => Err(prompt_failure(error)),
        None => Ok(()),
    }
}

fn prompt_file(prompt: &Value, version: &Value) -> Value {
    let mut file = Map::new();
    file.insert("schema".into(), json!(PROMPT_FILE_SCHEMA));
    file.insert(
        "prompt_id".into(),
        version.get("prompt_id").cloned().unwrap_or(Value::Null),
    );
    if let Some(name) = prompt
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
    {
        file.insert("name".into(), json!(name));
    }
    if let Some(description) = prompt.get("description").filter(|value| value.is_string()) {
        file.insert("description".into(), description.clone());
    }
    if let Some(tags) = prompt.get("tags").filter(|value| value.is_array()) {
        file.insert("tags".into(), tags.clone());
    }
    let content = version.get("content").cloned().unwrap_or(Value::Null);
    file.insert("kind".into(), json!(prompt_kind_of(prompt, &content)));
    file.insert("content".into(), content);
    file.insert(
        "parent_version".into(),
        version
            .get("parent_version")
            .cloned()
            .unwrap_or(Value::Null),
    );
    if let Some(message) = version
        .get("change_message")
        .filter(|value| value.is_string())
    {
        file.insert("change_message".into(), message.clone());
    }
    file.insert(
        "version".into(),
        version.get("version").cloned().unwrap_or(Value::Null),
    );
    file.insert(
        "content_digest".into(),
        version
            .get("content_digest")
            .cloned()
            .unwrap_or(Value::Null),
    );
    Value::Object(file)
}

fn prompts_list(
    args: &PromptsListArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let cloud = Cloud::connect(profile)?;
    let page = cloud.block(cloud.client.list_prompts(&PromptListQuery {
        query: args.query.clone(),
        tags: args.tags.clone(),
        limit: args.limit,
        cursor: args.cursor.clone(),
    }))?;
    if format != OutputFormat::Human {
        print_value(&page, format)?;
        return Ok(ExitCode::Success);
    }
    let rows: Vec<Vec<String>> = page
        .get("prompts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|prompt| {
            vec![
                cell(prompt.get("prompt_id")),
                cell(prompt.get("kind")),
                cell(prompt.get("latest_version")),
                cell(prompt.get("status")),
                cell(prompt.get("name")),
            ]
        })
        .collect();
    print_table(&["PROMPT ID", "KIND", "LATEST", "STATUS", "NAME"], &rows);
    if let Some(cursor) = page.get("next_cursor").and_then(Value::as_str) {
        println!("next page: --cursor {cursor}");
    }
    Ok(ExitCode::Success)
}

fn prompts_get(
    args: &PromptsGetArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let reference = parse_reference(&args.reference, RefContext::Management)?;
    let cloud = Cloud::connect(profile)?;
    let downloaded = download(&cloud, &reference)?;
    check_usable(&downloaded)?;
    let file = prompt_file(&downloaded.prompt, &downloaded.version);
    let Some(output) = &args.output else {
        print_value(&file, OutputFormat::JsonPretty)?;
        return Ok(ExitCode::Success);
    };
    write_json_file(output, &file)?;
    report_written(
        &[written(
            downloaded.prompt_id(),
            downloaded.version_number(),
            &file,
            output,
        )],
        format,
    )?;
    Ok(ExitCode::Success)
}

fn written(prompt_id: &str, version: u32, file: &Value, path: &Path) -> Value {
    json!({
        "ref": format!("{prompt_id}:{version}"),
        "content_digest": file.get("content_digest").cloned().unwrap_or(Value::Null),
        "path": path.display().to_string(),
    })
}

fn report_written(entries: &[Value], format: OutputFormat) -> CliResult<()> {
    if format != OutputFormat::Human {
        return print_value(&json!({ "written": entries }), format);
    }
    for entry in entries {
        println!(
            "wrote {} ({}) to {}",
            cell(entry.get("ref")),
            cell(entry.get("content_digest")),
            cell(entry.get("path"))
        );
    }
    Ok(())
}

fn pulled_path(dir: &Path, prompt_id: &str, version: u32) -> PathBuf {
    dir.join(prompt_id).join(format!("{version}.prompt.json"))
}

fn prompts_pull(
    args: &PromptsPullArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let reference = parse_reference(&args.reference, RefContext::Management)?;
    if args.all && !matches!(reference, PromptRef::PromptId { .. }) {
        return Err(usage(
            "pull_all_needs_prompt_id",
            "--all takes a bare prompt id such as prm_planner",
        ));
    }
    let cloud = Cloud::connect(profile)?;
    if !args.all {
        let downloaded = download(&cloud, &reference)?;
        check_usable(&downloaded)?;
        let file = prompt_file(&downloaded.prompt, &downloaded.version);
        let path = pulled_path(
            &args.dir,
            downloaded.prompt_id(),
            downloaded.version_number(),
        );
        write_json_file(&path, &file)?;
        report_written(
            &[written(
                downloaded.prompt_id(),
                downloaded.version_number(),
                &file,
                &path,
            )],
            format,
        )?;
        return Ok(ExitCode::Success);
    }
    let prompt_id = reference.prompt_id();
    let detail = cloud.block(cloud.client.get_prompt(prompt_id))?;
    let prompt = detail.get("prompt").cloned().unwrap_or(Value::Null);
    let mut cursor: Option<String> = None;
    let mut entries = Vec::new();
    for _ in 0..MAX_PAGES {
        let page = cloud.block(cloud.client.list_prompt_versions(
            prompt_id,
            true,
            cursor.as_deref(),
        ))?;
        for version in page
            .get("versions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (returned_id, number) = verify_downloaded(version)?;
            if returned_id != prompt_id {
                return Err(CliError::Network(format!(
                    "the version list of {prompt_id} returned {returned_id}"
                )));
            }
            let file = prompt_file(&prompt, version);
            let path = pulled_path(&args.dir, prompt_id, number);
            write_json_file(&path, &file)?;
            entries.push(written(prompt_id, number, &file, &path));
        }
        cursor = page
            .get("next_cursor")
            .and_then(Value::as_str)
            .map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }
    report_written(&entries, format)?;
    Ok(ExitCode::Success)
}

struct LocalFile {
    document: Value,
    prompt_id: String,
    kind: String,
}

impl LocalFile {
    fn content(&self) -> &Value {
        self.document.get("content").unwrap_or(&Value::Null)
    }
}

fn load_prompt_file(path: &Path) -> CliResult<LocalFile> {
    checked_prompt_file(path, read_json_file(path)?)
}

fn checked_prompt_file(path: &Path, document: Value) -> CliResult<LocalFile> {
    if document.get("schema").and_then(Value::as_str) != Some(PROMPT_FILE_SCHEMA) {
        return Err(usage(
            "unsupported_schema",
            format!("{} is not an {PROMPT_FILE_SCHEMA} document", path.display()),
        ));
    }
    check_schema(
        agenomic_spec::SchemaKind::PromptFile,
        &document,
        &path.display().to_string(),
    )?;
    let content = document.get("content").unwrap_or(&Value::Null);
    if let Some(expected) = document.get("content_digest").and_then(Value::as_str) {
        let prompt_id = document
            .get("prompt_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let version = document
            .get("version")
            .map(Value::to_string)
            .unwrap_or_default();
        verify_content(prompt_id, version, content, expected).map_err(prompt_failure)?;
    }
    Ok(LocalFile {
        prompt_id: text_of(&document, "prompt_id")?.to_string(),
        kind: text_of(&document, "kind")?.to_string(),
        document,
    })
}

fn offline_check(file: &LocalFile) -> CliResult<String> {
    let report = validate_version(file.content(), &file.kind, &NoFragments);
    let unresolved_only = report
        .errors
        .iter()
        .all(|item| item.code == "fragment_not_found");
    if !unresolved_only || !report.secret_findings.is_empty() {
        if let Some(error) = report.to_error() {
            return Err(prompt_failure(error));
        }
    }
    for warning in &report.warnings {
        eprintln!("warning: {}", warning.describe());
    }
    prompt_digest(file.content()).map_err(|error| {
        usage(
            error.reason,
            format!("content is outside the JSON subset at {}", error.value_path),
        )
    })
}

fn prompts_push(
    args: &PromptsPushArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let file = load_prompt_file(&args.file)?;
    let digest = offline_check(&file)?;
    if args.dry_run {
        let summary = json!({
            "prompt_id": file.prompt_id,
            "content_digest": digest,
            "dry_run": true,
        });
        if format == OutputFormat::Human {
            println!("valid: {} {digest} (dry run, nothing sent)", file.prompt_id);
        } else {
            print_value(&summary, format)?;
        }
        return Ok(ExitCode::Success);
    }
    let change_message = args.message.clone().or_else(|| {
        file.document
            .get("change_message")
            .and_then(Value::as_str)
            .map(str::to_string)
    });
    let mut body = json!({
        "content": file.content(),
        "parent_version": file.document.get("parent_version").cloned().unwrap_or(Value::Null),
        "source": "api",
    });
    if let Some(message) = &change_message {
        body["change_message"] = json!(message);
    }
    let cloud = Cloud::connect(profile)?;
    let published = match cloud.block(cloud.client.publish_prompt_version(&file.prompt_id, &body)) {
        Err(CliError::CloudRefused { code, .. }) if code == "prompt_not_found" => {
            let mut create = json!({
                "prompt_id": file.prompt_id,
                "kind": file.kind,
                "name": file
                    .document
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(&file.prompt_id),
            });
            for member in ["description", "tags"] {
                if let Some(value) = file.document.get(member) {
                    create[member] = value.clone();
                }
            }
            match cloud.block(cloud.client.create_prompt(&create)) {
                Ok(_) => {}
                Err(CliError::CloudRefused { code, .. }) if code == "prompt_id_taken" => {}
                Err(error) => return Err(error),
            }
            cloud.block(cloud.client.publish_prompt_version(&file.prompt_id, &body))?
        }
        other => other?,
    };
    let (_, response) = published;
    let version = response.get("version").cloned().unwrap_or(Value::Null);
    let server_digest = text_of(&version, "content_digest")?;
    if server_digest != digest {
        eprintln!(
            "hint: the cloud computed another content digest for the same content; the CLI and the server disagree on canonical JSON, report it with the prompt file"
        );
        return Err(CliError::HashMismatch {
            expected: server_digest.to_string(),
            actual: digest,
        });
    }
    let number = version
        .get("version")
        .and_then(version_number)
        .unwrap_or_default();
    let created = response
        .get("created")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let summary = json!({
        "ref": format!("{}:{number}", file.prompt_id),
        "prompt_id": file.prompt_id,
        "version": number,
        "content_digest": digest,
        "created": created,
    });
    if format == OutputFormat::Human {
        let state = if created {
            "published"
        } else {
            "already published"
        };
        println!("{state}: {}:{number} {digest}", file.prompt_id);
    } else {
        print_value(&summary, format)?;
    }
    Ok(ExitCode::Success)
}

fn collect_variables(args: &PromptsRenderArgs) -> CliResult<Map<String, Value>> {
    let mut variables = match &args.vars_file {
        Some(path) => match read_json_file(path)? {
            Value::Object(map) => map,
            _ => {
                return Err(usage(
                    "invalid_vars",
                    format!("{} must hold a JSON object", path.display()),
                ))
            }
        },
        None => Map::new(),
    };
    for pair in &args.vars {
        let Some((name, value)) = pair.split_once('=') else {
            return Err(usage(
                "invalid_var",
                format!("--var takes NAME=VALUE, got {pair}"),
            ));
        };
        variables.insert(name.to_string(), json!(value));
    }
    Ok(variables)
}

fn read_trust_key(path: &Path) -> CliResult<VerifyingKey> {
    let pem = std::fs::read_to_string(path).map_err(|e| io_at(path, e))?;
    verifying_key_from_pem(&pem).ok_or_else(|| {
        CliError::AttestationVerificationFailed(format!(
            "{} is not an ed25519 public key",
            path.display()
        ))
    })
}

struct RenderSource {
    content: Value,
    fragments: Box<dyn FragmentSource>,
    server_source: Value,
}

fn bundle_source(args: &PromptsRenderArgs, bundle_path: &Path) -> CliResult<RenderSource> {
    let required = |value: &Option<String>, flag: &str| {
        value
            .clone()
            .ok_or_else(|| usage("missing_argument", format!("--bundle needs {flag}")))
    };
    let slot = required(&args.slot, "--slot")?;
    if !is_slot_path(&slot) {
        return Err(usage(
            "invalid_slot_path",
            format!("{slot} is not a slot path"),
        ));
    }
    let workspace = normalize_uuid(&required(&args.workspace, "--workspace")?, "--workspace")?;
    let agent = normalize_uuid(&required(&args.agent, "--agent")?, "--agent")?;
    let trust_key = args.trust_key.as_deref().map(read_trust_key).transpose()?;
    let document = read_json_file(bundle_path)?;
    let options = LoadOptions {
        expected_workspace_id: &workspace,
        expected_agent_id: &agent,
        expected_bundle_digest: args.expect_bundle_digest.as_deref(),
        expected_manifest_digest: None,
        trust_key: trust_key.as_ref(),
        allow_ungoverned_bundle: false,
        now: Utc::now(),
    };
    let bundle = PromptBundle::load(document, &options).map_err(prompt_failure)?;
    let (_, _, entry) = bundle.slot(&slot).map_err(prompt_failure)?;
    Ok(RenderSource {
        server_source: json!({ "content": entry.content }),
        content: entry.content,
        fragments: Box::new(bundle),
    })
}

fn file_source(path: &Path) -> CliResult<RenderSource> {
    let document = read_json_file(path)?;
    let content = match document.get("schema").and_then(Value::as_str) {
        Some(PROMPT_FILE_SCHEMA) => checked_prompt_file(path, document)?.content().clone(),
        Some(CONTENT_SCHEMA) => document,
        _ => {
            return Err(usage(
                "unsupported_schema",
                format!(
                    "{} is neither an {PROMPT_FILE_SCHEMA} nor an {CONTENT_SCHEMA} document",
                    path.display()
                ),
            ))
        }
    };
    Ok(RenderSource {
        server_source: json!({ "content": content }),
        content,
        fragments: Box::new(NoFragments),
    })
}

fn reference_source(cloud: &Cloud, text: &str) -> CliResult<RenderSource> {
    let reference = parse_reference(text, RefContext::Execution)?;
    let downloaded = download(cloud, &reference)?;
    let pinned = format!("{}:{}", downloaded.prompt_id(), downloaded.version_number());
    Ok(RenderSource {
        content: downloaded.content().clone(),
        fragments: Box::new(downloaded.fragments),
        server_source: json!({ "ref": pinned }),
    })
}

fn rendered_output(rendered: &Rendered) -> Value {
    json!({
        "kind": rendered.kind,
        "text": rendered.text,
        "messages": rendered.messages,
        "content_digest": rendered.content_digest,
        "rendered_hash": rendered.rendered_hash,
        "warnings": rendered.warnings,
    })
}

fn prompts_render(
    args: &PromptsRenderArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let variables = collect_variables(args)?;
    let mut cloud: Option<Cloud> = None;
    let source = match (&args.bundle, &args.target) {
        (Some(bundle), _) => bundle_source(args, bundle)?,
        (None, Some(target)) if Path::new(target).is_file() => file_source(Path::new(target))?,
        (None, Some(target)) => {
            let connected = Cloud::connect(profile)?;
            let source = reference_source(&connected, target)?;
            cloud = Some(connected);
            source
        }
        (None, None) => {
            return Err(usage(
                "missing_argument",
                "pass a prompt file, a reference or --bundle",
            ))
        }
    };
    let rendered = render(
        &source.content,
        &variables,
        source.fragments.as_ref(),
        &RenderOptions::default(),
    )
    .map_err(|error| prompt_failure(PromptError::from(error)))?;
    let mut output = rendered_output(&rendered);
    if args.server {
        let cloud = match cloud {
            Some(cloud) => cloud,
            None => Cloud::connect(profile)?,
        };
        let body = json!({
            "source": source.server_source,
            "variables": variables,
            "strict": true,
        });
        let server = cloud.block(cloud.client.render_prompt(&body))?;
        let server_hash = server
            .get("rendered_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if server_hash != rendered.rendered_hash {
            eprintln!(
                "hint: the local renderer and the server disagree for renderer_version 1; report the prompt and variables"
            );
            return Err(CliError::HashMismatch {
                expected: server_hash,
                actual: rendered.rendered_hash,
            });
        }
        output["server"] = json!({ "rendered_hash": server_hash, "matches": true });
    }
    for warning in &rendered.warnings {
        eprintln!("warning: {}", warning.describe());
    }
    if format != OutputFormat::Human {
        print_value(&output, format)?;
    } else if let Some(text) = &rendered.text {
        println!("{text}");
    } else {
        print_value(
            &json!({
                "kind": rendered.kind,
                "messages": rendered.messages,
                "content_digest": rendered.content_digest,
                "rendered_hash": rendered.rendered_hash,
            }),
            OutputFormat::JsonPretty,
        )?;
    }
    if args.server && format == OutputFormat::Human {
        eprintln!("server render matches ({})", rendered.rendered_hash);
    }
    Ok(ExitCode::Success)
}

fn prompts_export(
    args: &PromptsExportArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let agent = normalize_uuid(&args.agent, "--agent")?;
    let selector = match (&args.channel, &args.release) {
        (Some(channel), None) => AgentSelector::Channel(checked_channel(channel)?.to_string()),
        (None, Some(release)) => AgentSelector::Release(normalize_uuid(release, "--release")?),
        _ => {
            return Err(usage(
                "agent_selector_required",
                "pass exactly one of --channel and --release",
            ))
        }
    };
    let trust_key = args.trust_key.as_deref().map(read_trust_key).transpose()?;
    let cloud = Cloud::connect(profile)?;
    let workspace = cloud.workspace_id()?.to_string();
    let (document, bytes) = cloud.block(cloud.client.export_prompt_bundle(
        &agent,
        &selector,
        args.expires_in_days,
    ))?;
    let bundle =
        PromptBundle::verify_exported(document, &workspace, &agent, trust_key.as_ref(), Utc::now())
            .map_err(prompt_failure)?;
    if let Some(parent) = args
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|e| io_at(parent, e))?;
    }
    std::fs::write(&args.output, &bytes).map_err(|e| io_at(&args.output, e))?;
    let key_id = bundle
        .member("issuer")
        .get("key_id")
        .cloned()
        .unwrap_or(Value::Null);
    let summary = json!({
        "path": args.output.display().to_string(),
        "prompt_bundle_digest": bundle.prompt_bundle_digest(),
        "prompt_manifest_digest": bundle.prompt_manifest_digest(),
        "expires_at": bundle.member("expires_at"),
        "governance": bundle.member("governance"),
        "key_id": key_id,
        "signature_verified": bundle.signature_verified(),
    });
    if format != OutputFormat::Human {
        print_value(&summary, format)?;
        return Ok(ExitCode::Success);
    }
    println!("wrote {}", args.output.display());
    println!("prompt_bundle_digest: {}", bundle.prompt_bundle_digest());
    println!(
        "prompt_manifest_digest: {}",
        bundle.prompt_manifest_digest()
    );
    println!("expires_at: {}", cell(summary.get("expires_at")));
    println!("governance: {}", compact(&summary["governance"]));
    if bundle.signature_verified() {
        println!("signature: verified (key {})", cell(summary.get("key_id")));
    } else {
        println!(
            "signature: not verified (pass --trust-key to verify key {})",
            cell(summary.get("key_id"))
        );
    }
    println!(
        "pin it as expected_bundle_digest (Python) or expectedBundleDigest (TypeScript): {}",
        bundle.prompt_bundle_digest()
    );
    Ok(ExitCode::Success)
}

fn channels_list(agent: &str, format: OutputFormat, profile: Option<&str>) -> CliResult<ExitCode> {
    let agent = normalize_uuid(agent, "--agent")?;
    let cloud = Cloud::connect(profile)?;
    let response = cloud.block(cloud.client.list_channels(&agent))?;
    if format != OutputFormat::Human {
        print_value(&response, format)?;
        return Ok(ExitCode::Success);
    }
    let rows: Vec<Vec<String>> = response
        .get("channels")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|channel| {
            let release = channel.get("release").unwrap_or(&Value::Null);
            vec![
                cell(channel.get("name")),
                cell(release.get("name")),
                cell(channel.get("release_id")),
                cell(channel.get("generation")),
                cell(channel.get("protected")),
            ]
        })
        .collect();
    print_table(
        &[
            "CHANNEL",
            "RELEASE",
            "RELEASE ID",
            "GENERATION",
            "PROTECTED",
        ],
        &rows,
    );
    Ok(ExitCode::Success)
}

fn actor(value: Option<&Value>) -> String {
    let value = value.unwrap_or(&Value::Null);
    if let Some(user) = value.get("user_id").and_then(Value::as_str) {
        return format!("user:{user}");
    }
    if let Some(key) = value.get("api_key_id").and_then(Value::as_str) {
        return format!("key:{key}");
    }
    "-".to_string()
}

fn channels_history(
    agent: &str,
    channel: &str,
    after: Option<i64>,
    limit: Option<u32>,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let agent = normalize_uuid(agent, "--agent")?;
    let channel = checked_channel(channel)?;
    let cloud = Cloud::connect(profile)?;
    let response = cloud.block(cloud.client.channel_history(&agent, channel, after, limit))?;
    if format != OutputFormat::Human {
        print_value(&response, format)?;
        return Ok(ExitCode::Success);
    }
    let events: Vec<&Value> = response
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    let rows: Vec<Vec<String>> = events
        .iter()
        .map(|event| {
            vec![
                cell(event.get("generation")),
                cell(event.get("action")),
                cell(event.get("from_release_id")),
                cell(event.get("to_release_id")),
                actor(event.get("actor")),
                cell(event.get("reason")),
            ]
        })
        .collect();
    print_table(
        &["GENERATION", "ACTION", "FROM", "TO", "ACTOR", "REASON"],
        &rows,
    );
    if let Some(next) = response.get("next_after").and_then(Value::as_i64) {
        if !events.is_empty() {
            println!("next page: --after {next}");
        }
    }
    Ok(ExitCode::Success)
}

fn absolute_move_url(move_url: Option<&str>, web_url: Option<&str>) -> Option<String> {
    let move_url = move_url?;
    if move_url.starts_with("https://") || move_url.starts_with("http://") {
        return Some(move_url.to_string());
    }
    match web_url {
        Some(base) => Some(format!(
            "{}/{}",
            base.trim_end_matches('/'),
            move_url.trim_start_matches('/')
        )),
        None => Some(move_url.to_string()),
    }
}

fn release_line(release: Option<&Value>) -> String {
    let Some(release) = release.filter(|value| value.is_object()) else {
        return "none".to_string();
    };
    format!(
        "{} {} ({}) genome {} manifest {}",
        cell(release.get("name")),
        cell(release.get("release_id")),
        cell(release.get("status")),
        cell(release.get("genome_version")),
        cell(release.get("prompt_manifest_digest"))
    )
}

fn channels_hand_off(
    agent: &str,
    channel: &str,
    preview: MovePreview,
    web_url: Option<&str>,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let agent = normalize_uuid(agent, "--agent")?;
    let channel = checked_channel(channel)?;
    let cloud = Cloud::connect(profile)?;
    let response = cloud.block(cloud.client.channel_move_preview(&agent, channel, &preview))?;
    let action = match preview {
        MovePreview::Promote { .. } => "promote",
        MovePreview::Rollback { .. } => "rollback",
    };
    let move_url = absolute_move_url(
        response.get("move_url").and_then(Value::as_str),
        web_url.filter(|url| !url.is_empty()),
    );
    if format != OutputFormat::Human {
        print_value(
            &json!({
                "action": action,
                "channel": channel,
                "moved": false,
                "move_url": move_url,
                "preview": response,
            }),
            format,
        )?;
        return Ok(ExitCode::Success);
    }
    let state = response.get("channel").unwrap_or(&Value::Null);
    println!("{action} preview for channel {channel} of agent {agent}");
    println!(
        "channel:   generation {}, protected {}",
        cell(state.get("generation")),
        cell(state.get("protected"))
    );
    println!("current:   {}", release_line(response.get("current")));
    if action == "promote" {
        println!("candidate: {}", release_line(response.get("candidate")));
    } else {
        let rollback = response.get("rollback").unwrap_or(&Value::Null);
        println!(
            "target:    {}",
            release_line(rollback.get("default_target"))
        );
        for option in rollback
            .get("options")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            println!("option:    {}", release_line(Some(option)));
        }
    }
    let gates: Vec<&Value> = response
        .get("gates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    if !gates.is_empty() {
        println!("gates:");
        for gate in gates {
            println!(
                "  {}: {} ({})",
                cell(gate.get("id")),
                cell(gate.get("status")),
                cell(gate.get("detail"))
            );
        }
    }
    if let Some(approvals) = response.get("approvals").filter(|value| !value.is_null()) {
        println!("approvals: {}", compact(approvals));
    }
    let actions = response.get("actions").unwrap_or(&Value::Null);
    println!(
        "actions for this credential: promote={} rollback={} reasons={}",
        cell(actions.get("promote")),
        cell(actions.get("rollback")),
        compact(actions.get("reasons").unwrap_or(&Value::Null))
    );
    println!();
    let noun = if action == "promote" {
        "promotion"
    } else {
        "rollback"
    };
    println!("This command never moves a channel: an authorized person completes the {noun} in the Agenomic web app, with a session.");
    match &move_url {
        Some(url) if url.starts_with("http") => println!("open: {url}"),
        Some(path) => println!(
            "open: {path} (on your Agenomic web app; pass --web-url or set AGENOMIC_WEB_URL to print the full address)"
        ),
        None => println!("open: the channel page of this agent (the preview carried no move_url)"),
    }
    Ok(ExitCode::Success)
}

fn cell(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "-".to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

fn compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers
        .iter()
        .map(|header| header.chars().count())
        .collect();
    for row in rows {
        for (index, value) in row.iter().enumerate() {
            if let Some(width) = widths.get_mut(index) {
                *width = (*width).max(value.chars().count());
            }
        }
    }
    let line = |values: Vec<&str>| {
        let cells: Vec<String> = values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                if index + 1 == values.len() {
                    value.to_string()
                } else {
                    format!("{value:<width$}", width = widths[index])
                }
            })
            .collect();
        println!("{}", cells.join("  ").trim_end());
    };
    line(headers.to_vec());
    for row in rows {
        line(row.iter().map(String::as_str).collect());
    }
}
