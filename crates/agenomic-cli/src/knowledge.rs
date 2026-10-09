use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use agenomic_cloud_client::{KnowledgeListQuery, KnowledgeUpload};
use agenomic_core::{io_at, CliError, CliResult, ExitCode, Severity, ValidationIssue};
use serde_json::{json, Value};

use crate::cli::{
    KnowledgeAnswerArgs, KnowledgeCommand, KnowledgeCreateArgs, KnowledgeExportArgs,
    KnowledgeImportArgs, KnowledgeJobArgs, KnowledgeListArgs, KnowledgePublishArgs,
    KnowledgeQueryArgs, KnowledgeRollbackArgs, KnowledgeSearchArgs, KnowledgeSub,
    KnowledgeUploadArgs, KnowledgeVersionCreateArgs, KnowledgeVersionDiffArgs, KnowledgeVersionSub,
    KnowledgeVersionVerifyArgs, KnowledgeVersionsArgs, OutputFormat,
};
use crate::commands::print_value;
use crate::prompts::{cell, compact, print_table, Cloud};

const MAX_KB_ID: usize = 64;
const MAX_VERSION: u64 = 2_147_483_647;
const MAX_DOCUMENT_PATH: usize = 512;
const OCTET_STREAM: &str = "application/octet-stream";
const MAX_IMPORT_BYTES: u64 = 17 * 1024 * 1024;
const FIRST_POLL: Duration = Duration::from_millis(250);
const LONGEST_POLL: Duration = Duration::from_secs(2);

pub fn cmd_knowledge(
    args: &KnowledgeCommand,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let format = if args.json && format == OutputFormat::Human {
        OutputFormat::Json
    } else {
        format
    };
    match &args.command {
        KnowledgeSub::List(list) => kb_list(list, format, profile),
        KnowledgeSub::Get { kb_id } => kb_get(kb_id, format, profile),
        KnowledgeSub::Create(create) => kb_create(create, format, profile),
        KnowledgeSub::Upload(upload) => kb_upload(upload, format, profile),
        KnowledgeSub::Search(search) => kb_search(search, format, profile),
        KnowledgeSub::Query(query) => kb_query(query, format, profile),
        KnowledgeSub::Answer(answer) => kb_answer(answer, format, profile),
        KnowledgeSub::Versions(versions) => kb_versions(versions, format, profile),
        KnowledgeSub::Version(version) => match &version.command {
            KnowledgeVersionSub::Create(create) => version_create(create, format, profile),
            KnowledgeVersionSub::Diff(diff) => version_diff(diff, format, profile),
            KnowledgeVersionSub::Verify(verify) => version_verify(verify, format, profile),
        },
        KnowledgeSub::Publish(publish) => kb_publish(publish, format, profile),
        KnowledgeSub::Rollback(rollback) => kb_rollback(rollback, format, profile),
        KnowledgeSub::Job(job) => kb_job(job, format, profile),
        KnowledgeSub::Export(export) => kb_export(export, format, profile),
        KnowledgeSub::Import(import) => kb_import(import, format, profile),
    }
}

fn issue(code: &str, message: impl Into<String>, path: Option<String>) -> ValidationIssue {
    ValidationIssue {
        code: format!("agenomic::knowledge::{code}"),
        severity: Severity::High,
        message: message.into(),
        path,
        hint: None,
        doc: None,
    }
}

fn failed(issues: Vec<ValidationIssue>) -> CliError {
    for item in &issues {
        match &item.path {
            Some(path) => eprintln!("{}: {} ({path})", item.code, item.message),
            None => eprintln!("{}: {}", item.code, item.message),
        }
    }
    CliError::ValidationFailed { reports: issues }
}

fn usage(code: &str, message: impl Into<String>) -> CliError {
    failed(vec![issue(code, message, None)])
}

fn is_kb_id(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("kb_") else {
        return false;
    };
    if text.len() > MAX_KB_ID {
        return false;
    }
    let mut after_separator = true;
    for byte in rest.bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => after_separator = false,
            b'_' | b'-' if !after_separator => after_separator = true,
            _ => return false,
        }
    }
    !after_separator
}

fn checked_kb_id(text: &str) -> CliResult<&str> {
    if is_kb_id(text) {
        Ok(text)
    } else {
        Err(usage(
            "invalid_kb_id",
            format!(
                "knowledge base ids match ^kb_[a-z0-9]+(?:[_-][a-z0-9]+)*$ ({MAX_KB_ID} characters at most), got {text}"
            ),
        ))
    }
}

fn non_empty<'a>(text: &'a str, what: &str) -> CliResult<&'a str> {
    if text.trim().is_empty() {
        Err(usage("empty_argument", format!("{what} must not be empty")))
    } else {
        Ok(text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selector {
    Number(u32),
    Published,
    Draft,
}

impl Selector {
    fn wire(self) -> Value {
        match self {
            Self::Number(number) => json!(number),
            Self::Published => json!("published"),
            Self::Draft => json!("draft"),
        }
    }

    fn param(self) -> String {
        match self {
            Self::Number(number) => number.to_string(),
            Self::Published => "published".to_string(),
            Self::Draft => "draft".to_string(),
        }
    }
}

fn parse_version(text: &str) -> CliResult<Selector> {
    match text {
        "published" => return Ok(Selector::Published),
        "draft" => return Ok(Selector::Draft),
        _ => {}
    }
    let digits = text.strip_prefix('v').unwrap_or(text);
    let well_formed = (1..=10).contains(&digits.len())
        && !digits.starts_with('0')
        && digits.bytes().all(|byte| byte.is_ascii_digit());
    digits
        .parse::<u64>()
        .ok()
        .filter(|number| well_formed && *number <= MAX_VERSION)
        .and_then(|number| u32::try_from(number).ok())
        .map(Selector::Number)
        .ok_or_else(|| {
            usage(
                "invalid_version",
                format!(
                    "a version is 3, v3, published or draft (at most {MAX_VERSION}), got {text}"
                ),
            )
        })
}

fn version_number(text: &str) -> CliResult<u32> {
    match parse_version(text)? {
        Selector::Number(number) => Ok(number),
        Selector::Published | Selector::Draft => Err(usage(
            "version_number_required",
            format!("this command takes a version number such as 3 or v3, got {text}"),
        )),
    }
}

fn hidden_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if hidden_char(c) { ' ' } else { c })
        .collect()
}

fn clean_block(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == '\n' || c == '\t' || !hidden_char(c) {
                c
            } else {
                ' '
            }
        })
        .collect()
}

fn field(value: Option<&Value>) -> String {
    clean(&cell(value))
}

fn items<'a>(value: &'a Value, member: &str) -> std::slice::Iter<'a, Value> {
    value
        .get(member)
        .and_then(Value::as_array)
        .map(|array| array.iter())
        .unwrap_or_default()
}

fn version_label(value: Option<&Value>) -> String {
    match value.and_then(Value::as_u64) {
        Some(number) => format!("v{number}"),
        None => "-".to_string(),
    }
}

fn heading(value: Option<&Value>) -> String {
    let parts: Vec<String> = value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|part| field(Some(part)))
        .collect();
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" / ")
    }
}

fn unsigned(value: Option<&Value>, member: &str) -> CliResult<u64> {
    value.and_then(Value::as_u64).ok_or_else(|| {
        CliError::Network(format!(
            "the knowledge base response has no {member} number"
        ))
    })
}

fn print_retrieval(retrieval: Option<&Value>) {
    let Some(retrieval) = retrieval.filter(|value| value.is_object()) else {
        return;
    };
    println!(
        "retrieval {}: {} {}, {}",
        field(retrieval.get("event_id")),
        field(retrieval.get("kb_id")),
        version_label(retrieval.get("version")),
        field(retrieval.get("mode"))
    );
}

fn kb_list(
    args: &KnowledgeListArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let cloud = Cloud::connect(profile)?;
    let page = cloud.block(cloud.client.list_knowledge_bases(&KnowledgeListQuery {
        query: args.query.clone(),
        status: args.status.clone(),
        tag: args.tag.clone(),
        limit: args.limit,
        cursor: args.cursor.clone(),
    }))?;
    if format != OutputFormat::Human {
        print_value(&page, format)?;
        return Ok(ExitCode::Success);
    }
    let rows: Vec<Vec<String>> = items(&page, "knowledge_bases")
        .map(|kb| {
            vec![
                field(kb.get("kb_id")),
                field(kb.get("status")),
                field(kb.get("health")),
                version_label(kb.get("published_version")),
                version_label(kb.get("latest_version")),
                field(kb.get("document_count")),
                field(kb.get("name")),
            ]
        })
        .collect();
    print_table(
        &[
            "KB ID",
            "STATUS",
            "HEALTH",
            "PUBLISHED",
            "LATEST",
            "DOCUMENTS",
            "NAME",
        ],
        &rows,
    );
    if let Some(cursor) = page.get("next_cursor").and_then(Value::as_str) {
        println!("next page: --cursor {}", clean(cursor));
    }
    Ok(ExitCode::Success)
}

fn kb_get(kb_id: &str, format: OutputFormat, profile: Option<&str>) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(kb_id)?;
    let cloud = Cloud::connect(profile)?;
    let detail = cloud.block(cloud.client.get_knowledge_base(kb_id))?;
    if format != OutputFormat::Human {
        print_value(&detail, format)?;
        return Ok(ExitCode::Success);
    }
    let kb = detail.get("knowledge_base").unwrap_or(&Value::Null);
    let stats = detail.get("stats").unwrap_or(&Value::Null);
    let health = detail.get("health").unwrap_or(&Value::Null);
    println!("{}: {}", field(kb.get("kb_id")), field(kb.get("name")));
    println!("uri:         {}", field(kb.get("uri")));
    println!("status:      {}", field(kb.get("status")));
    let reasons: Vec<String> = items(health, "reasons")
        .map(|reason| field(Some(reason)))
        .collect();
    if reasons.is_empty() {
        println!("health:      {}", field(health.get("status")));
    } else {
        println!(
            "health:      {} ({})",
            field(health.get("status")),
            reasons.join(", ")
        );
    }
    match detail.get("published").filter(|value| value.is_object()) {
        Some(published) => println!(
            "published:   {} ({}) {}",
            version_label(published.get("version")),
            field(published.get("status")),
            field(published.get("manifest_digest"))
        ),
        None => println!("published:   none"),
    }
    println!("latest:      {}", version_label(kb.get("latest_version")));
    println!("draft:       revision {}", field(kb.get("draft_revision")));
    println!(
        "publication: generation {}",
        field(kb.get("publication_generation"))
    );
    println!(
        "documents:   {} ({} sections, {} tokens)",
        field(kb.get("document_count")),
        field(stats.get("section_count")),
        field(stats.get("token_count"))
    );
    println!(
        "jobs:        {} pending, {} failed",
        field(stats.get("pending_jobs")),
        field(stats.get("failed_jobs"))
    );
    Ok(ExitCode::Success)
}

fn kb_create(
    args: &KnowledgeCreateArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(&args.kb_id)?;
    let name = non_empty(&args.name, "--name")?;
    let mut body = json!({ "kb_id": kb_id, "name": name });
    if let Some(description) = &args.description {
        body["description"] = json!(description);
    }
    if !args.tags.is_empty() {
        body["tags"] = json!(args.tags);
    }
    let cloud = Cloud::connect(profile)?;
    let response = cloud.block(cloud.client.create_knowledge_base(&body))?;
    if format != OutputFormat::Human {
        print_value(&response, format)?;
        return Ok(ExitCode::Success);
    }
    let kb = response.get("knowledge_base").unwrap_or(&Value::Null);
    println!(
        "created {} ({})",
        field(kb.get("kb_id")),
        field(kb.get("name"))
    );
    println!("uri: {}", field(kb.get("uri")));
    Ok(ExitCode::Success)
}

struct Planned {
    file: PathBuf,
    document_path: String,
}

fn is_hidden(name: &OsStr) -> bool {
    name.as_encoded_bytes().first() == Some(&b'.')
}

fn is_credential(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(lower.as_str(), "id_rsa" | "id_ed25519" | ".env")
        || lower.starts_with(".env.")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
}

fn joined(prefix: Option<&str>, relative: &str) -> String {
    match prefix {
        Some(prefix) => format!("{prefix}/{relative}"),
        None => relative.to_string(),
    }
}

fn relative_path(root: &Path, path: &Path) -> CliResult<String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        CliError::Internal(format!(
            "{} is not below {}",
            path.display(),
            root.display()
        ))
    })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(usage(
                "invalid_document_path",
                format!("{} is not below {}", path.display(), root.display()),
            ));
        };
        let part = part.to_str().ok_or_else(|| {
            usage(
                "invalid_document_path",
                format!("{} is not valid UTF-8", path.display()),
            )
        })?;
        parts.push(part);
    }
    Ok(parts.join("/"))
}

fn walk_error(root: &Path, error: walkdir::Error) -> CliError {
    let path = error
        .path()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.to_path_buf());
    match error.into_io_error() {
        Some(source) => io_at(path, source),
        None => usage(
            "walk_failed",
            format!("{}: file system loop", path.display()),
        ),
    }
}

fn walk_directory(
    root: &Path,
    patterns: &[glob::Pattern],
    prefix: Option<&str>,
    planned: &mut Vec<Planned>,
) -> CliResult<()> {
    let walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| entry.depth() == 0 || !is_hidden(entry.file_name()));
    for entry in walker {
        let entry = entry.map_err(|error| walk_error(root, error))?;
        if entry.file_type().is_dir() {
            continue;
        }
        let relative = relative_path(root, entry.path())?;
        if !patterns.is_empty() && !patterns.iter().any(|pattern| pattern.matches(&relative)) {
            continue;
        }
        if entry.path_is_symlink() {
            eprintln!("skipped {}: symbolic link", clean(&relative));
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.file_name().to_str().is_some_and(is_credential) {
            eprintln!("skipped {}: credential file", clean(&relative));
            continue;
        }
        planned.push(Planned {
            file: entry.path().to_path_buf(),
            document_path: joined(prefix, &relative),
        });
    }
    Ok(())
}

fn check_document_path(path: &str) -> CliResult<()> {
    let valid = path.chars().count() <= MAX_DOCUMENT_PATH
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
    if valid {
        Ok(())
    } else {
        Err(usage(
            "invalid_document_path",
            format!("{} is not a normalized relative document path", clean(path)),
        ))
    }
}

fn plan_uploads(args: &KnowledgeUploadArgs) -> CliResult<Vec<Planned>> {
    let patterns = args
        .globs
        .iter()
        .map(|text| {
            glob::Pattern::new(text)
                .map_err(|error| usage("invalid_glob", format!("--glob {text}: {error}")))
        })
        .collect::<CliResult<Vec<_>>>()?;
    let prefix = args
        .prefix
        .as_deref()
        .map(|prefix| prefix.trim_matches('/'))
        .filter(|prefix| !prefix.is_empty());
    let mut planned = Vec::new();
    for root in &args.paths {
        let metadata = std::fs::metadata(root).map_err(|e| io_at(root, e))?;
        if metadata.is_dir() {
            walk_directory(root, &patterns, prefix, &mut planned)?;
            continue;
        }
        let name = root.file_name().and_then(OsStr::to_str).ok_or_else(|| {
            usage(
                "invalid_document_path",
                format!("{} has no UTF-8 file name", root.display()),
            )
        })?;
        if is_credential(name) {
            return Err(usage(
                "credential_file",
                format!(
                    "{} looks like a credential file; credential files are never uploaded",
                    root.display()
                ),
            ));
        }
        planned.push(Planned {
            file: root.clone(),
            document_path: joined(prefix, name),
        });
    }
    let mut seen = BTreeSet::new();
    for item in &planned {
        check_document_path(&item.document_path)?;
        if !seen.insert(item.document_path.as_str()) {
            return Err(usage(
                "duplicate_document_path",
                format!(
                    "two files map to the document path {}",
                    clean(&item.document_path)
                ),
            ));
        }
    }
    if planned.is_empty() {
        return Err(usage("nothing_to_upload", "no file to upload"));
    }
    Ok(planned)
}

fn upload_line(path: &str, response: &Value) -> String {
    let created = response
        .get("created")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let document = response.get("document").unwrap_or(&Value::Null);
    let path = document.get("path").and_then(Value::as_str).unwrap_or(path);
    let state = if created { "uploaded " } else { "unchanged" };
    let mut line = format!(
        "{state} {} ({}, revision {}",
        clean(path),
        field(document.get("document_id")),
        field(document.get("current_revision"))
    );
    if let Some(job) = response.get("job").and_then(|job| job.get("job_id")) {
        line.push_str(&format!(", job {}", field(Some(job))));
    }
    line.push(')');
    line
}

fn job_of(response: Value) -> CliResult<Value> {
    match response {
        Value::Object(mut object) => match object.remove("job") {
            Some(job) if job.is_object() => Ok(job),
            _ => Err(CliError::Network(
                "the job response has no job member".to_string(),
            )),
        },
        _ => Err(CliError::Network(
            "the job response is not a JSON object".to_string(),
        )),
    }
}

fn job_status(job: &Value) -> &str {
    job.get("status")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn job_error(job: &Value) -> String {
    let parts: Vec<String> = ["error_code", "error"]
        .iter()
        .filter_map(|member| job.get(*member).and_then(Value::as_str))
        .map(clean)
        .collect();
    parts.join(": ")
}

fn job_line(job: &Value) -> String {
    let error = job_error(job);
    if job_status(job) == "succeeded" || error.is_empty() {
        format!(
            "job {} {}",
            field(job.get("job_id")),
            field(job.get("status"))
        )
    } else {
        format!(
            "job {} {}: {error}",
            field(job.get("job_id")),
            field(job.get("status"))
        )
    }
}

fn job_issue(job: &Value) -> Option<ValidationIssue> {
    let status = job_status(job);
    if status != "failed" && status != "cancelled" {
        return None;
    }
    let error = job_error(job);
    let mut message = format!(
        "job {} ({}) {status}",
        field(job.get("job_id")),
        field(job.get("kind"))
    );
    if !error.is_empty() {
        message.push_str(&format!(": {error}"));
    }
    Some(issue("job_failed", message, None))
}

fn wait_for_job(cloud: &Cloud, job_id: &str, deadline: Instant, timeout: u64) -> CliResult<Value> {
    let mut delay = FIRST_POLL;
    loop {
        let job = job_of(cloud.block(cloud.client.get_knowledge_job(job_id))?)?;
        let status = job_status(&job);
        if matches!(status, "succeeded" | "failed" | "cancelled") {
            return Ok(job);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(CliError::Network(format!(
                "knowledge_job_timeout: job {job_id} is still {} after {timeout} seconds",
                clean(status)
            )));
        }
        std::thread::sleep(delay.min(deadline - now));
        delay = (delay * 2).min(LONGEST_POLL);
    }
}

fn job_id_of(response: &Value) -> Option<String> {
    response
        .get("job")
        .and_then(|job| job.get("job_id"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn set_member(target: &mut Value, member: &str, value: Value) {
    if let Some(object) = target.as_object_mut() {
        object.insert(member.to_string(), value);
    }
}

fn kb_upload(
    args: &KnowledgeUploadArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(&args.kb_id)?;
    for tag in &args.tags {
        if tag.trim().is_empty() || tag.contains(',') {
            return Err(usage(
                "invalid_tag",
                format!("tags are non-empty and hold no comma, got {tag:?}"),
            ));
        }
    }
    let content_type = match &args.content_type {
        None => OCTET_STREAM.to_string(),
        Some(text)
            if !text.trim().is_empty()
                && text.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) =>
        {
            text.clone()
        }
        Some(text) => {
            return Err(usage(
                "invalid_content_type",
                format!("--content-type must be printable ASCII, got {text:?}"),
            ))
        }
    };
    let planned = plan_uploads(args)?;
    let cloud = Cloud::connect(profile)?;
    let human = format == OutputFormat::Human;
    let mut writes = Vec::with_capacity(planned.len());
    for item in &planned {
        let upload = KnowledgeUpload {
            document_path: item.document_path.clone(),
            content_type: content_type.clone(),
            collection: args.collection.clone(),
            tags: args.tags.clone(),
            classification: args.classification.clone(),
            change_message: args.message.clone(),
        };
        let response = cloud.block(
            cloud
                .client
                .upload_knowledge_document(kb_id, &item.file, &upload),
        )?;
        if human {
            println!("{}", upload_line(&item.document_path, &response));
        }
        writes.push(response);
    }
    let mut issues = Vec::new();
    if args.wait {
        let deadline = Instant::now() + Duration::from_secs(args.timeout);
        for write in &mut writes {
            let Some(job_id) = job_id_of(write) else {
                continue;
            };
            let job = wait_for_job(&cloud, &job_id, deadline, args.timeout)?;
            if human {
                println!("{}", job_line(&job));
            }
            issues.extend(job_issue(&job));
            set_member(write, "job", job);
        }
    }
    let uploaded = writes
        .iter()
        .filter(|write| {
            write
                .get("created")
                .and_then(Value::as_bool)
                .unwrap_or(true)
        })
        .count();
    if human {
        println!("{uploaded} uploaded, {} unchanged", writes.len() - uploaded);
    } else {
        print_value(&json!({ "kb_id": kb_id, "documents": writes }), format)?;
    }
    if !issues.is_empty() {
        return Err(failed(issues));
    }
    Ok(ExitCode::Success)
}

fn kb_search(
    args: &KnowledgeSearchArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(&args.kb_id)?;
    let mut body = json!({ "query": non_empty(&args.query, "the query")? });
    if let Some(version) = &args.version {
        body["version"] = parse_version(version)?.wire();
    }
    if let Some(mode) = args.mode {
        body["mode"] = json!(mode.as_str());
    }
    if let Some(top_k) = args.top_k {
        body["top_k"] = json!(top_k);
    }
    if args.context {
        body["include_context"] = json!(true);
    }
    let cloud = Cloud::connect(profile)?;
    let response = cloud.block(cloud.client.search_knowledge(kb_id, &body))?;
    if format != OutputFormat::Human {
        print_value(&response, format)?;
        return Ok(ExitCode::Success);
    }
    let rows: Vec<Vec<String>> = items(&response, "results")
        .map(|result| {
            vec![
                field(result.get("rank")),
                field(result.get("score")),
                field(result.get("risk").and_then(|risk| risk.get("level"))),
                field(result.get("evidence_id")),
                field(result.get("path")),
                heading(result.get("heading_path")),
            ]
        })
        .collect();
    if rows.is_empty() {
        println!("no results");
    } else {
        print_table(
            &["RANK", "SCORE", "RISK", "EVIDENCE", "PATH", "HEADING"],
            &rows,
        );
    }
    print_retrieval(response.get("retrieval"));
    if args.context {
        if let Some(context) = response.get("context").and_then(Value::as_str) {
            println!();
            println!("{}", clean_block(context).trim_end());
        }
    }
    Ok(ExitCode::Success)
}

fn section_title(section: &Value) -> String {
    let path = heading(section.get("heading_path"));
    if path == "-" {
        field(section.get("heading"))
    } else {
        path
    }
}

fn kb_query(
    args: &KnowledgeQueryArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(&args.kb_id)?;
    let mut body = json!({ "query": non_empty(&args.query, "the query")? });
    if let Some(version) = &args.version {
        body["version"] = parse_version(version)?.wire();
    }
    let cloud = Cloud::connect(profile)?;
    let response = cloud.block(cloud.client.query_knowledge(kb_id, &body))?;
    if format != OutputFormat::Human {
        print_value(&response, format)?;
        return Ok(ExitCode::Success);
    }
    let matches: Vec<Vec<String>> = items(&response, "matches")
        .map(|found| {
            vec![
                field(found.get("match_kind")),
                field(found.get("score")),
                field(found.get("path")),
                heading(found.get("heading_path")),
                field(found.get("section_id")),
            ]
        })
        .collect();
    let documents: Vec<Vec<String>> = items(&response, "documents")
        .map(|document| {
            vec![
                field(document.get("document_id")),
                field(document.get("current_revision")),
                field(document.get("path")),
                field(document.get("title")),
            ]
        })
        .collect();
    if matches.is_empty() && documents.is_empty() {
        println!("no match");
    }
    if !matches.is_empty() {
        print_table(&["MATCH", "SCORE", "PATH", "HEADING", "SECTION"], &matches);
    }
    if !documents.is_empty() {
        print_table(&["DOCUMENT", "REVISION", "PATH", "TITLE"], &documents);
    }
    print_retrieval(response.get("retrieval"));
    for section in items(&response, "sections") {
        let Some(content) = section.get("content").and_then(Value::as_str) else {
            continue;
        };
        println!();
        println!(
            "== {} ({})",
            section_title(section),
            field(section.get("section_id"))
        );
        println!("{}", clean_block(content).trim_end());
    }
    Ok(ExitCode::Success)
}

fn kb_answer(
    args: &KnowledgeAnswerArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(&args.kb_id)?;
    let mut body = json!({ "query": non_empty(&args.question, "the question")? });
    if let Some(version) = &args.version {
        body["version"] = parse_version(version)?.wire();
    }
    if let Some(top_k) = args.top_k {
        body["top_k"] = json!(top_k);
    }
    let cloud = Cloud::connect(profile)?;
    let response = cloud.block(cloud.client.answer_knowledge(kb_id, &body))?;
    if format != OutputFormat::Human {
        print_value(&response, format)?;
        return Ok(ExitCode::Success);
    }
    let abstained = response
        .get("abstained")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match response.get("answer").and_then(Value::as_str) {
        Some(answer) if !abstained => println!("{}", clean_block(answer).trim_end()),
        _ => println!("abstained: {}", field(response.get("reason"))),
    }
    let citations: Vec<&Value> = items(&response, "citations").collect();
    let rows: Vec<Vec<String>> = items(&response, "evidence")
        .map(|evidence| {
            let cited = evidence
                .get("citation")
                .is_some_and(|citation| citations.contains(&citation));
            vec![
                field(evidence.get("evidence_id")),
                if cited { "yes" } else { "-" }.to_string(),
                field(evidence.get("risk").and_then(|risk| risk.get("level"))),
                field(evidence.get("path")),
                heading(evidence.get("heading_path")),
            ]
        })
        .collect();
    if !rows.is_empty() {
        println!();
        print_table(&["EVIDENCE", "CITED", "RISK", "PATH", "HEADING"], &rows);
    }
    for conflict in items(&response, "conflicts") {
        let ids: Vec<String> = items(conflict, "evidence_ids")
            .map(|id| field(Some(id)))
            .collect();
        let heuristic = conflict
            .get("heuristic")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        println!(
            "conflict {} between {}: {}{}",
            field(conflict.get("kind")),
            ids.join(", "),
            field(conflict.get("detail")),
            if heuristic { " (heuristic)" } else { "" }
        );
    }
    let invalid: Vec<String> = items(&response, "invalid_citations")
        .map(|id| field(Some(id)))
        .collect();
    if !invalid.is_empty() {
        println!("invalid citations: {}", invalid.join(", "));
    }
    if let Some(model) = response.get("model").filter(|model| model.is_string()) {
        println!("model: {}", field(Some(model)));
    }
    print_retrieval(response.get("retrieval"));
    Ok(ExitCode::Success)
}

fn kb_versions(
    args: &KnowledgeVersionsArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(&args.kb_id)?;
    let cloud = Cloud::connect(profile)?;
    let page = cloud.block(cloud.client.list_knowledge_versions(
        kb_id,
        args.limit,
        args.cursor.as_deref(),
    ))?;
    if format != OutputFormat::Human {
        print_value(&page, format)?;
        return Ok(ExitCode::Success);
    }
    let rows: Vec<Vec<String>> = items(&page, "versions")
        .map(|version| {
            let published = version
                .get("published")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            vec![
                version_label(version.get("version")),
                field(version.get("status")),
                if published { "yes" } else { "-" }.to_string(),
                field(
                    version
                        .get("counts")
                        .and_then(|counts| counts.get("documents")),
                ),
                field(version.get("manifest_digest")),
                field(version.get("change_message")),
            ]
        })
        .collect();
    print_table(
        &[
            "VERSION",
            "STATUS",
            "PUBLISHED",
            "DOCUMENTS",
            "MANIFEST",
            "MESSAGE",
        ],
        &rows,
    );
    if let Some(cursor) = page.get("next_cursor").and_then(Value::as_str) {
        println!("next page: --cursor {}", clean(cursor));
    }
    Ok(ExitCode::Success)
}

fn version_create(
    args: &KnowledgeVersionCreateArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(&args.kb_id)?;
    let cloud = Cloud::connect(profile)?;
    let expected = match args.expected_draft_revision {
        Some(revision) => revision,
        None => {
            let detail = cloud.block(cloud.client.get_knowledge_base(kb_id))?;
            unsigned(
                detail.pointer("/knowledge_base/draft_revision"),
                "draft_revision",
            )?
        }
    };
    let mut body = json!({
        "expected_draft_revision": expected,
        "idempotency_key": ulid::Ulid::new().to_string(),
    });
    if let Some(message) = &args.message {
        body["change_message"] = json!(message);
    }
    let mut response = cloud.block(cloud.client.create_knowledge_version(kb_id, &body))?;
    let human = format == OutputFormat::Human;
    if human {
        let version = response.get("version").unwrap_or(&Value::Null);
        let created = response
            .get("created")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if created {
            println!(
                "created {} of {kb_id} from draft revision {expected} ({})",
                version_label(version.get("version")),
                field(version.get("status"))
            );
        } else {
            println!(
                "unchanged: {} of {kb_id} already snapshots draft revision {expected} ({})",
                version_label(version.get("version")),
                field(version.get("status"))
            );
        }
        println!("manifest: {}", field(version.get("manifest_digest")));
        if let Some(job) = response.get("job").filter(|job| job.is_object()) {
            println!(
                "job: {} ({})",
                field(job.get("job_id")),
                field(job.get("status"))
            );
        }
    }
    let mut issues = Vec::new();
    if args.wait {
        if let Some(job_id) = job_id_of(&response) {
            let deadline = Instant::now() + Duration::from_secs(args.timeout);
            let job = wait_for_job(&cloud, &job_id, deadline, args.timeout)?;
            if human {
                println!("{}", job_line(&job));
            }
            issues.extend(job_issue(&job));
            set_member(&mut response, "job", job);
        }
    }
    if !human {
        print_value(&response, format)?;
    }
    if !issues.is_empty() {
        return Err(failed(issues));
    }
    Ok(ExitCode::Success)
}

fn change_line(kind: &str, change: &Value) -> String {
    let revision = |member: &str| match change.get(member).and_then(Value::as_u64) {
        Some(number) => format!("r{number}"),
        None => "-".to_string(),
    };
    let detail = match kind {
        "added" => revision("to_revision"),
        "deleted" => revision("from_revision"),
        "moved" => format!("from {}", field(change.get("from_path"))),
        _ => format!(
            "{} -> {}",
            revision("from_revision"),
            revision("to_revision")
        ),
    };
    format!("  {kind:<9} {} ({detail})", field(change.get("path")))
}

fn version_diff(
    args: &KnowledgeVersionDiffArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(&args.kb_id)?;
    let version = version_number(&args.version)?;
    let against = args.against.as_deref().map(version_number).transpose()?;
    let cloud = Cloud::connect(profile)?;
    let diff = cloud.block(
        cloud
            .client
            .diff_knowledge_versions(kb_id, version, against),
    )?;
    if format != OutputFormat::Human {
        print_value(&diff, format)?;
        return Ok(ExitCode::Success);
    }
    let from = diff
        .get("from")
        .map(|from| version_label(from.get("version")))
        .filter(|label| label != "-")
        .unwrap_or_else(|| "(none)".to_string());
    let to = version_label(diff.get("to").and_then(|to| to.get("version")));
    println!("{kb_id} {from} -> {to}");
    if diff
        .get("identical")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        println!("identical");
        return Ok(ExitCode::Success);
    }
    let documents = diff.pointer("/content/documents").unwrap_or(&Value::Null);
    let kinds = ["added", "modified", "deleted", "moved"];
    let counts: Vec<String> = kinds
        .iter()
        .map(|kind| format!("{} {kind}", items(documents, kind).len()))
        .collect();
    println!("documents: {}", counts.join(", "));
    for kind in kinds {
        for change in items(documents, kind) {
            println!("{}", change_line(kind, change));
        }
    }
    let sections: Vec<&Value> = diff
        .get("content")
        .map(|content| items(content, "sections").collect())
        .unwrap_or_default();
    println!("sections: {} changed", sections.len());
    for section in sections {
        println!(
            "  {:<9} {}: {}",
            field(section.get("change")),
            field(section.get("path")),
            heading(section.get("heading_path"))
        );
    }
    let metadata: Vec<&Value> = items(&diff, "metadata").collect();
    if !metadata.is_empty() {
        println!("metadata: {} changed", metadata.len());
        for change in metadata {
            println!(
                "  {} {}: {} -> {}",
                field(change.get("path")),
                field(change.get("field")),
                clean(&compact(change.get("before").unwrap_or(&Value::Null))),
                clean(&compact(change.get("after").unwrap_or(&Value::Null)))
            );
        }
    }
    let configuration = diff.get("configuration").unwrap_or(&Value::Null);
    let changed: Vec<&str> = [
        ("index_config_changed", "index configuration"),
        ("chunking_changed", "chunking"),
        ("embedding_changed", "embedding"),
        ("text_search_changed", "text search"),
    ]
    .iter()
    .filter(|(member, _)| {
        configuration
            .get(*member)
            .and_then(Value::as_bool)
            .unwrap_or(false)
    })
    .map(|(_, label)| *label)
    .collect();
    if changed.is_empty() {
        println!("configuration: unchanged");
    } else {
        println!("configuration: {} changed", changed.join(", "));
    }
    let agents: Vec<&Value> = items(&diff, "affected_agents").collect();
    println!("affected agents: {}", agents.len());
    for agent in agents {
        let pin = match agent.get("pinned_version").and_then(Value::as_u64) {
            Some(number) => format!(" v{number}"),
            None => String::new(),
        };
        println!(
            "  {} ({}) {}{pin}",
            field(agent.get("agent_name")),
            field(agent.get("agent_id")),
            field(agent.get("selector"))
        );
    }
    Ok(ExitCode::Success)
}

fn version_verify(
    args: &KnowledgeVersionVerifyArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(&args.kb_id)?;
    let version = version_number(&args.version)?;
    let cloud = Cloud::connect(profile)?;
    let report = cloud.block(cloud.client.verify_knowledge_version(kb_id, version))?;
    let flag = |value: Option<&Value>| value.and_then(Value::as_bool).unwrap_or(false);
    let manifest_valid = flag(report.get("manifest_digest_valid"));
    let signature = report.get("signature").unwrap_or(&Value::Null);
    let signed = flag(signature.get("present"));
    let signature_valid = flag(signature.get("valid"));
    let errors: Vec<&Value> = items(&report, "digest_errors").collect();
    let mut issues = Vec::new();
    if !manifest_valid {
        issues.push(issue(
            "manifest_digest_mismatch",
            format!(
                "the manifest of {kb_id} v{version} does not match {}",
                field(report.get("manifest_digest"))
            ),
            None,
        ));
    }
    for error in &errors {
        issues.push(issue(
            "document_digest_mismatch",
            format!(
                "expected {}, got {}",
                field(error.get("expected")),
                field(error.get("actual"))
            ),
            Some(field(error.get("document_id"))),
        ));
    }
    if signed && !signature_valid {
        issues.push(issue(
            "signature_invalid",
            format!(
                "the signature of {kb_id} v{version} (key {}) is invalid",
                field(signature.get("key_id"))
            ),
            None,
        ));
    }
    if format != OutputFormat::Human {
        print_value(&report, format)?;
    } else {
        let verdict = if issues.is_empty() {
            "valid"
        } else {
            "invalid"
        };
        println!("{kb_id} v{version}: {verdict}");
        println!(
            "manifest:  {} ({})",
            field(report.get("manifest_digest")),
            if manifest_valid {
                "digest valid"
            } else {
                "digest mismatch"
            }
        );
        println!(
            "documents: {} checked, {} digest error(s)",
            field(report.get("documents_checked")),
            errors.len()
        );
        let signature_line = match (signed, signature_valid) {
            (false, _) => "none".to_string(),
            (true, true) => format!("valid (key {})", field(signature.get("key_id"))),
            (true, false) => format!("invalid (key {})", field(signature.get("key_id"))),
        };
        println!("signature: {signature_line}");
    }
    if !issues.is_empty() {
        return Err(failed(issues));
    }
    Ok(ExitCode::Success)
}

fn publication_generation(cloud: &Cloud, kb_id: &str) -> CliResult<u64> {
    let detail = cloud.block(cloud.client.get_knowledge_base(kb_id))?;
    unsigned(
        detail.pointer("/knowledge_base/publication_generation"),
        "publication_generation",
    )
}

fn conflict_hint(error: CliError, kb_id: &str, generation: u64, action: &str) -> CliError {
    if let CliError::CloudRefused { status: 409, .. } = &error {
        eprintln!(
            "hint: the publication of {kb_id} moved after generation {generation} was read, so nothing was {action}; check `agenomic knowledge get {kb_id}` and run the command again"
        );
    }
    error
}

fn publication_line(response: &Value) -> (String, String) {
    let event = response.get("event").unwrap_or(&Value::Null);
    let generation = event.get("generation").or_else(|| {
        response
            .get("knowledge_base")
            .and_then(|kb| kb.get("publication_generation"))
    });
    (version_label(event.get("from_version")), field(generation))
}

fn kb_publish(
    args: &KnowledgePublishArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(&args.kb_id)?;
    let version = version_number(&args.version)?;
    let mut body = json!({ "version": version });
    if let Some(reason) = &args.reason {
        body["reason"] = json!(non_empty(reason, "--reason")?);
    }
    let cloud = Cloud::connect(profile)?;
    let generation = publication_generation(&cloud, kb_id)?;
    let response = cloud
        .block(
            cloud
                .client
                .publish_knowledge_version(kb_id, &body, generation),
        )
        .map_err(|error| conflict_hint(error, kb_id, generation, "published"))?;
    if format != OutputFormat::Human {
        print_value(&response, format)?;
        return Ok(ExitCode::Success);
    }
    let (previous, generation) = publication_line(&response);
    println!(
        "published v{version} of {kb_id} (previously {previous}, publication generation {generation})"
    );
    Ok(ExitCode::Success)
}

fn kb_rollback(
    args: &KnowledgeRollbackArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(&args.kb_id)?;
    let mut body = json!({ "reason": non_empty(&args.reason, "--reason")? });
    if let Some(to) = &args.to {
        body["to_version"] = json!(version_number(to)?);
    }
    let cloud = Cloud::connect(profile)?;
    let generation = publication_generation(&cloud, kb_id)?;
    let response = cloud
        .block(
            cloud
                .client
                .rollback_knowledge_base(kb_id, &body, generation),
        )
        .map_err(|error| conflict_hint(error, kb_id, generation, "rolled back"))?;
    if format != OutputFormat::Human {
        print_value(&response, format)?;
        return Ok(ExitCode::Success);
    }
    let (previous, generation) = publication_line(&response);
    let target = version_label(
        response
            .get("event")
            .and_then(|event| event.get("to_version")),
    );
    println!(
        "rolled back {kb_id} to {target} (previously {previous}, publication generation {generation})"
    );
    Ok(ExitCode::Success)
}

fn kb_job(
    args: &KnowledgeJobArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let job_id = non_empty(&args.job_id, "the job id")?;
    let cloud = Cloud::connect(profile)?;
    let job = if args.wait {
        let deadline = Instant::now() + Duration::from_secs(args.timeout);
        wait_for_job(&cloud, job_id, deadline, args.timeout)?
    } else {
        job_of(cloud.block(cloud.client.get_knowledge_job(job_id))?)?
    };
    if format != OutputFormat::Human {
        print_value(&json!({ "job": job }), format)?;
    } else {
        println!(
            "{}: {} {} (attempt {} of {})",
            field(job.get("job_id")),
            field(job.get("kind")),
            field(job.get("status")),
            field(job.get("attempts")),
            field(job.get("max_attempts"))
        );
        println!("kb:       {}", field(job.get("kb_id")));
        println!(
            "subject:  {}",
            clean(&compact(job.get("subject").unwrap_or(&Value::Null)))
        );
        if let Some(progress) = job
            .get("progress")
            .filter(|progress| progress.as_object().is_some_and(|map| !map.is_empty()))
        {
            println!("progress: {}", clean(&compact(progress)));
        }
        let error = job_error(&job);
        if !error.is_empty() {
            println!("error:    {error}");
        }
    }
    if args.wait {
        if let Some(problem) = job_issue(&job) {
            return Err(failed(vec![problem]));
        }
    }
    Ok(ExitCode::Success)
}

fn kb_export(
    args: &KnowledgeExportArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = checked_kb_id(&args.kb_id)?;
    let selector = args.version.as_deref().map(parse_version).transpose()?;
    let cloud = Cloud::connect(profile)?;
    let (document, bytes) = cloud.block(
        cloud
            .client
            .export_knowledge_base(kb_id, selector.map(Selector::param).as_deref()),
    )?;
    if !document.is_object() {
        return Err(CliError::Network(
            "the knowledge base export is not a JSON object".to_string(),
        ));
    }
    if let Some(parent) = args
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|e| io_at(parent, e))?;
    }
    std::fs::write(&args.output, &bytes).map_err(|e| io_at(&args.output, e))?;
    let summary = json!({
        "path": args.output.display().to_string(),
        "kb_id": kb_id,
        "version": selector.map(Selector::wire),
        "schema": document.get("schema").filter(|schema| schema.is_string()),
        "bytes": bytes.len(),
    });
    if format != OutputFormat::Human {
        print_value(&summary, format)?;
        return Ok(ExitCode::Success);
    }
    println!(
        "wrote {} ({kb_id}, {} bytes)",
        args.output.display(),
        bytes.len()
    );
    Ok(ExitCode::Success)
}

fn read_export(file: &Path) -> CliResult<Vec<u8>> {
    let handle = std::fs::File::open(file).map_err(|e| io_at(file, e))?;
    let mut bytes = Vec::new();
    handle
        .take(MAX_IMPORT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_at(file, e))?;
    if bytes.len() as u64 > MAX_IMPORT_BYTES {
        return Err(usage(
            "import_too_large",
            format!(
                "{} is larger than 17 MiB ({MAX_IMPORT_BYTES} bytes), the most the import route accepts",
                file.display()
            ),
        ));
    }
    let document: Value = serde_json::from_slice(&bytes)
        .map_err(|e| usage("invalid_json", format!("{}: {e}", file.display())))?;
    if !document.is_object() {
        return Err(usage(
            "invalid_export",
            format!("{} does not hold a JSON object", file.display()),
        ));
    }
    Ok(bytes)
}

fn kb_import(
    args: &KnowledgeImportArgs,
    format: OutputFormat,
    profile: Option<&str>,
) -> CliResult<ExitCode> {
    let kb_id = args.kb_id.as_deref().map(checked_kb_id).transpose()?;
    let name = args
        .name
        .as_deref()
        .map(|name| non_empty(name, "--name"))
        .transpose()?;
    let export = read_export(&args.file)?;
    let cloud = Cloud::connect(profile)?;
    let response = cloud.block(cloud.client.import_knowledge_base(&export, kb_id, name))?;
    if format != OutputFormat::Human {
        print_value(&response, format)?;
        return Ok(ExitCode::Success);
    }
    let kb = response.get("knowledge_base").unwrap_or(&Value::Null);
    println!(
        "imported {} ({})",
        field(kb.get("kb_id")),
        field(kb.get("name"))
    );
    println!("uri:       {}", field(kb.get("uri")));
    println!("documents: {}", field(response.get("imported_documents")));
    let jobs = response.get("enqueued_jobs");
    if jobs.and_then(Value::as_u64).is_some_and(|jobs| jobs > 0) {
        println!(
            "jobs:      {} enqueued; `agenomic knowledge get {}` shows the pending ones",
            field(jobs),
            field(kb.get("kb_id"))
        );
    } else {
        println!("jobs:      {} enqueued", field(jobs));
    }
    Ok(ExitCode::Success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kb_ids_follow_the_rfc_grammar() {
        for valid in ["kb_x", "kb_customer_support", "kb_a-b_c9", "kb_0"] {
            assert!(is_kb_id(valid), "{valid}");
        }
        let long = format!("kb_{}", "a".repeat(62));
        for invalid in [
            "kb_",
            "kb__x",
            "kb_x_",
            "kb_X",
            "kb_x--y",
            "x_kb",
            "kb_é",
            long.as_str(),
        ] {
            assert!(!is_kb_id(invalid), "{invalid}");
        }
        assert!(is_kb_id(&format!("kb_{}", "a".repeat(61))));
    }

    #[test]
    fn versions_take_numbers_v_numbers_and_the_two_selectors() {
        assert_eq!(parse_version("3").ok(), Some(Selector::Number(3)));
        assert_eq!(parse_version("v3").ok(), Some(Selector::Number(3)));
        assert_eq!(
            parse_version("2147483647").ok(),
            Some(Selector::Number(2_147_483_647))
        );
        assert_eq!(parse_version("published").ok(), Some(Selector::Published));
        assert_eq!(parse_version("draft").ok(), Some(Selector::Draft));
        for invalid in [
            "0",
            "v0",
            "03",
            "2147483648",
            "V3",
            "v",
            "",
            "-1",
            "3.0",
            "latest",
        ] {
            assert!(parse_version(invalid).is_err(), "{invalid}");
        }
        assert!(version_number("published").is_err());
    }

    #[test]
    fn terminal_text_loses_control_and_invisible_characters() {
        assert_eq!(clean("a\u{1b}[31mb\nc\u{202E}d"), "a [31mb c d");
        assert_eq!(clean_block("a\u{1b}]0;x\u{7}\nb\tc"), "a ]0;x \nb\tc");
    }

    #[test]
    fn credential_files_are_recognized() {
        for name in [
            "id_rsa",
            "ID_ED25519",
            "server.pem",
            "tls.KEY",
            ".env",
            ".env.local",
        ] {
            assert!(is_credential(name), "{name}");
        }
        for name in ["keys.md", "pem.txt", "environment.md"] {
            assert!(!is_credential(name), "{name}");
        }
    }

    #[test]
    fn document_paths_are_normalized_relative_paths() {
        assert!(check_document_path("guides/security.md").is_ok());
        assert!(check_document_path("é/ü.md").is_ok());
        for invalid in [
            "",
            "/a.md",
            "a//b.md",
            "a/./b.md",
            "../a.md",
            "a\\b.md",
            "a\u{7}.md",
        ] {
            assert!(check_document_path(invalid).is_err(), "{invalid:?}");
        }
    }
}
