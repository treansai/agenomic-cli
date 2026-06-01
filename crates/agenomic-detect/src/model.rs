//! Core data model for repo-aware detection.
//!
//! [`DetectedGenome`] holds **plain values** (directly serializable to the
//! canonical `genome.yaml`), while the per-field provenance — which [`Source`]
//! set each field and the supporting evidence — is kept separately in
//! [`DetectedGenome::evidence`]. This split matches the architecture decision
//! that provenance lives in a `.agenomic/provenance.yaml` sidecar (excluded
//! from the bundle hash), never inline in `genome.yaml`.

/// A detection source, listed in §2.3 precedence order (lowest → highest).
///
/// Later sources overwrite earlier ones field-by-field; empty values never
/// overwrite a set value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// Hard-coded placeholders — the legacy `cmd_init` values.
    Defaults,
    /// Local git: `remote.origin.url` → `agent.id`.
    Git,
    /// `README.md`: first H1 → name, first paragraph → description.
    Readme,
    /// `go.mod`.
    GoMod,
    /// `Cargo.toml`.
    Cargo,
    /// `package.json`.
    PackageJson,
    /// `pyproject.toml`.
    Pyproject,
    /// `Dockerfile`: `ENTRYPOINT`/`CMD` → entrypoint fallback.
    Dockerfile,
    /// An existing `agenomic.yaml` — read last so its values win (idempotence).
    AgenomicYaml,
}

impl Source {
    /// All sources in ascending precedence order (lowest first).
    pub const PRECEDENCE: [Source; 9] = [
        Source::Defaults,
        Source::Git,
        Source::Readme,
        Source::GoMod,
        Source::Cargo,
        Source::PackageJson,
        Source::Pyproject,
        Source::Dockerfile,
        Source::AgenomicYaml,
    ];

    /// The stable kebab-case label used in `--from`, the `--format json`
    /// precedence log, and the provenance sidecar.
    ///
    /// ```
    /// use agenomic_detect::Source;
    /// assert_eq!(Source::Pyproject.label(), "pyproject");
    /// assert_eq!(Source::GoMod.label(), "go-mod");
    /// ```
    pub fn label(self) -> &'static str {
        match self {
            Source::Defaults => "defaults",
            Source::Git => "git",
            Source::Readme => "readme",
            Source::GoMod => "go-mod",
            Source::Cargo => "cargo",
            Source::PackageJson => "package-json",
            Source::Pyproject => "pyproject",
            Source::Dockerfile => "dockerfile",
            Source::AgenomicYaml => "agenomic-yaml",
        }
    }

    /// Precedence rank (higher wins). Equal to the index in [`Source::PRECEDENCE`].
    ///
    /// ```
    /// use agenomic_detect::Source;
    /// assert!(Source::Pyproject.rank() > Source::Git.rank());
    /// ```
    pub fn rank(self) -> usize {
        Source::PRECEDENCE
            .iter()
            .position(|s| *s == self)
            .unwrap_or(0)
    }

    /// Parse a `--from` label back into a [`Source`]. Returns `None` for
    /// unknown labels and for [`Source::Defaults`] (not user-selectable).
    ///
    /// ```
    /// use agenomic_detect::Source;
    /// assert_eq!(Source::from_label("package-json"), Some(Source::PackageJson));
    /// assert_eq!(Source::from_label("nope"), None);
    /// ```
    pub fn from_label(label: &str) -> Option<Source> {
        Source::PRECEDENCE
            .iter()
            .copied()
            .find(|s| *s != Source::Defaults && s.label() == label)
    }
}

/// One entry in the per-field evidence chain (§2.3).
///
/// Surfaced under `--format json` and persisted into the provenance sidecar's
/// `sources` list, where it doubles as the "what detection did last time"
/// record the merge algorithm (§3.4) compares against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Dotted field path, e.g. `runtime.model_provider` or `tools[0]`.
    pub field: String,
    /// The value detection wrote, rendered as a string.
    pub value: String,
    /// Which source won this field.
    pub source: Source,
    /// Human-readable justification, e.g. `dependency anthropic>=0.45.0`.
    pub evidence: String,
}

/// The kind of a detected tool (§2.4 allow-list).
///
/// The variant declaration order is significant: it defines the `kind` half of
/// the `(kind, name)` tool sort (§2.7), matching the order shown in §2.5
/// (`linter`, then `complexity`, then `security`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ToolKind {
    Linter,
    Complexity,
    Security,
    Test,
    Http,
    Schema,
    Memory,
    Sql,
}

impl ToolKind {
    /// Stable lowercase label written into `genome.yaml :: tools[].kind`.
    ///
    /// ```
    /// use agenomic_detect::ToolKind;
    /// assert_eq!(ToolKind::Complexity.label(), "complexity");
    /// ```
    pub fn label(self) -> &'static str {
        match self {
            ToolKind::Linter => "linter",
            ToolKind::Complexity => "complexity",
            ToolKind::Security => "security",
            ToolKind::Test => "test",
            ToolKind::Http => "http",
            ToolKind::Schema => "schema",
            ToolKind::Memory => "memory",
            ToolKind::Sql => "sql",
        }
    }
}

/// One detected tool entry (§2.4). Sorted by `(kind, name)` before emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolEntry {
    pub name: String,
    pub kind: ToolKind,
    pub version: Option<String>,
}

/// A dependency parsed from a language manifest, fed into runtime/tool
/// inference (§2.4). Not emitted into `genome.yaml`; it is an intermediate
/// hand-off from the manifest sources (P2) to the inference tables (P3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// Normalised lowercase dependency name (e.g. `langgraph`, `anthropic`).
    pub name: String,
    /// Version requirement string as written, if any (e.g. `>=0.45.0`).
    pub version: Option<String>,
    /// Which manifest source declared it.
    pub source: Source,
}

/// Inferred memory backend (§2.4). Omitted entirely when no backend is found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryInfo {
    pub enabled: bool,
    pub backend: String,
}

/// The fully detected genome, ready for canonical emission.
///
/// All fields are plain values; provenance is tracked separately in
/// [`DetectedGenome::evidence`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedGenome {
    pub spec_version: String,
    pub agent_id: String,
    pub agent_name: String,
    pub domain: String,
    pub criticality: String,
    pub authors: Vec<String>,
    pub description: Option<String>,
    pub framework: Option<String>,
    pub runtime_kind: Option<String>,
    pub model_provider: String,
    pub model_id: String,
    pub entrypoint: Option<String>,
    pub memory: Option<MemoryInfo>,
    pub tools: Vec<ToolEntry>,
    pub skills: Vec<String>,
    pub knowledge: Vec<String>,
    pub policies: Vec<String>,
    /// Per-field evidence chain, one entry per field detection set.
    pub evidence: Vec<Evidence>,
}

impl DetectedGenome {
    /// The hard-coded defaults — byte-equivalent to the legacy `cmd_init`
    /// scaffold. Detection layers higher-precedence sources on top of this.
    ///
    /// ```
    /// use agenomic_detect::DetectedGenome;
    /// let g = DetectedGenome::defaults();
    /// assert_eq!(g.agent_id, "agent://example/new");
    /// assert_eq!(g.model_provider, "openai");
    /// assert_eq!(g.model_id, "gpt-4o");
    /// assert!(g.tools.is_empty());
    /// ```
    pub fn defaults() -> DetectedGenome {
        let agent_id = "agent://example/new".to_string();
        let agent_name = "Example Agent".to_string();
        let model_provider = "openai".to_string();
        let model_id = "gpt-4o".to_string();
        let default_evidence = |field: &str, value: &str| Evidence {
            field: field.to_string(),
            value: value.to_string(),
            source: Source::Defaults,
            evidence: "built-in default".to_string(),
        };
        let evidence = vec![
            default_evidence("agent.id", &agent_id),
            default_evidence("agent.name", &agent_name),
            default_evidence("runtime.model_provider", &model_provider),
            default_evidence("runtime.model_id", &model_id),
        ];
        DetectedGenome {
            spec_version: agenomic_spec::CURRENT_SPEC_VERSION.to_string(),
            agent_id,
            agent_name,
            domain: "general".to_string(),
            criticality: "low".to_string(),
            authors: Vec::new(),
            description: None,
            framework: None,
            runtime_kind: None,
            model_provider,
            model_id,
            entrypoint: None,
            memory: None,
            tools: Vec::new(),
            skills: Vec::new(),
            knowledge: Vec::new(),
            policies: Vec::new(),
            evidence,
        }
    }

    /// Record that `source` set `field` to `value`. Because sources run in
    /// ascending precedence order, a later (higher-precedence) source
    /// **replaces** the prior evidence for the same field, so `evidence`
    /// always reflects the current winner per field.
    ///
    /// ```
    /// use agenomic_detect::{DetectedGenome, Source};
    /// let mut g = DetectedGenome::defaults();
    /// g.record(Source::Git, "agent.id", "agent://acme/widget", "origin remote");
    /// // agent.id already had a default entry → replaced, not duplicated:
    /// assert_eq!(g.evidence.iter().filter(|e| e.field == "agent.id").count(), 1);
    /// assert_eq!(g.evidence.iter().find(|e| e.field == "agent.id").unwrap().source, Source::Git);
    /// ```
    pub fn record(&mut self, source: Source, field: &str, value: &str, evidence: &str) {
        self.evidence.retain(|e| e.field != field);
        self.evidence.push(Evidence {
            field: field.to_string(),
            value: value.to_string(),
            source,
            evidence: evidence.to_string(),
        });
    }

    /// The winning evidence entries, sorted by field path — the deterministic
    /// order used for the `--format json` precedence log and the provenance
    /// sidecar (§2.7).
    ///
    /// ```
    /// use agenomic_detect::DetectedGenome;
    /// let g = DetectedGenome::defaults();
    /// let sorted = g.sorted_evidence();
    /// assert!(sorted.windows(2).all(|w| w[0].field <= w[1].field));
    /// ```
    pub fn sorted_evidence(&self) -> Vec<Evidence> {
        let mut e = self.evidence.clone();
        e.sort_by(|a, b| a.field.cmp(&b.field));
        e
    }
}
