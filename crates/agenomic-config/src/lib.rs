//! Profile, credential, and project config for agenomic-cli.
//!
//! Files:
//! - User config: `~/.config/agenomic/config.toml` (cross-platform via `directories`)
//! - Credentials: `~/.config/agenomic/credentials.toml` (mode 0600)
//! - Project: `agenomic.toml` in cwd or any ancestor

use std::path::{Path, PathBuf};

use agenomic_core::{io_at, CliError, CliResult, Severity, ValidationLevel};
use directories::ProjectDirs;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

const APP_QUALIFIER: &str = "dev";
const APP_ORG: &str = "agenomic";
const APP_NAME: &str = "agenomic";

/// Default Agenomic Cloud endpoint, used when neither `AGENOMIC_ENDPOINT`
/// nor a profile endpoint is configured. The web origin rewrites `/v1/*`
/// to the API gateway, so it serves CLI traffic too.
pub const DEFAULT_ENDPOINT: &str = "https://app.agenomic.io";

/// Operating mode of a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileMode {
    Offline,
    Cloud,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileFileEntry {
    #[serde(default = "default_mode")]
    pub mode: ProfileMode,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub org: Option<String>,
}

fn default_mode() -> ProfileMode {
    ProfileMode::Offline
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: std::collections::BTreeMap<String, ProfileFileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialsFile {
    #[serde(default)]
    pub credentials: std::collections::BTreeMap<String, CredentialEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub api_key: String,
    #[serde(default)]
    pub active_bucket_slug: Option<String>,
}

/// `[init]` table from `agenomic.toml` (see `docs/init-and-update.md` §4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InitConfig {
    #[serde(default)]
    pub default_domain: Option<String>,
    #[serde(default)]
    pub default_criticality: Option<String>,
    /// Detection sources to enable (kebab-case labels), used when `--from` is absent.
    #[serde(default)]
    pub sources: Option<Vec<String>>,
}

/// `[update]` table from `agenomic.toml` (see `docs/init-and-update.md` §4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateConfig {
    #[serde(default)]
    pub auto_commit: Option<bool>,
    #[serde(default)]
    pub sign: Option<bool>,
    #[serde(default)]
    pub protected_branches: Option<Vec<String>>,
    #[serde(default)]
    pub commit_template: Option<String>,
}

/// Project config from `agenomic.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectConfig {
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub spec_version: Option<String>,
    #[serde(default)]
    pub default_output: Option<PathBuf>,
    #[serde(default)]
    pub validation_level: Option<ValidationLevel>,
    #[serde(default)]
    pub fail_on: Option<Severity>,
    #[serde(default)]
    pub cloud_profile: Option<String>,
    #[serde(default)]
    pub init: Option<InitConfig>,
    #[serde(default)]
    pub update: Option<UpdateConfig>,
}

/// Resolved profile (merged from file + env).
#[derive(Debug, Clone)]
pub struct ProfileConfig {
    pub name: String,
    pub mode: ProfileMode,
    pub endpoint: Option<String>,
    pub org: Option<String>,
    pub api_key: Option<SecretString>,
    pub active_bucket_slug: Option<String>,
}

/// Final effective configuration.
pub struct EffectiveConfig {
    pub default_profile: String,
    pub profile: ProfileConfig,
    pub project: Option<ProjectConfig>,
}

/// Load configuration with the given (optional) profile override.
///
/// Precedence:
/// 1. CLI flags (caller's responsibility)
/// 2. Environment variables (`AGENOMIC_PROFILE`, `AGENOMIC_API_KEY`,
///    `AGENOMIC_ENDPOINT`)
/// 3. Project `agenomic.toml`
/// 4. User `config.toml` / `credentials.toml`
/// 5. Built-in defaults
///
/// ```no_run
/// let cfg = agenomic_config::load(None).unwrap();
/// println!("{}", cfg.default_profile);
/// ```
pub fn load(profile: Option<&str>) -> CliResult<EffectiveConfig> {
    let user_cfg = read_user_config()?;
    let creds = read_credentials()?;

    let env_profile = std::env::var("AGENOMIC_PROFILE").ok();
    let project = load_project_walking_up(&std::env::current_dir().unwrap_or_default())?;

    let chosen_profile_name = profile
        .map(str::to_string)
        .or(env_profile)
        .or_else(|| project.as_ref().and_then(|p| p.cloud_profile.clone()))
        .or(user_cfg.default_profile.clone())
        .unwrap_or_else(|| "default".to_string());

    let file_profile = user_cfg
        .profiles
        .get(&chosen_profile_name)
        .cloned()
        .unwrap_or(ProfileFileEntry {
            mode: ProfileMode::Offline,
            endpoint: None,
            org: None,
        });

    let endpoint = std::env::var("AGENOMIC_ENDPOINT")
        .ok()
        .or(file_profile.endpoint.clone());
    let api_key_str = std::env::var("AGENOMIC_API_KEY").ok().or_else(|| {
        creds
            .credentials
            .get(&chosen_profile_name)
            .map(|c| c.api_key.clone())
    });
    let active_bucket_slug = creds
        .credentials
        .get(&chosen_profile_name)
        .and_then(|c| c.active_bucket_slug.clone());

    let mode = match (&file_profile.mode, &api_key_str, &endpoint) {
        (ProfileMode::Cloud, _, _) => ProfileMode::Cloud,
        (ProfileMode::Offline, Some(_), Some(_)) => ProfileMode::Cloud,
        _ => ProfileMode::Offline,
    };

    let resolved = ProfileConfig {
        name: chosen_profile_name.clone(),
        mode,
        endpoint,
        org: file_profile.org.clone(),
        api_key: api_key_str.map(|s| SecretString::new(s.into_boxed_str())),
        active_bucket_slug,
    };

    Ok(EffectiveConfig {
        default_profile: user_cfg
            .default_profile
            .unwrap_or_else(|| "default".to_string()),
        profile: resolved,
        project,
    })
}

/// Persist a profile (without credentials) into the user config.
pub fn save_profile(name: &str, profile: &ProfileFileEntry) -> CliResult<()> {
    let mut cfg = read_user_config().unwrap_or_default();
    cfg.profiles.insert(name.to_string(), profile.clone());
    if cfg.default_profile.is_none() {
        cfg.default_profile = Some(name.to_string());
    }
    let path = config_file_path()?;
    let bytes = toml::to_string_pretty(&cfg)
        .map_err(|e| CliError::Internal(format!("config serialize: {e}")))?;
    agenomic_fs::write_atomic(&path, bytes.as_bytes())?;
    Ok(())
}

/// Persist credentials (mode 0600 on Unix).
pub fn save_credentials(name: &str, api_key: &SecretString) -> CliResult<()> {
    let mut creds = read_credentials().unwrap_or_default();
    let active_bucket_slug = creds
        .credentials
        .get(name)
        .and_then(|entry| entry.active_bucket_slug.clone());
    creds.credentials.insert(
        name.to_string(),
        CredentialEntry {
            api_key: api_key.expose_secret().to_string(),
            active_bucket_slug,
        },
    );
    let path = credentials_file_path()?;
    let bytes = toml::to_string_pretty(&creds)
        .map_err(|e| CliError::Internal(format!("credentials serialize: {e}")))?;
    agenomic_fs::write_atomic(&path, bytes.as_bytes())?;
    agenomic_fs::set_secret_mode(&path)?;
    Ok(())
}

/// Persist or clear the active bucket for a profile.
///
/// ```no_run
/// # use agenomic_config::save_active_bucket;
/// save_active_bucket("default", Some("default"))?;
/// # Ok::<(), agenomic_core::CliError>(())
/// ```
pub fn save_active_bucket(name: &str, bucket_slug: Option<&str>) -> CliResult<()> {
    let mut creds = read_credentials().unwrap_or_default();
    let entry = creds
        .credentials
        .get_mut(name)
        .ok_or(CliError::AuthFailed)?;
    entry.active_bucket_slug = bucket_slug.map(str::to_string);
    let path = credentials_file_path()?;
    let bytes = toml::to_string_pretty(&creds)
        .map_err(|e| CliError::Internal(format!("credentials serialize: {e}")))?;
    agenomic_fs::write_atomic(&path, bytes.as_bytes())?;
    agenomic_fs::set_secret_mode(&path)?;
    Ok(())
}

/// Remove credentials for a profile.
pub fn delete_credentials(name: &str) -> CliResult<()> {
    let mut creds = read_credentials().unwrap_or_default();
    creds.credentials.remove(name);
    let path = credentials_file_path()?;
    let bytes = toml::to_string_pretty(&creds)
        .map_err(|e| CliError::Internal(format!("credentials serialize: {e}")))?;
    agenomic_fs::write_atomic(&path, bytes.as_bytes())?;
    agenomic_fs::set_secret_mode(&path)?;
    Ok(())
}

fn read_user_config() -> CliResult<ConfigFile> {
    let path = config_file_path()?;
    if !path.exists() {
        return Ok(ConfigFile::default());
    }
    let s = std::fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
    toml::from_str(&s).map_err(|e| CliError::Internal(format!("config parse: {e}")))
}

fn read_credentials() -> CliResult<CredentialsFile> {
    let path = credentials_file_path()?;
    if !path.exists() {
        return Ok(CredentialsFile::default());
    }
    let s = std::fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
    toml::from_str(&s).map_err(|e| CliError::Internal(format!("credentials parse: {e}")))
}

/// Load the nearest `agenomic.toml` by walking up from `start`, returning
/// `None` if none is found. Exposed for `agm init`/`agm update` to read the
/// `[init]`/`[update]` tables.
///
/// ```no_run
/// let cfg = agenomic_config::load_project_walking_up(std::path::Path::new(".")).unwrap();
/// println!("{}", cfg.is_some());
/// ```
pub fn load_project_walking_up(start: &Path) -> CliResult<Option<ProjectConfig>> {
    let mut cur = start.to_path_buf();
    loop {
        let candidate = cur.join("agenomic.toml");
        if candidate.is_file() {
            let text = std::fs::read_to_string(&candidate).map_err(|e| io_at(&candidate, e))?;
            let p: ProjectConfig = toml::from_str(&text)
                .map_err(|e| CliError::Internal(format!("project config parse: {e}")))?;
            return Ok(Some(p));
        }
        if !cur.pop() {
            break;
        }
    }
    Ok(None)
}

/// Path to the user config TOML.
pub fn config_file_path() -> CliResult<PathBuf> {
    let dirs = ProjectDirs::from(APP_QUALIFIER, APP_ORG, APP_NAME)
        .ok_or_else(|| CliError::Internal("could not determine config directory".into()))?;
    Ok(dirs.config_dir().join("config.toml"))
}

/// Path to the credentials TOML.
pub fn credentials_file_path() -> CliResult<PathBuf> {
    let dirs = ProjectDirs::from(APP_QUALIFIER, APP_ORG, APP_NAME)
        .ok_or_else(|| CliError::Internal("could not determine config directory".into()))?;
    Ok(dirs.config_dir().join("credentials.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_config_walks_up() {
        let d = tempfile::tempdir().unwrap();
        let inner = d.path().join("a/b/c");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(
            d.path().join("agenomic.toml"),
            "agent_id = 'agent://acme/foo'\nspec_version = '0.1'\n",
        )
        .unwrap();
        let p = load_project_walking_up(&inner).unwrap();
        assert!(p.is_some());
        assert_eq!(p.unwrap().agent_id.as_deref(), Some("agent://acme/foo"));
    }

    #[test]
    fn parses_init_and_update_tables() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("agenomic.toml"),
            "[init]\ndefault_domain = \"finance\"\nsources = [\"pyproject\", \"git\"]\n\
             [update]\nauto_commit = false\nprotected_branches = [\"main\", \"release/*\"]\n\
             commit_template = \"chore: bundle {step} {hash}\"\n",
        )
        .unwrap();
        let p = load_project_walking_up(d.path()).unwrap().unwrap();
        let init = p.init.unwrap();
        assert_eq!(init.default_domain.as_deref(), Some("finance"));
        assert_eq!(
            init.sources.unwrap(),
            vec!["pyproject".to_string(), "git".to_string()]
        );
        let update = p.update.unwrap();
        assert_eq!(update.auto_commit, Some(false));
        assert_eq!(
            update.protected_branches.unwrap(),
            vec!["main".to_string(), "release/*".to_string()]
        );
        assert_eq!(
            update.commit_template.as_deref(),
            Some("chore: bundle {step} {hash}")
        );
    }

    #[test]
    fn config_path_is_under_config_dir() {
        let p = config_file_path().unwrap();
        let s = p.display().to_string();
        assert!(s.contains("agenomic"), "{s}");
    }

    #[test]
    fn save_credentials_preserves_active_bucket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let mut creds = CredentialsFile::default();
        creds.credentials.insert(
            "default".into(),
            CredentialEntry {
                api_key: "old-key".into(),
                active_bucket_slug: Some("bench".into()),
            },
        );
        let bytes = toml::to_string_pretty(&creds).unwrap();
        std::fs::write(&path, bytes).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let mut loaded: CredentialsFile = toml::from_str(&raw).unwrap();
        let active_bucket_slug = loaded
            .credentials
            .get("default")
            .and_then(|entry| entry.active_bucket_slug.clone());
        loaded.credentials.insert(
            "default".into(),
            CredentialEntry {
                api_key: "new-key".into(),
                active_bucket_slug,
            },
        );
        let updated = loaded.credentials.get("default").unwrap();
        assert_eq!(updated.api_key, "new-key");
        assert_eq!(updated.active_bucket_slug.as_deref(), Some("bench"));
    }
}
