//! Profile, credential, and project config for agentlock-cli.
//!
//! Files:
//! - User config: `~/.config/agentlock/config.toml` (cross-platform via `directories`)
//! - Credentials: `~/.config/agentlock/credentials.toml` (mode 0600)
//! - Project: `agentlock.toml` in cwd or any ancestor

use std::path::{Path, PathBuf};

use agentlock_core::{io_at, CliError, CliResult, Severity, ValidationLevel};
use directories::ProjectDirs;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

const APP_QUALIFIER: &str = "dev";
const APP_ORG: &str = "agentlock";
const APP_NAME: &str = "agentlock";

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
}

/// Project config from `agentlock.toml`.
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
}

/// Resolved profile (merged from file + env).
#[derive(Debug, Clone)]
pub struct ProfileConfig {
    pub name: String,
    pub mode: ProfileMode,
    pub endpoint: Option<String>,
    pub org: Option<String>,
    pub api_key: Option<SecretString>,
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
/// 2. Environment variables (`AGENTLOCK_PROFILE`, `AGENTLOCK_API_KEY`,
///    `AGENTLOCK_ENDPOINT`)
/// 3. Project `agentlock.toml`
/// 4. User `config.toml` / `credentials.toml`
/// 5. Built-in defaults
///
/// ```no_run
/// let cfg = agentlock_config::load(None).unwrap();
/// println!("{}", cfg.default_profile);
/// ```
pub fn load(profile: Option<&str>) -> CliResult<EffectiveConfig> {
    let user_cfg = read_user_config()?;
    let creds = read_credentials()?;

    let env_profile = std::env::var("AGENTLOCK_PROFILE").ok();
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

    let endpoint = std::env::var("AGENTLOCK_ENDPOINT")
        .ok()
        .or(file_profile.endpoint.clone());
    let api_key_str = std::env::var("AGENTLOCK_API_KEY").ok().or_else(|| {
        creds
            .credentials
            .get(&chosen_profile_name)
            .map(|c| c.api_key.clone())
    });

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
    agentlock_fs::write_atomic(&path, bytes.as_bytes())?;
    Ok(())
}

/// Persist credentials (mode 0600 on Unix).
pub fn save_credentials(name: &str, api_key: &SecretString) -> CliResult<()> {
    let mut creds = read_credentials().unwrap_or_default();
    creds.credentials.insert(
        name.to_string(),
        CredentialEntry {
            api_key: api_key.expose_secret().to_string(),
        },
    );
    let path = credentials_file_path()?;
    let bytes = toml::to_string_pretty(&creds)
        .map_err(|e| CliError::Internal(format!("credentials serialize: {e}")))?;
    agentlock_fs::write_atomic(&path, bytes.as_bytes())?;
    agentlock_fs::set_secret_mode(&path)?;
    Ok(())
}

/// Remove credentials for a profile.
pub fn delete_credentials(name: &str) -> CliResult<()> {
    let mut creds = read_credentials().unwrap_or_default();
    creds.credentials.remove(name);
    let path = credentials_file_path()?;
    let bytes = toml::to_string_pretty(&creds)
        .map_err(|e| CliError::Internal(format!("credentials serialize: {e}")))?;
    agentlock_fs::write_atomic(&path, bytes.as_bytes())?;
    agentlock_fs::set_secret_mode(&path)?;
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

fn load_project_walking_up(start: &Path) -> CliResult<Option<ProjectConfig>> {
    let mut cur = start.to_path_buf();
    loop {
        let candidate = cur.join("agentlock.toml");
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
            d.path().join("agentlock.toml"),
            "agent_id = 'agent://acme/foo'\nspec_version = '0.1'\n",
        )
        .unwrap();
        let p = load_project_walking_up(&inner).unwrap();
        assert!(p.is_some());
        assert_eq!(p.unwrap().agent_id.as_deref(), Some("agent://acme/foo"));
    }

    #[test]
    fn config_path_is_under_config_dir() {
        let p = config_file_path().unwrap();
        let s = p.display().to_string();
        assert!(s.contains("agentlock"), "{s}");
    }
}
