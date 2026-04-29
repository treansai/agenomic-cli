pub mod bundle;
pub mod errors;
pub mod models;
pub mod validate;

pub use bundle::{
    collect_bundle_file_entries, default_attestation_output, init_bundle_dir, load_bundle_dir,
    normalized_relative_path, BundleFileEntry, AGENT_LOCK_FILE, BEHAVIOR_CONTRACT_FILE,
    GENOME_FILE, PROMPTS_DIR, SYSTEM_PROMPT_FILE,
};
pub use errors::AgentlockError;
pub use models::*;
pub use validate::{
    hash_bundle_dir, hash_bundle_from_entries, parse_trace_events, validate_bundle_dir,
};
