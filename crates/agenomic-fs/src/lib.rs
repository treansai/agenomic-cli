//! Safe filesystem helpers: deterministic walk, atomic write, gitignore-style
//! pattern parser, and Unix file-mode helpers.

pub mod atomic;
pub mod ignore;
pub mod walk;

pub use atomic::{set_secret_mode, write_atomic};
pub use ignore::IgnoreFile;
pub use walk::{
    walk_bundle, EntryKind, WalkEntry, WalkOptions, DEFAULT_EXCLUDES, SECURITY_EXCLUDES,
};
