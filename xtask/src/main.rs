use std::env;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, Context, Result};

fn main() -> Result<()> {
    let task = env::args().nth(1).unwrap_or_else(|| "help".into());
    match task.as_str() {
        "dist" => dist(),
        "schemas" => schemas(),
        "examples" => examples(),
        _ => {
            println!("usage: cargo xtask <dist|schemas|examples>");
            Ok(())
        }
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default()
}

fn dist() -> Result<()> {
    let root = workspace_root();
    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", "agenomic-cli", "--release"])
        .current_dir(&root)
        .status()
        .context("cargo build")?;
    if !status.success() {
        return Err(anyhow!("cargo build failed"));
    }
    println!("built target/release/agenomic");
    Ok(())
}

fn schemas() -> Result<()> {
    for kind in agenomic_spec::SchemaKind::ALL {
        agenomic_spec::validator(kind)
            .map_err(|e| anyhow!("schema {} failed to compile: {e}", kind.label()))?;
        println!("ok  {}", kind.label());
    }
    Ok(())
}

fn examples() -> Result<()> {
    let root = workspace_root();
    for ex in ["claims-agent", "support-agent", "trading-risk-agent"] {
        let path = root.join("examples").join(ex);
        let status = Command::new(env!("CARGO"))
            .args([
                "run",
                "-p",
                "agenomic-cli",
                "--quiet",
                "--",
                "validate",
                path.to_str().expect("utf-8 path"),
                "--level",
                "strict",
            ])
            .current_dir(&root)
            .status()?;
        if !status.success() {
            return Err(anyhow!("example {ex} failed strict validation"));
        }
        println!("ok  {ex}");
    }
    Ok(())
}
