//! Build script that captures a content-hash of `tools/graft-inject/src/`
//! at build time. The runtime uses this to detect when the installed
//! binary has fallen behind source — see `warn_if_stale` in `main.rs`.
//!
//! RH1 step 3 (HARD-FRICTION-1): the previous metric was `git log -1
//! --format=%H -- src` (latest commit touching src/). In a working
//! checkout where source has advanced past the binary's git context,
//! that fired the warning on every invocation. A content-hash compares
//! actual bytes, so the warning fires when (and only when) the source
//! tree differs from what the binary was built against.
//!
//! Silent fallbacks (no `cargo:warning`):
//! - `src/` walk fails (release tarball with src stripped, vendored
//!   build with non-standard layout).
//! - The manifest dir isn't readable.
//!
//! In any of those cases the embedded hash is `unknown` and the runtime
//! check no-ops. The check only fires for installs that happened from
//! a normal source checkout, which is the dogfood scenario.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let src_root = Path::new(&manifest_dir).join("src");

    let src_hash = hash_dir(&src_root).unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=GRAFT_INJECT_BUILD_SRC_HASH={src_hash}");
    println!("cargo:rustc-env=GRAFT_INJECT_MANIFEST_DIR={manifest_dir}");

    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");
}

/// Recursively walk `dir`, sort entries by relative path, and feed
/// `(relative_path_bytes, file_bytes)` into a single sha256 digest.
/// Sorting makes the hash deterministic across filesystems whose
/// `read_dir` order is implementation-defined.
fn hash_dir(dir: &Path) -> std::io::Result<String> {
    let mut entries: Vec<PathBuf> = Vec::new();
    collect_files(dir, &mut entries)?;
    entries.sort();

    let mut hasher = Sha256::new();
    for path in &entries {
        let rel = path.strip_prefix(dir).unwrap_or(path);
        // Use forward-slash form so the hash matches across Windows / Unix.
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        hasher.update(rel_str.as_bytes());
        hasher.update(b"\0");
        let bytes = fs::read(path)?;
        hasher.update(&bytes);
        hasher.update(b"\0");
    }

    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_files(&path, out)?;
        } else if ft.is_file() {
            out.push(path);
        }
        // Symlinks intentionally skipped — keep the hash content-only.
    }
    Ok(())
}
