//! Cross-cutting helpers that don't fit any single pipeline module:
//! binary staleness detection and `--lib-dir` trust-posture warnings.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// One-line stderr warning when the binary's content-hash of `src/`
/// (captured at build time by `build.rs`) doesn't match the current
/// content-hash of `src/` in the manifest dir. Catches the dogfood
/// case where a global `cargo install --path tools/graft-inject` ran
/// weeks ago and has fallen behind source.
///
/// An earlier metric — `git log -1 -- src`, the latest commit touching
/// src/ — fired in a working checkout where source had advanced past
/// the binary's git context even when the binary's `src/` bytes already
/// matched. A content-hash fires only when actual bytes differ.
///
/// Silent when:
/// - The build hash is `unknown` (build.rs couldn't walk src/).
/// - The manifest dir from build time no longer exists on this machine
///   (binary was moved, or the source checkout was deleted).
/// - The runtime walk of src/ fails for any reason.
/// - The current content-hash matches the build hash (binary is current).
///
/// Suppress entirely with `GRAFT_INJECT_NO_STALENESS_WARNING=1` for
/// CI runs that don't want the noise.
pub(crate) fn warn_if_stale() {
    if std::env::var("GRAFT_INJECT_NO_STALENESS_WARNING").is_ok() {
        return;
    }
    let build_hash = env!("GRAFT_INJECT_BUILD_SRC_HASH");
    if build_hash == "unknown" {
        return;
    }
    let manifest_dir = env!("GRAFT_INJECT_MANIFEST_DIR");
    let src_root = Path::new(manifest_dir).join("src");
    if !src_root.exists() {
        return;
    }
    let Ok(current_hash) = hash_src_dir(&src_root) else {
        return;
    };
    if current_hash == build_hash {
        return;
    }
    let short = |s: &str| s.chars().take(12).collect::<String>();
    eprintln!(
        "graft-inject: warning — binary built from src/ hash {} but src/ \
         is now at {}.\n  Rebuild from the published source:\n    \
         cargo install --git https://github.com/zkvesl/vesl-nockup \
         --bin nockup-graft --force\n  Or from a local checkout:\n    \
         cargo install --path tools/graft-inject --bin nockup-graft --force",
        short(build_hash),
        short(&current_hash),
    );
}

/// Mirror of `build.rs::hash_dir` for runtime staleness check. Walks
/// `dir` recursively, sorts entries by relative path for determinism,
/// and digests `(relative_path_bytes \0 file_bytes \0)` into a sha256.
/// Must stay byte-compatible with the build-time helper.
fn hash_src_dir(dir: &Path) -> std::io::Result<String> {
    let mut entries: Vec<PathBuf> = Vec::new();
    collect_src_files(dir, &mut entries)?;
    entries.sort();

    let mut hasher = Sha256::new();
    for path in &entries {
        let rel = path.strip_prefix(dir).unwrap_or(path);
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

fn collect_src_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_src_files(&path, out)?;
        } else if ft.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Refuse a `--lib-dir` outside any project tree unless the caller
/// opted in with `--accept-untrusted-libs`.
///
/// A `--lib-dir` with no `nockapp.toml` ancestor is almost always a
/// mistake — and the loader splices any `*.toml` `[graft]` table it
/// finds verbatim into the user's compiled Hoon. An out-of-tree
/// lib-dir is a hard error; `--accept-untrusted-libs` downgrades it to
/// a warning for tests and other deliberate out-of-tree uses.
pub(crate) fn check_lib_dir_trust(
    lib_dir: &Path,
    accept_untrusted: bool,
) -> anyhow::Result<()> {
    let canonical = match lib_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    if has_nockapp_toml_ancestor(&canonical) {
        return Ok(());
    }
    if accept_untrusted {
        eprintln!(
            "graft-inject: warning — --lib-dir {} is outside any project \
             (no `nockapp.toml` ancestor); accepted via --accept-untrusted-libs.",
            canonical.display()
        );
        return Ok(());
    }
    anyhow::bail!(
        "--lib-dir {} is outside any project (no `nockapp.toml` ancestor). \
         Graft manifests there are spliced verbatim into compiled Hoon — \
         re-run with --accept-untrusted-libs if you trust this directory.",
        canonical.display()
    )
}

fn has_nockapp_toml_ancestor(start: &Path) -> bool {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        if dir.join("nockapp.toml").is_file() {
            return true;
        }
        cur = dir.parent();
    }
    false
}
