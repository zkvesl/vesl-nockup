//! Build script that captures the SHA of the latest commit touching
//! `tools/graft-inject/src/`. The runtime uses this to detect when the
//! installed binary has fallen behind source — see `warn_if_stale` in
//! `main.rs`.
//!
//! Silent fallbacks (no `cargo:warning`):
//! - No `git` on PATH, or `git log` fails (release tarball, vendored
//!   build, sandboxed CI without git).
//! - The manifest dir isn't inside a git work tree.
//! - `src/` has no commits (fresh repo before first commit).
//!
//! In any of those cases the embedded SHA is `unknown` and the
//! runtime check no-ops. The check only fires for installs that
//! happened from a git checkout, which is the dogfood scenario.

use std::process::Command;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());

    let src_sha = Command::new("git")
        .args(["-C", &manifest_dir, "log", "-1", "--format=%H", "--", "src"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=GRAFT_INJECT_BUILD_SRC_SHA={src_sha}");
    println!("cargo:rustc-env=GRAFT_INJECT_MANIFEST_DIR={manifest_dir}");

    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");
}
