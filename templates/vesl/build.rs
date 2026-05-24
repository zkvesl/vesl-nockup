//! Scaffold build script. Declares the `out.jam` rerun and runs
//! `nockup-graft doctor` on every build, so project-health findings —
//! a manifest-schema version skew, a Cargo `[patch]` inconsistency, a
//! hand-edited graft block, a missing `nockup:load-defaults` marker —
//! surface as `cargo:warning=` lines in output you are already reading.
//!
//! The doctor pass only ever warns: every failure path degrades to a
//! single warning, never a build failure. It is also strictly
//! read-only — composition stays an explicit `nockup graft inject` step.

use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=out.jam");
    // Re-run the doctor pass when its inputs change — the kernel, the
    // graft library, and the dependency manifest.
    println!("cargo:rerun-if-changed=hoon/app/app.hoon");
    println!("cargo:rerun-if-changed=hoon/lib");
    println!("cargo:rerun-if-changed=Cargo.toml");

    run_doctor();
}

/// Run `nockup-graft doctor --format build-warnings` and forward each
/// finding to cargo as a build warning. Every path here ends in a
/// `cargo:warning=` or a silent return — the build never fails because
/// of the doctor pass.
fn run_doctor() {
    let app = "hoon/app/app.hoon";
    if !Path::new(app).exists() {
        return;
    }
    // Resolve the binary in two steps: explicit NOCKUP_GRAFT_BIN first,
    // then a single well-known location at ~/.cargo/bin/nockup-graft.
    // Never a bare PATH search — a malicious `nockup-graft` earlier on
    // PATH would otherwise hijack `cargo build`. ~/.cargo/bin is
    // user-owned and the canonical destination of `cargo install`, so
    // it's the install location the published quickstart documents.
    let graft_bin = env::var("NOCKUP_GRAFT_BIN").ok().or_else(|| {
        env::var_os("HOME").and_then(|home| {
            let candidate = Path::new(&home).join(".cargo/bin/nockup-graft");
            candidate
                .exists()
                .then(|| candidate.to_string_lossy().into_owned())
        })
    });
    let graft_bin = match graft_bin {
        Some(p) => p,
        None => {
            println!(
                "cargo:warning=nockup-graft doctor skipped — install via \
                 `cargo install --git https://github.com/zkvesl/vesl-nockup \
                 --bin nockup-graft --force --locked` (lands at \
                 ~/.cargo/bin/nockup-graft), or set NOCKUP_GRAFT_BIN to a \
                 binary path."
            );
            return;
        }
    };
    match Command::new(&graft_bin)
        .args(["doctor", app, "--format", "build-warnings"])
        .output()
    {
        Ok(r) => {
            for line in String::from_utf8_lossy(&r.stdout).lines() {
                if !line.trim().is_empty() {
                    println!("cargo:warning={line}");
                }
            }
            // `doctor --format build-warnings` exits 0 by contract even
            // with findings; a nonzero status means the pass itself
            // failed (bad install, unreadable project). Surface it as
            // one warning and let the build continue.
            if !r.status.success() {
                println!(
                    "cargo:warning=nockup-graft doctor exited nonzero: {}",
                    String::from_utf8_lossy(&r.stderr).trim()
                );
            }
        }
        Err(e) => {
            println!(
                "cargo:warning=could not run nockup-graft doctor: {e}; \
                 skipping the project-health pass."
            );
        }
    }
}
