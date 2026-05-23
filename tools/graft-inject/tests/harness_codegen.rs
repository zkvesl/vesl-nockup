//! Byte-equality test for the committed `generated_harness.rs`.
//!
//! Runs `nockup-graft codegen harness-methods` against the canonical
//! sidecar + lib dir, captures the emitted Rust, and asserts byte
//! equality with the committed
//! `test/vesl-test/src/generated_harness.rs`. The committed file is
//! the source of truth that downstream `cargo build`s see; if a sidecar
//! or per-graft poke-arm change drifts the generator's output, this
//! test fires and the contributor re-runs the codegen.
//!
//! The test is structured so its failure message points the contributor
//! at the exact regen command.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("tools/graft-inject manifest dir has two parents (= vesl-nockup root)")
}

#[test]
fn committed_generated_harness_matches_codegen_output() {
    let repo = repo_root();
    let committed = repo.join("test/vesl-test/src/generated_harness.rs");

    let bin_status = Command::new("cargo")
        .args(["build", "-p", "graft-inject", "--bin", "nockup-graft"])
        .current_dir(&repo)
        .status()
        .expect("spawn cargo build");
    assert!(bin_status.success(), "cargo build nockup-graft failed");

    let bin = repo.join("target/debug/nockup-graft");
    assert!(bin.exists(), "nockup-graft binary missing at {}", bin.display());

    // Invoke from the repo root with relative paths so the generated
    // file's `//! Source:` line matches what the maintainer-run
    // regen-command (the one in the failure hint) produces.
    let out = Command::new(&bin)
        .args([
            "codegen",
            "harness-methods",
            "--bindings",
            "hoon/lib/harness-bindings.toml",
            "--lib-dir",
            "hoon/lib",
        ])
        .current_dir(&repo)
        .output()
        .expect("spawn nockup-graft codegen harness-methods");
    assert!(
        out.status.success(),
        "nockup-graft codegen failed: stdout=`{}` stderr=`{}`",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let generated = String::from_utf8(out.stdout).expect("codegen output is UTF-8");
    let on_disk =
        std::fs::read_to_string(&committed).expect("committed generated_harness.rs exists");

    if generated != on_disk {
        // Surface the first divergent line for fast triage.
        let diff_summary = first_divergent_line(&on_disk, &generated);
        panic!(
            "test/vesl-test/src/generated_harness.rs is stale vs the codegen output.\n\
             Re-run:\n\
             \n\
             \tcargo run -p graft-inject --bin nockup-graft -- \\\n\
             \t  codegen harness-methods \\\n\
             \t  --bindings hoon/lib/harness-bindings.toml \\\n\
             \t  --lib-dir hoon/lib \\\n\
             \t  --out test/vesl-test/src/generated_harness.rs\n\
             \n\
             First divergence: {diff_summary}"
        );
    }
}

fn first_divergent_line(a: &str, b: &str) -> String {
    let a_lines: Vec<&str> = a.lines().collect();
    let b_lines: Vec<&str> = b.lines().collect();
    let n = a_lines.len().min(b_lines.len());
    for i in 0..n {
        if a_lines[i] != b_lines[i] {
            return format!(
                "line {} differs.\n  on disk: {}\n  emitted: {}",
                i + 1,
                a_lines[i],
                b_lines[i]
            );
        }
    }
    if a_lines.len() != b_lines.len() {
        format!(
            "line counts differ: on disk = {} lines, emitted = {} lines",
            a_lines.len(),
            b_lines.len()
        )
    } else {
        "trailing-newline difference".to_string()
    }
}
