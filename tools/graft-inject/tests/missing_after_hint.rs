//! Discovery-pass test: a manifest's `after = ["X"]` hint must NOT
//! hard-error when X is absent from the discovered set.
//!
//! Per `cli.md` §"Priority lattice", `after` is a soft ordering hint.
//! Earlier graft-inject revisions hard-errored on missing hints; this
//! test pins the new contract — the hint is logged on stderr and
//! ignored, with priority-based ordering still applying.
//!
//! The catalog's transitive after-chain (settle ← mint ← guard ← forge
//! ← kv ← counter ← queue ← rbac ← registry) makes the hard-error
//! variant unusable for any cp'd subset that omits an early link;
//! eight of nine R2 dogfood rounds hit it before the demotion.
//!
//! Test runs `graft-inject --list --json` against a scratch lib/ with
//! two synthetic manifests:
//!   - alpha-graft (priority 50, no `after`)
//!   - beta-graft  (priority 60, `after = ["nonexistent-graft"]`)
//!
//! Asserts: exit 0, stderr carries the ignore note, stdout JSON lists both grafts in priority order (alpha before beta).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const ALPHA_TOML: &str = r#"
[graft]
name     = "alpha-graft"
version  = "0.1.0"
priority = 50

[graft.blocks]
"#;

const BETA_TOML: &str = r#"
[graft]
name     = "beta-graft"
version  = "0.1.0"
priority = 60
after    = ["nonexistent-graft"]

[graft.blocks]
"#;

fn scratch_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("graft-inject manifest dir has a grandparent")
        .join("target")
        .join("missing_after_hint_lib");
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("clean scratch lib");
    }
    fs::create_dir_all(&dir).expect("create scratch lib");
    dir
}

fn graft_inject_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_graft-inject"))
}

#[test]
fn missing_after_hint_is_soft() {
    let lib = scratch_dir();
    fs::write(lib.join("alpha-graft.toml"), ALPHA_TOML).unwrap();
    fs::write(lib.join("beta-graft.toml"), BETA_TOML).unwrap();

    let output = Command::new(graft_inject_bin())
        .arg("--accept-untrusted-libs").arg("--lib-dir")
        .arg(&lib)
        .arg("--list")
        .arg("--json")
        .output()
        .expect("spawn graft-inject");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "graft-inject must exit 0 when an after-hint references a missing graft\n\
         status: {:?}\nstdout: {}\nstderr: {}",
        output.status,
        stdout,
        stderr
    );

    assert!(
        stderr.contains("note") && stderr.contains("nonexistent-graft"),
        "stderr must carry the ignore note for the missing after-hint; got:\n{}",
        stderr
    );

    let alpha_pos = stdout.find("alpha-graft").expect("alpha-graft listed");
    let beta_pos = stdout.find("beta-graft").expect("beta-graft listed");
    assert!(
        alpha_pos < beta_pos,
        "priority ordering must place alpha-graft (50) before beta-graft (60); got:\n{}",
        stdout
    );
}
