//! Integration tests for `nockup-graft rename-kernel`. Spawns the
//! compiled binary inside a tempdir scaffold and asserts disk state.

use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_graft-inject");

const APP_HOON_BODY: &str = "/+  lib\n::  nockup:imports\n";
const NOCKAPP_TOML_BODY: &str = "\
# A leading comment that toml_edit must preserve on rewrite.
[project]
name = \"test-rename\"
template = \"vesl\"
";
const README_BODY: &str = "\
# test-rename

Build:

```bash
hoonc --new hoon/app/app.hoon hoon/
```

Run:

```bash
cargo +nightly run --release -- hoon/app/app.hoon
```
";

fn scaffold(root: &Path) {
    fs::create_dir_all(root.join("hoon/app")).unwrap();
    fs::write(root.join("hoon/app/app.hoon"), APP_HOON_BODY).unwrap();
    fs::write(root.join("nockapp.toml"), NOCKAPP_TOML_BODY).unwrap();
    fs::write(root.join("README.md"), README_BODY).unwrap();
}

fn run(args: &[&str], cwd: &Path) -> (bool, String) {
    let out = Command::new(BIN)
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn graft-inject");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), stderr)
}

#[test]
fn happy_path_renames_kernel_toml_and_readme() {
    let tmp = TempDir::new().unwrap();
    scaffold(tmp.path());

    let (ok, _) = run(&["rename-kernel", "wallet", "--apply"], tmp.path());
    assert!(ok, "rename-kernel --apply must succeed on a clean tree");

    assert!(tmp.path().join("hoon/app/wallet.hoon").is_file());
    assert!(!tmp.path().join("hoon/app/app.hoon").exists());

    let toml = fs::read_to_string(tmp.path().join("nockapp.toml")).unwrap();
    assert!(toml.contains("kernel_name = \"wallet\""), "toml: {toml}");
    assert!(
        toml.contains("# A leading comment"),
        "comment must survive toml_edit roundtrip"
    );

    let readme = fs::read_to_string(tmp.path().join("README.md")).unwrap();
    assert!(readme.contains("hoon/app/wallet.hoon"));
    assert!(!readme.contains("hoon/app/app.hoon"));
}

#[test]
fn preview_mode_does_not_write() {
    let tmp = TempDir::new().unwrap();
    scaffold(tmp.path());

    let (ok, _) = run(&["rename-kernel", "wallet"], tmp.path());
    assert!(ok);

    assert!(tmp.path().join("hoon/app/app.hoon").exists());
    assert!(!tmp.path().join("hoon/app/wallet.hoon").exists());

    let toml = fs::read_to_string(tmp.path().join("nockapp.toml")).unwrap();
    assert!(!toml.contains("kernel_name"));
}

#[test]
fn rerun_defaults_from_to_current_kernel_name() {
    let tmp = TempDir::new().unwrap();
    scaffold(tmp.path());

    let (ok1, _) = run(&["rename-kernel", "wallet", "--apply"], tmp.path());
    assert!(ok1);

    let (ok2, _) = run(&["rename-kernel", "mint", "--apply"], tmp.path());
    assert!(
        ok2,
        "second rename without --from must read kernel_name from toml"
    );

    assert!(tmp.path().join("hoon/app/mint.hoon").is_file());
    assert!(!tmp.path().join("hoon/app/wallet.hoon").exists());

    let toml = fs::read_to_string(tmp.path().join("nockapp.toml")).unwrap();
    assert!(toml.contains("kernel_name = \"mint\""));
}

#[test]
fn refuses_to_clobber_existing_target() {
    let tmp = TempDir::new().unwrap();
    scaffold(tmp.path());
    fs::write(tmp.path().join("hoon/app/wallet.hoon"), "stub").unwrap();

    let (ok, stderr) = run(&["rename-kernel", "wallet", "--apply"], tmp.path());
    assert!(!ok);
    assert!(
        stderr.contains("already exists"),
        "stderr should explain the clobber refusal: {stderr}"
    );
}

#[test]
fn rejects_invalid_name() {
    let tmp = TempDir::new().unwrap();
    scaffold(tmp.path());

    let (ok, stderr) = run(&["rename-kernel", "My-App", "--apply"], tmp.path());
    assert!(!ok);
    assert!(
        stderr.contains("lowercase"),
        "stderr should hint regex shape: {stderr}"
    );

    assert!(tmp.path().join("hoon/app/app.hoon").exists());
}

#[test]
fn bails_outside_a_project() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join("hoon/app")).unwrap();
    fs::write(tmp.path().join("hoon/app/app.hoon"), APP_HOON_BODY).unwrap();

    let (ok, stderr) = run(&["rename-kernel", "wallet", "--apply"], tmp.path());
    assert!(!ok);
    assert!(
        stderr.contains("nockapp.toml"),
        "stderr should mention the missing nockapp.toml: {stderr}"
    );
}

#[test]
fn missing_readme_skips_cleanly() {
    let tmp = TempDir::new().unwrap();
    scaffold(tmp.path());
    fs::remove_file(tmp.path().join("README.md")).unwrap();

    let (ok, stderr) = run(&["rename-kernel", "wallet", "--apply"], tmp.path());
    assert!(ok, "rename should succeed even without a README");
    assert!(
        stderr.contains("README.md skipped"),
        "stderr should announce the README skip: {stderr}"
    );

    assert!(tmp.path().join("hoon/app/wallet.hoon").is_file());
}
