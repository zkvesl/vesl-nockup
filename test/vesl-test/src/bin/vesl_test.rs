//! `vesl-test` — runtime kernel introspection + build-provenance bin.
//!
//! Two subcommand families:
//!
//!   * `inspect peek` (Tool 4) — boots a compiled out.jam through the
//!     standard `GraftTestHarness`, runs a peek against the kernel's
//!     `++peek` arm, and prints the result. The CLI wraps the three
//!     peek-path families that already ship with vesl-core
//!     (`build_keyless_peek_path`, `build_hull_peek_path`,
//!     `build_keyed_peek_path`) — Hoon-literal path parsing is
//!     deliberately out of scope for the v1 cut.
//!   * `verify-jam` — sentinel-based out.jam-staleness
//!     check. Reads `.out-jam-source-fingerprint` (a `sha256sum`
//!     sidecar listing app.hoon + manifests), recomputes current
//!     hashes, exits 0 (fresh) / 1 (stale) / 2 (no fingerprint).
//!
//! Examples:
//!   vesl-test inspect peek out.jam --path-tag log-len
//!   vesl-test inspect peek out.jam --path-tag settle-registered --hull 1
//!   vesl-test inspect peek out.jam --path-tag kv-value --key greeting
//!   vesl-test inspect peek out.jam --path-tag log-len --json
//!   vesl-test verify-jam .
//!   vesl-test verify-jam path/to/project --json
//!   vesl-test watch out.jam
//!   vesl-test watch out.jam --json --filter cause=settle-register

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nock_noun_rs::NounSlab;
use nockvm::noun::{NounAllocator, NounHandle};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use vesl_core::{build_hull_peek_path, build_keyed_peek_path, build_keyless_peek_path};
use vesl_test::GraftTestHarness;
use vesl_test::watch::{self, DEFAULT_EFFECT_WINDOW_MS, WatchOpts};

#[derive(Parser, Debug)]
#[command(name = "vesl-test", about = "Runtime introspection + build-provenance for grafted NockApp kernels")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Boot a kernel and inspect its state from the outside.
    Inspect {
        #[command(subcommand)]
        sub: InspectCmd,
    },
    /// Verify out.jam is fresh against the source fingerprint sidecar.
    /// Exit 0 = fresh, 1 = stale, 2 = no fingerprint.
    VerifyJam {
        /// Project directory containing out.jam and
        /// .out-jam-source-fingerprint. Defaults to cwd.
        #[arg(default_value = ".")]
        project: PathBuf,
        /// Emit a structured JSON document to stdout instead of the
        /// human-readable form.
        #[arg(long)]
        json: bool,
    },
    /// REPL-style live-trace tool: boot a kernel, run `app.run()` in
    /// the background, subscribe to its effect_broadcast, and render
    /// one structured row per kernel event while reading poke/peek
    /// commands from stdin. See README §"Inspecting a kernel from the
    /// outside" for the stdin grammar and JSON schema.
    Watch {
        /// Compiled `out.jam` to boot.
        jam: PathBuf,
        /// `cause=<tag>` keeps only events whose cause matches; `effect=<tag>`
        /// keeps only events whose effect-list contains `<tag>`. Without a
        /// filter, every event is emitted.
        #[arg(long)]
        filter: Option<String>,
        /// Emit one JSON object per line instead of the human table.
        #[arg(long)]
        json: bool,
        /// Per-event drain window (ms) for the broadcast tap. After a
        /// poke acks, drain effects for this many ms before rendering.
        /// Default 100 ms.
        #[arg(long, default_value_t = DEFAULT_EFFECT_WINDOW_MS)]
        effect_window_ms: u64,
    },
}

#[derive(Subcommand, Debug)]
enum InspectCmd {
    /// Run a peek against the booted kernel's `++peek` arm.
    Peek {
        /// Compiled out.jam path.
        jam: PathBuf,
        /// Head tag of the peek path (e.g. `log-len`, `settle-count`,
        /// `settle-registered`, `kv-value`).
        #[arg(long)]
        path_tag: String,
        /// Hull index for hull-keyed peeks (`[%<tag> hull=@ ~]`).
        /// Mutually exclusive with `--key`.
        #[arg(long, conflicts_with = "key")]
        hull: Option<u64>,
        /// Cord key for keyed peeks (`[%<tag> key=@t ~]`).
        /// Mutually exclusive with `--hull`.
        #[arg(long, conflicts_with = "hull")]
        key: Option<String>,
        /// Emit a structured JSON document to stdout instead of the
        /// human-readable form.
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result: Result<u8> = match cli.cmd {
        Cmd::Inspect { sub } => match sub {
            InspectCmd::Peek {
                jam,
                path_tag,
                hull,
                key,
                json,
            } => run_peek(&jam, &path_tag, hull, key.as_deref(), json)
                .await
                .map(|()| 0),
        },
        Cmd::VerifyJam { project, json } => run_verify_jam(&project, json).await,
        Cmd::Watch {
            jam,
            filter,
            json,
            effect_window_ms,
        } => run_watch(jam, filter, json, effect_window_ms)
            .await
            .map(|()| 0),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("vesl-test: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run_watch(
    jam: PathBuf,
    filter: Option<String>,
    json: bool,
    effect_window_ms: u64,
) -> Result<()> {
    let opts = WatchOpts {
        jam,
        json,
        filter: watch::parse_filter(filter.as_deref())?,
        effect_window: Duration::from_millis(effect_window_ms),
    };
    watch::run_with_jam(opts).await
}

async fn run_peek(
    jam: &PathBuf,
    tag: &str,
    hull: Option<u64>,
    key: Option<&str>,
    json_out: bool,
) -> Result<()> {
    let mut harness = GraftTestHarness::boot(jam)
        .await
        .with_context(|| format!("boot kernel from {}", jam.display()))?;
    let path = build_path(tag, hull, key);
    let result = harness
        .peek_raw(path)
        .await
        .with_context(|| format!("peek against {}", jam.display()))?;

    let path_repr = format_path(tag, hull, key);
    let outcome = classify(&result);

    if json_out {
        println!("{}", emit_json(&path_repr, &outcome));
    } else {
        emit_human(&path_repr, &outcome);
    }
    Ok(())
}

fn build_path(tag: &str, hull: Option<u64>, key: Option<&str>) -> NounSlab {
    if let Some(h) = hull {
        build_hull_peek_path(tag, h)
    } else if let Some(k) = key {
        build_keyed_peek_path(tag, k)
    } else {
        build_keyless_peek_path(tag)
    }
}

fn format_path(tag: &str, hull: Option<u64>, key: Option<&str>) -> String {
    if let Some(h) = hull {
        format!("[%{tag} {h} ~]")
    } else if let Some(k) = key {
        format!("[%{tag} %{k} ~]")
    } else {
        format!("[%{tag} ~]")
    }
}

/// Three terminal states a `(unit (unit *))` peek can land in.
enum Outcome {
    /// Kernel returned bare `~` — the peek arm did not match this path.
    Unrecognized,
    /// Outer `[~ ~]` — path is recognized, value is absent.
    Absent,
    /// Outer `[~ [~ value]]` — path recognized, value present.
    Present(Value),
}

fn classify(result: &NounSlab) -> Outcome {
    // SAFETY: copy the Noun out immediately; the slab outlives this scope.
    let outer = unsafe { *result.root() };
    let space = result.noun_space();

    let outer_cell = match outer.in_space(&space).as_cell() {
        Ok(c) => c,
        Err(_) => return Outcome::Unrecognized,
    };
    let inner = outer_cell.tail();
    if inner.as_atom().is_ok() {
        // `[~ ~]` shape — atom 0 in the tail position.
        return Outcome::Absent;
    }
    let inner_cell = match inner.as_cell() {
        Ok(c) => c,
        Err(_) => return Outcome::Absent,
    };
    Outcome::Present(noun_to_json(inner_cell.tail()))
}

/// Recursive noun→JSON walker used both for human and JSON output.
///
/// Atoms render as `{atom: {decimal, ascii?}}`. ASCII is included when
/// the LE-byte sequence (after trimming trailing zeros) decodes to
/// printable UTF-8 — matching the convention `effect_tags` uses for
/// effect-head tags. Cells render as `{cell: [head, tail]}`.
fn noun_to_json(n: NounHandle<'_>) -> Value {
    if let Ok(atom) = n.as_atom() {
        let bytes = atom.as_ne_bytes();
        let trimmed: Vec<u8> = trim_trailing_zeros(bytes);
        let mut obj = serde_json::Map::new();
        obj.insert("decimal".into(), Value::String(format_decimal_dotted(&trimmed)));
        if let Some(s) = bytes_as_printable_ascii(&trimmed) {
            obj.insert("ascii".into(), Value::String(s));
        }
        return json!({ "atom": obj });
    }
    if let Ok(cell) = n.as_cell() {
        return json!({
            "cell": [
                noun_to_json(cell.head()),
                noun_to_json(cell.tail()),
            ]
        });
    }
    Value::Null
}

fn trim_trailing_zeros(bytes: &[u8]) -> Vec<u8> {
    let last = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    bytes[..last].to_vec()
}

fn bytes_as_printable_ascii(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let s = std::str::from_utf8(bytes).ok()?;
    if s.chars().all(|c| !c.is_control()) {
        Some(s.to_string())
    } else {
        None
    }
}

/// Format an atom's LE bytes as a `1.234.567`-style decimal — Hoon's
/// default formatter for atoms over `1.000`.
fn format_decimal_dotted(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".to_string();
    }
    // Reverse for LE -> BE, then strip leading zeros, then dot every three.
    let mut be: Vec<u8> = bytes.iter().rev().copied().collect();
    while be.len() > 1 && be[0] == 0 {
        be.remove(0);
    }
    // Convert to a decimal string by repeated division by 10. For short
    // values we can use u128, otherwise fall back to digit-by-digit.
    let decimal = if be.len() <= 16 {
        let mut acc: u128 = 0;
        for b in &be {
            acc = (acc << 8) | (*b as u128);
        }
        acc.to_string()
    } else {
        // For huge atoms, just hex-print so we don't bring in a bignum dep.
        format!("0x{}", be.iter().map(|b| format!("{:02x}", b)).collect::<String>())
    };
    add_dotted_thousands(&decimal)
}

fn add_dotted_thousands(s: &str) -> String {
    if s.starts_with("0x") || s.len() <= 3 {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::with_capacity(chars.len() + chars.len() / 3);
    for (i, c) in chars.iter().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push('.');
        }
        out.push(*c);
    }
    out.iter().rev().collect()
}

fn emit_json(path_repr: &str, outcome: &Outcome) -> String {
    let body = match outcome {
        Outcome::Unrecognized => json!({
            "path": path_repr,
            "recognized": false,
            "present": false,
            "value": Value::Null,
        }),
        Outcome::Absent => json!({
            "path": path_repr,
            "recognized": true,
            "present": false,
            "value": Value::Null,
        }),
        Outcome::Present(v) => json!({
            "path": path_repr,
            "recognized": true,
            "present": true,
            "value": v.clone(),
        }),
    };
    serde_json::to_string_pretty(&body).expect("serializable")
}

fn emit_human(path_repr: &str, outcome: &Outcome) {
    println!("path: {}", path_repr);
    match outcome {
        Outcome::Unrecognized => {
            println!("status: unrecognized (peek arm returned ~)");
        }
        Outcome::Absent => {
            println!("status: present-but-empty");
        }
        Outcome::Present(v) => {
            println!("status: present");
            print_human_value(v, 0);
        }
    }
}

fn print_human_value(v: &Value, indent: usize) {
    let pad = "  ".repeat(indent);
    if let Some(atom) = v.get("atom") {
        let decimal = atom
            .get("decimal")
            .and_then(Value::as_str)
            .unwrap_or("0");
        match atom.get("ascii").and_then(Value::as_str) {
            Some(ascii) => println!("{pad}value: '{ascii}' (decimal: {decimal})"),
            None => println!("{pad}value: {decimal}"),
        }
    } else if let Some(arr) = v.get("cell").and_then(Value::as_array) {
        println!("{pad}cell:");
        for (label, child) in [("head", &arr[0]), ("tail", &arr[1])] {
            println!("{pad}  {label}:");
            print_human_value(child, indent + 2);
        }
    } else {
        println!("{pad}value: <opaque>");
    }
}

// =============================================================================
// verify-jam — sentinel-based out.jam-staleness check
// =============================================================================

/// Read `[project].kernel_name` from `<project>/nockapp.toml`. Returns
/// `None` for any failure path (missing file, malformed toml, missing
/// field) so callers can fall back to defaults silently. Mirrors
/// `read_kernel_name_from_toml` in `tools/graft-inject/src/cli.rs` so
/// the two surfaces resolve the same value.
fn read_kernel_name(project_root: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(project_root.join("nockapp.toml")).ok()?;
    let value: toml::Value = toml::from_str(&raw).ok()?;
    value
        .get("project")?
        .get("kernel_name")?
        .as_str()
        .map(str::to_string)
}

/// Project-relative kernel path for verify-jam's hint output. Pastes
/// into shell verbatim — `hoon/app/<kernel_name>.hoon` if the project
/// has set kernel_name (via `nockup graft rename-kernel`), else the
/// pre-rename default `hoon/app/app.hoon`.
fn kernel_rel_path(project_root: &Path) -> String {
    let name = read_kernel_name(project_root).unwrap_or_else(|| "app".into());
    format!("hoon/app/{name}.hoon")
}

/// Run `verify-jam` against `project`. Returns the exit code:
/// 0 = fresh, 1 = stale (or fingerprinted file missing), 2 = no
/// fingerprint sidecar. Errors are surfaced as anyhow bails (exit
/// code 1 via the main dispatcher).
async fn run_verify_jam(project: &Path, json_out: bool) -> Result<u8> {
    let fingerprint_path = project.join(".out-jam-source-fingerprint");

    if !fingerprint_path.exists() {
        if json_out {
            let doc = json!({
                "fresh": false,
                "exit_code": 2,
                "fingerprint": fingerprint_path.display().to_string(),
                "missing_fingerprint": true,
                "diffs": [],
            });
            println!("{}", serde_json::to_string_pretty(&doc).expect("serializable"));
        } else {
            let kernel_rel = kernel_rel_path(project);
            eprintln!(
                "verify-jam: no fingerprint at {}",
                fingerprint_path.display(),
            );
            eprintln!("  Generate one after a clean hoonc compile:");
            eprintln!("    hoonc --new {kernel_rel} hoon/ && [ -s out.jam ] || \\");
            eprintln!("      (echo \"hoonc silent-failed\" >&2; exit 1)");
            eprintln!(
                "    sha256sum {kernel_rel} hoon/lib/*.hoon hoon/lib/*.toml > .out-jam-source-fingerprint"
            );
        }
        return Ok(2);
    }

    let entries = read_fingerprint(&fingerprint_path)?;
    let diffs = compute_diffs(project, &entries)?;

    let exit_code: u8 = if diffs.is_empty() { 0 } else { 1 };

    if json_out {
        let diffs_json: Vec<Value> = diffs
            .iter()
            .map(|d| {
                json!({
                    "path": d.rel_path.display().to_string(),
                    "expected_sha256": d.expected,
                    "actual_sha256": if d.missing {
                        Value::Null
                    } else {
                        Value::String(d.actual.clone())
                    },
                    "missing": d.missing,
                })
            })
            .collect();
        let doc = json!({
            "fresh": diffs.is_empty(),
            "exit_code": exit_code,
            "fingerprint": fingerprint_path.display().to_string(),
            "missing_fingerprint": false,
            "files_checked": entries.len(),
            "diffs": diffs_json,
        });
        println!("{}", serde_json::to_string_pretty(&doc).expect("serializable"));
    } else if diffs.is_empty() {
        eprintln!(
            "verify-jam: out.jam fresh ({} file(s) matched fingerprint)",
            entries.len(),
        );
    } else {
        eprintln!("verify-jam: STALE OUT.JAM");
        for d in &diffs {
            if d.missing {
                eprintln!(
                    "  {} — fingerprinted file no longer exists",
                    d.rel_path.display(),
                );
            } else {
                eprintln!(
                    "  {} expected sha256:{} actual sha256:{}",
                    d.rel_path.display(),
                    d.expected,
                    d.actual,
                );
            }
        }
        let kernel_rel = kernel_rel_path(project);
        eprintln!();
        eprintln!("  Re-run hoonc and refresh the fingerprint:");
        eprintln!("    hoonc --new {kernel_rel} hoon/ && [ -s out.jam ] || \\");
        eprintln!("      (echo \"hoonc silent-failed\" >&2; exit 1)");
        eprintln!(
            "    sha256sum {kernel_rel} hoon/lib/*.hoon hoon/lib/*.toml > .out-jam-source-fingerprint"
        );
    }

    Ok(exit_code)
}

/// One row of the `.out-jam-source-fingerprint` sidecar.
#[derive(Debug)]
struct FingerprintEntry {
    expected: String,
    rel_path: PathBuf,
}

/// One staleness finding — fingerprinted file's hash diverged from
/// current source, OR the file is now missing entirely.
#[derive(Debug)]
struct StalenessDiff {
    rel_path: PathBuf,
    expected: String,
    actual: String,
    missing: bool,
}

/// Parse a `sha256sum`-formatted file: each non-empty line is
/// `<64-hex-chars>  <path>` (two-space separator). Comments (`#` and
/// blank lines) are tolerated for human-edited fingerprints.
fn read_fingerprint(path: &Path) -> Result<Vec<FingerprintEntry>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading fingerprint {}", path.display()))?;
    let mut entries = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let raw = line.trim();
        if raw.is_empty() || raw.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = raw.splitn(2, "  ").collect();
        if parts.len() != 2 {
            bail!(
                "{}:{}: malformed fingerprint line (expected `<sha256>  <path>`): {}",
                path.display(),
                i + 1,
                raw,
            );
        }
        let sha = parts[0].trim();
        if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!(
                "{}:{}: hash field is not a 64-char hex sha256: {}",
                path.display(),
                i + 1,
                sha,
            );
        }
        entries.push(FingerprintEntry {
            expected: sha.to_lowercase(),
            rel_path: PathBuf::from(parts[1].trim()),
        });
    }
    Ok(entries)
}

/// For each fingerprint entry, recompute the file's current sha256 and
/// flag divergences. Missing files are flagged as `missing: true`.
fn compute_diffs(project: &Path, entries: &[FingerprintEntry]) -> Result<Vec<StalenessDiff>> {
    let mut diffs = Vec::new();
    for entry in entries {
        let abs_path = if entry.rel_path.is_absolute() {
            entry.rel_path.clone()
        } else {
            project.join(&entry.rel_path)
        };
        match std::fs::read(&abs_path) {
            Ok(bytes) => {
                let actual = format!("{:x}", Sha256::digest(&bytes));
                if actual != entry.expected {
                    diffs.push(StalenessDiff {
                        rel_path: entry.rel_path.clone(),
                        expected: entry.expected.clone(),
                        actual,
                        missing: false,
                    });
                }
            }
            Err(_) => {
                diffs.push(StalenessDiff {
                    rel_path: entry.rel_path.clone(),
                    expected: entry.expected.clone(),
                    actual: String::new(),
                    missing: true,
                });
            }
        }
    }
    Ok(diffs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_thousands_short() {
        assert_eq!(add_dotted_thousands("12"), "12");
        assert_eq!(add_dotted_thousands("123"), "123");
    }

    #[test]
    fn dotted_thousands_long() {
        assert_eq!(add_dotted_thousands("1234"), "1.234");
        assert_eq!(add_dotted_thousands("499918253415"), "499.918.253.415");
    }

    #[test]
    fn trim_trailing_zeros_drops_pad() {
        let bytes = vec![b'h', b'i', 0, 0, 0];
        assert_eq!(trim_trailing_zeros(&bytes), vec![b'h', b'i']);
    }

    #[test]
    fn ascii_decode_recognizes_printable() {
        assert_eq!(
            bytes_as_printable_ascii(b"settle"),
            Some("settle".to_string())
        );
        assert_eq!(bytes_as_printable_ascii(&[0xff, 0xfe]), None);
        assert_eq!(bytes_as_printable_ascii(&[]), None);
    }

    #[test]
    fn format_decimal_handles_small_atom() {
        // little-endian "g-mint" = 0x67_2d_6d_69_6e_74
        let bytes = [b'g', b'-', b'm', b'i', b'n', b't'];
        let expected = (0x74_6e_69_6d_2d_67u64).to_string();
        let dotted = add_dotted_thousands(&expected);
        assert_eq!(format_decimal_dotted(&bytes), dotted);
    }

    // -- verify-jam fingerprint parsing -------------------------------------

    #[test]
    fn fingerprint_parses_sha256sum_format() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "vesl-test-fp-{}",
            std::process::id(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let fp = dir.join("fingerprint");
        let mut f = std::fs::File::create(&fp).unwrap();
        writeln!(
            f,
            "{}  hoon/app/app.hoon",
            "0".repeat(64)
        )
        .unwrap();
        writeln!(
            f,
            "{}  hoon/lib/settle-graft.toml",
            "abcdef0123456789".repeat(4)
        )
        .unwrap();
        writeln!(f, "# comment line").unwrap();
        writeln!(f).unwrap();
        drop(f);

        let entries = read_fingerprint(&fp).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].rel_path, PathBuf::from("hoon/app/app.hoon"));
        assert_eq!(entries[0].expected, "0".repeat(64));
        assert_eq!(entries[1].rel_path, PathBuf::from("hoon/lib/settle-graft.toml"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fingerprint_rejects_short_hash() {
        let dir = std::env::temp_dir().join(format!(
            "vesl-test-fp-bad-{}",
            std::process::id(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let fp = dir.join("fingerprint");
        std::fs::write(&fp, "deadbeef  hoon/app/app.hoon\n").unwrap();
        let err = read_fingerprint(&fp).unwrap_err();
        assert!(
            format!("{:#}", err).contains("not a 64-char hex sha256"),
            "got: {err:#}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn compute_diffs_detects_stale_and_missing() {
        let dir = std::env::temp_dir().join(format!(
            "vesl-test-diffs-{}",
            std::process::id(),
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // a.txt — present and matches expected
        let a_path = dir.join("a.txt");
        std::fs::write(&a_path, b"hello").unwrap();
        let a_sha = format!("{:x}", Sha256::digest(b"hello"));

        // b.txt — present but content drifted
        let b_path = dir.join("b.txt");
        std::fs::write(&b_path, b"actual").unwrap();
        let b_old_sha = format!("{:x}", Sha256::digest(b"old"));

        // c.txt — fingerprint claims it should exist but it's gone
        let c_sha = format!("{:x}", Sha256::digest(b"never written"));

        let entries = vec![
            FingerprintEntry {
                expected: a_sha.clone(),
                rel_path: PathBuf::from("a.txt"),
            },
            FingerprintEntry {
                expected: b_old_sha.clone(),
                rel_path: PathBuf::from("b.txt"),
            },
            FingerprintEntry {
                expected: c_sha.clone(),
                rel_path: PathBuf::from("c.txt"),
            },
        ];

        let diffs = compute_diffs(&dir, &entries).unwrap();
        assert_eq!(diffs.len(), 2);
        assert_eq!(diffs[0].rel_path, PathBuf::from("b.txt"));
        assert!(!diffs[0].missing);
        assert_ne!(diffs[0].actual, diffs[0].expected);
        assert_eq!(diffs[1].rel_path, PathBuf::from("c.txt"));
        assert!(diffs[1].missing);

        std::fs::remove_dir_all(&dir).ok();
    }
}
