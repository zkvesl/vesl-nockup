//! `vesl-test` — runtime kernel introspection bin (Tool 4).
//!
//! Boots a compiled out.jam through the standard `GraftTestHarness`,
//! runs a peek against the kernel's `++peek` arm, and prints the
//! result. The CLI wraps the three peek-path families that already
//! ship with vesl-core (`build_keyless_peek_path`,
//! `build_hull_peek_path`, `build_keyed_peek_path`) — Hoon-literal
//! path parsing is deliberately out of scope for the v1 cut.
//!
//! Examples:
//!   vesl-test inspect peek out.jam --path-tag log-len
//!   vesl-test inspect peek out.jam --path-tag settle-registered --hull 1
//!   vesl-test inspect peek out.jam --path-tag kv-value --key greeting
//!   vesl-test inspect peek out.jam --path-tag log-len --json

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nock_noun_rs::NounSlab;
use nockvm::noun::Noun;
use serde_json::{json, Value};
use vesl_core::{build_hull_peek_path, build_keyed_peek_path, build_keyless_peek_path};
use vesl_test::GraftTestHarness;

#[derive(Parser, Debug)]
#[command(name = "vesl-test", about = "Runtime introspection for grafted NockApp kernels")]
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
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Inspect { sub } => match sub {
            InspectCmd::Peek {
                jam,
                path_tag,
                hull,
                key,
                json,
            } => run_peek(&jam, &path_tag, hull, key.as_deref(), json).await,
        },
    }
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

    let outer_cell = match outer.as_cell() {
        Ok(c) => c,
        Err(_) => return Outcome::Unrecognized,
    };
    let inner = outer_cell.tail();
    if let Ok(_) = inner.as_atom() {
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
fn noun_to_json(n: Noun) -> Value {
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
}
