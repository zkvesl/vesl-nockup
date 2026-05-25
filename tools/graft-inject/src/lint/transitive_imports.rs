//! Transitive-imports lint: walk every `.hoon` file reachable from the
//! input path via `/+`, `/=`, `/-`, `/#` imports, AND eagerly scan
//! every `.hoon` under `<hoon-root>/common/`. Report unsatisfied edges
//! as findings.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{LintFinding, LintSeverity};

/// One import edge extracted from a .hoon prologue.
#[derive(Debug, Clone)]
struct ImportSpec {
    rune: &'static str,
    name: String,
    /// `/=` only: the path argument (e.g. `/common/wrapper`). Empty
    /// for the other runes.
    path_arg: String,
}

/// JSON projection record for `transitive_imports` findings.
#[derive(Serialize)]
pub(super) struct TransitiveImportRecord<'a> {
    pub(super) severity: LintSeverity,
    pub(super) source: &'a Path,
    pub(super) rune: &'a str,
    pub(super) name: &'a str,
    pub(super) target: &'a Path,
    pub(super) reachable_from: &'a [PathBuf],
}

/// Pre-apply lint: walk every `.hoon` file reachable from the input
/// path via `/+`, `/=`, `/-`, `/#` imports, AND eagerly scan every
/// `.hoon` under `<hoon-root>/common/`. Report unsatisfied edges as
/// findings.
///
/// Reproduces a real friction (`hoon/common/nock-prover.hoon → /#
/// softed-constraints` after a slimmed copy): even though an app.hoon
/// doesn't reach nock-prover transitively, hoonc parses hoon/common/
/// eagerly and silent-fails on the missing `/dat/` target. This lint
/// surfaces the same edge before hoonc runs so the developer sees a
/// clear "missing file at PATH" rather than hoonc's "no panic!" lie.
///
/// Resolution rules:
/// - `/+ <name>`         → `<lib-dir>/<name>.hoon`
/// - `/+ *<name>`        → `<lib-dir>/<name>.hoon` (public-import form)
/// - `/= <bind> /<path>` → `<hoon-root>/<path>.hoon`
/// - `/-  <name>`        → `<hoon-root>/sur/<name>.hoon`
/// - `/# <name>`         → `<hoon-root>/dat/<name>.hoon`
pub(crate) fn lint_transitive_imports(root_path: &Path, lib_dir: &Path) -> Vec<LintFinding> {
    use std::collections::VecDeque;

    let hoon_root = lib_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let common_dir = hoon_root.join("common");

    // Canonicalize for dedup. If canonicalize fails (e.g. the file
    // doesn't exist), fall back to the raw path — the resolver below
    // is the place that flags absence, not the dedup step.
    let canon = |p: &Path| -> PathBuf {
        p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
    };

    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut queue: VecDeque<(PathBuf, Vec<PathBuf>)> = VecDeque::new();
    queue.push_back((canon(root_path), Vec::new()));

    // Eagerly seed every .hoon under hoon/common/. Manual recursion via
    // fs::read_dir keeps us off walkdir.
    if common_dir.is_dir() {
        let mut stack = vec![common_dir.clone()];
        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().and_then(|e| e.to_str()) == Some("hoon") {
                    queue.push_back((canon(&p), Vec::new()));
                }
            }
        }
    }

    let mut findings: Vec<LintFinding> = Vec::new();
    while let Some((current, parents)) = queue.pop_front() {
        if !visited.insert(current.clone()) {
            continue;
        }
        let content = match fs::read_to_string(&current) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let lines: Vec<String> = content.lines().map(String::from).collect();
        for spec in parse_imports(&lines) {
            // AUDIT 2026-05-25 L-31: skip imports that try to traverse
            // outside the lib_dir / hoon_root tree (e.g. a malicious
            // `.hoon` declaring `/+ ../../../etc/passwd`). resolve_import
            // returns None for any spec whose name or path_arg contains
            // `..` or `/`; we drop the import silently rather than
            // reading the attacker-chosen file or leaking its existence
            // via the finding's `target` PathBuf in JSON output.
            let Some(target) = resolve_import(&spec, &hoon_root, lib_dir) else {
                continue;
            };
            if target.exists() {
                let mut next_parents = parents.clone();
                next_parents.push(current.clone());
                queue.push_back((canon(&target), next_parents));
            } else {
                let mut chain = parents.clone();
                chain.push(current.clone());
                findings.push(LintFinding::TransitiveImport {
                    source: current.clone(),
                    rune: spec.rune.to_string(),
                    name: spec.name.clone(),
                    target,
                    reachable_from: chain,
                });
            }
        }
    }

    findings
}

/// Parse the leading import block of a .hoon file. Stops at the first
/// non-rune non-comment non-empty line — Hoon prologues conventionally
/// run all imports before the first runic body.
fn parse_imports(lines: &[String]) -> Vec<ImportSpec> {
    let mut out = Vec::new();
    for line in lines {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("::") {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("/+") {
            for name in split_import_names(rest) {
                out.push(ImportSpec {
                    rune: "/+",
                    name,
                    path_arg: String::new(),
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("/=") {
            // `/= <bind> /<path>`. Extract the leading slash-path; bind
            // name is the first whitespace-separated token.
            let fields: Vec<&str> = rest.split_whitespace().collect();
            if let Some(p) = fields.iter().find(|f| f.starts_with('/')) {
                out.push(ImportSpec {
                    rune: "/=",
                    name: fields.first().map(|s| s.to_string()).unwrap_or_default(),
                    path_arg: p.to_string(),
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("/-") {
            for name in split_import_names(rest) {
                out.push(ImportSpec {
                    rune: "/-",
                    name,
                    path_arg: String::new(),
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("/#") {
            for name in split_import_names(rest) {
                out.push(ImportSpec {
                    rune: "/#",
                    name,
                    path_arg: String::new(),
                });
            }
        } else {
            break;
        }
    }
    out
}

/// Split a `/+` or `/-` argument into individual import names.
/// Tolerates leading `*` (public import) and comma-separated lists.
fn split_import_names(rest: &str) -> Vec<String> {
    rest.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_start_matches('*').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Reject import names that try to escape their containing directory.
/// Hoon imports name a module; the name should never contain a path
/// separator or a `..` component. AUDIT 2026-05-25 L-31: without this
/// guard, a malicious `.hoon` could declare e.g. `/+ ../../../etc/passwd`
/// and the lint walker would attempt to read attacker-chosen files
/// outside `lib_dir`, disclosing one bit of existence per file via the
/// `target` PathBuf in JSON output.
fn is_safe_import_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
}

/// Reject `/=` path arguments that contain `..` components. Legitimate
/// slash-paths under hoon-root never need to traverse upward. Mirror of
/// `is_safe_import_name` for the path-shaped argument of `/=`.
fn is_safe_path_arg(path: &str) -> bool {
    !path.split('/').any(|seg| seg == "..")
}

/// Resolve an import spec to a candidate file path under hoon-root, or
/// `None` if the spec attempts a path-traversal escape.
fn resolve_import(spec: &ImportSpec, hoon_root: &Path, lib_dir: &Path) -> Option<PathBuf> {
    match spec.rune {
        "/+" => is_safe_import_name(&spec.name)
            .then(|| lib_dir.join(format!("{}.hoon", spec.name))),
        "/=" => {
            let p = spec.path_arg.trim_start_matches('/');
            is_safe_path_arg(p)
                .then(|| hoon_root.join(format!("{}.hoon", p)))
        }
        "/-" => is_safe_import_name(&spec.name)
            .then(|| hoon_root.join("sur").join(format!("{}.hoon", spec.name))),
        "/#" => is_safe_import_name(&spec.name)
            .then(|| hoon_root.join("dat").join(format!("{}.hoon", spec.name))),
        _ => None,
    }
}
