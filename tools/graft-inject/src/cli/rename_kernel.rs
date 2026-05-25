//! `nockup graft rename-kernel <new>` subcommand — rename the project's
//! kernel file (`hoon/app/<old>.hoon` → `hoon/app/<new>.hoon`), update
//! `[project].kernel_name` in `nockapp.toml`, and rewrite bash code
//! blocks in `./README.md` that reference the old name.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use super::find_project_root;

/// Validate a kernel base name against the Hoon module name shape:
/// lowercase letter start, then lowercase letters, digits, or hyphens.
/// Hand-rolled regex `^[a-z][a-z0-9-]*$` to avoid pulling in the
/// `regex` crate for one check.
fn validate_kernel_name(s: &str) -> Result<()> {
    let mut chars = s.chars();
    let first = chars
        .next()
        .ok_or_else(|| anyhow!("kernel name must not be empty"))?;
    if !first.is_ascii_lowercase() {
        bail!("kernel name `{s}` must start with a lowercase letter (a-z)");
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            bail!(
                "kernel name `{s}` may only contain lowercase letters, digits, \
                 and hyphens"
            );
        }
    }
    Ok(())
}

/// Read `[project].kernel_name` from a project's `nockapp.toml`. Returns
/// `None` for any failure path (missing file, malformed toml, missing
/// field) so callers can fall back to defaults silently.
fn read_kernel_name_from_toml(toml_path: &Path) -> Option<String> {
    let raw = fs::read_to_string(toml_path).ok()?;
    let value: toml::Value = toml::from_str(&raw).ok()?;
    value
        .get("project")?
        .get("kernel_name")?
        .as_str()
        .map(str::to_string)
}

/// Rewrite `[project].kernel_name = "<new>"` in `nockapp.toml`,
/// preserving comments and key ordering via `toml_edit`. Creates the
/// `[project]` table if missing.
fn rewrite_nockapp_toml(path: &Path, new_name: &str) -> Result<()> {
    use toml_edit::{value, DocumentMut, Item, Table};
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let mut doc: DocumentMut = raw
        .parse()
        .with_context(|| format!("parse {}", path.display()))?;
    if !doc.contains_key("project") {
        doc["project"] = Item::Table(Table::new());
    }
    doc["project"]["kernel_name"] = value(new_name);
    fs::write(path, doc.to_string())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Substitute `hoon/app/<from>.hoon` → `hoon/app/<new>.hoon` inside
/// fenced ```bash code blocks in a README. Returns the substitution
/// count. No-op (returns Ok(0)) when the file is absent.
fn rewrite_readme_codeblocks(path: &Path, from: &str, new: &str) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let needle = format!("hoon/app/{from}.hoon");
    let replacement = format!("hoon/app/{new}.hoon");
    let mut out = String::with_capacity(raw.len());
    let mut in_bash = false;
    let mut count = 0usize;
    for line in raw.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if !in_bash && trimmed.starts_with("```bash") {
            in_bash = true;
            out.push_str(line);
        } else if in_bash && trimmed.starts_with("```") {
            in_bash = false;
            out.push_str(line);
        } else if in_bash {
            let occurrences = line.matches(&needle).count();
            if occurrences > 0 {
                count += occurrences;
                out.push_str(&line.replace(&needle, &replacement));
            } else {
                out.push_str(line);
            }
        } else {
            out.push_str(line);
        }
    }
    fs::write(path, out)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(count)
}

/// `nockup graft rename-kernel <new>` entry point. Renames the project
/// kernel file, updates `[project].kernel_name` in `nockapp.toml`, and
/// rewrites bash code blocks in `./README.md` if present.
///
/// `from` is the previous kernel base name. When `None`, defaults to
/// the value of `[project].kernel_name` in `nockapp.toml` if set, else
/// `"app"`. Preview-by-default — only `apply == true` writes to disk.
pub(super) fn run_rename_kernel(new: &str, from: Option<&str>, apply: bool) -> Result<()> {
    validate_kernel_name(new)?;

    let cwd = std::env::current_dir().context("get current directory")?;
    let project_root = find_project_root(&cwd).ok_or_else(|| {
        anyhow!(
            "no nockapp.toml found in `{}` or its ancestors; run \
             `nockup graft rename-kernel` from inside a vesl project",
            cwd.display()
        )
    })?;

    let toml_path = project_root.join("nockapp.toml");

    let from_owned = from.map(str::to_string).unwrap_or_else(|| {
        read_kernel_name_from_toml(&toml_path).unwrap_or_else(|| "app".to_string())
    });

    let app_dir = project_root.join("hoon/app");
    let old_path = app_dir.join(format!("{from_owned}.hoon"));
    let new_path = app_dir.join(format!("{new}.hoon"));

    if !old_path.exists() {
        bail!(
            "source kernel `{}` not found (use --from to override)",
            old_path.display()
        );
    }
    if new_path.exists() {
        bail!(
            "target `{}` already exists; refusing to clobber",
            new_path.display()
        );
    }

    let readme_path = project_root.join("README.md");

    eprintln!("nockup graft rename-kernel: planned operations");
    eprintln!("  rename {} → {}", old_path.display(), new_path.display());
    eprintln!(
        "  set    [project].kernel_name = \"{new}\" in {}",
        toml_path.display()
    );
    if readme_path.exists() {
        eprintln!(
            "  edit   {} (substitute hoon/app/{from_owned}.hoon → hoon/app/{new}.hoon in bash blocks)",
            readme_path.display()
        );
    } else {
        eprintln!("  edit   README.md skipped (file absent)");
    }

    if !apply {
        eprintln!("  (preview only — pass --apply to write)");
        return Ok(());
    }

    fs::rename(&old_path, &new_path).with_context(|| {
        format!("rename {} → {}", old_path.display(), new_path.display())
    })?;
    rewrite_nockapp_toml(&toml_path, new)?;
    let readme_edits = rewrite_readme_codeblocks(&readme_path, &from_owned, new)?;
    eprintln!(
        "nockup graft rename-kernel: applied (README substitutions: {readme_edits})"
    );
    Ok(())
}
