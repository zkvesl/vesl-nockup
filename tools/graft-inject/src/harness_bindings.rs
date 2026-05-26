//! `harness-bindings.toml` schema, loader, and cross-check against
//! discovered graft poke arms.
//!
//! The sidecar lives outside the canonical per-graft manifests so the
//! first cut of typed-harness codegen can ship without cross-repo
//! coordination — see `.dev/vesl-nockup-v2.0.md` for the planned
//! promotion into the per-graft `*-graft.toml` files.
//!
//! Each `[[graft]]` block names one shipped graft (without the
//! `-graft` suffix) and lists its bound poke arms, typed errors, typed
//! rejections, and typed denials. The codegen reads only this file;
//! the per-graft manifests stay untouched.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::lint::extract_graft_cause_tags;
use crate::manifest::{Graft, sha256_hex};

/// Top-level wrapper for the `harness-bindings.toml` file.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HarnessBindingsFile {
    /// Schema-version field for future append-only sidecar changes.
    /// Currently unread by the codegen — every shipped sidecar is `1`
    /// — but kept in the deserialized form so an older binary against
    /// a newer sidecar can surface the skew on a future migration.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) schema_version: Option<u32>,
    #[serde(default, rename = "graft")]
    pub(crate) grafts: Vec<HarnessGraftBindings>,
}

/// Per-graft binding block: the simple `<graft>` name plus its bound
/// poke arms / error tags / rejected tags / denied tags.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HarnessGraftBindings {
    /// Base name without the `-graft` suffix (e.g. `"counter"`).
    pub(crate) name: String,
    #[serde(default, rename = "pokes")]
    pub(crate) pokes: Vec<HarnessPoke>,
    #[serde(default, rename = "errors")]
    pub(crate) errors: Vec<HarnessErrorTag>,
    #[serde(default, rename = "rejected")]
    pub(crate) rejected: Vec<HarnessRejectedTag>,
    #[serde(default, rename = "denied")]
    pub(crate) denied: Vec<HarnessDeniedTag>,
}

/// One bound poke arm: maps a `%<tag>` to a typed harness method that
/// delegates to a `vesl_core::<builder>` function with the listed args.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HarnessPoke {
    /// The `%<tag>` the kernel accepts. Compile-time-asserted via
    /// `assert_kernel_cause_tag!` in the generated method body.
    pub(crate) tag: String,
    /// snake_case Rust ident for the method on `GraftTestHarness`.
    pub(crate) method: String,
    /// Path under `vesl_core::` for the underlying SDK builder
    /// function (e.g. `"build_counter_increment_poke"`).
    pub(crate) builder: String,
    /// Typed args, in builder-call order. Each becomes one parameter on
    /// the generated method with the given Rust type, and is forwarded
    /// positionally to the builder.
    #[serde(default)]
    pub(crate) args: Vec<HarnessArg>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HarnessArg {
    pub(crate) name: String,
    pub(crate) rust: String,
}

/// `[%<graft>-error msg=@t]` effect tag — the simple cord-typed kernel
/// error every graft emits. Presence of any entry generates an
/// `Error { msg: String }` variant on the per-graft outcome enum; the
/// `tag` field is documentation for now (the codegen routes by the
/// `<graft>-graft:` cord prefix established across every shipped
/// graft).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HarnessErrorTag {
    #[allow(dead_code)]
    pub(crate) tag: String,
}

/// `[%<graft>-..-rejected ...]` typed-rejection effect. Generates a
/// struct variant on the per-graft outcome enum.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HarnessRejectedTag {
    pub(crate) tag: String,
    #[serde(default)]
    pub(crate) fields: Vec<HarnessArg>,
}

/// `[%<graft>-denied reason=@t]` gate-clean-deny effect. Presence of
/// any entry generates a `Denied { reason: String }` variant; the
/// `tag` field is documentation, mirroring `HarnessErrorTag`.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HarnessDeniedTag {
    #[allow(dead_code)]
    pub(crate) tag: String,
}

/// Loaded bindings paired with the sha256 of the raw TOML bytes — same
/// shape as `Graft::sha256`, lets the emitter embed provenance in the
/// generated source.
#[derive(Debug, Clone)]
pub(crate) struct LoadedHarnessBindings {
    pub(crate) bindings: HarnessBindingsFile,
    pub(crate) sha256: String,
}

/// Load and parse the sidecar.
pub(crate) fn load_harness_bindings(path: &Path) -> Result<LoadedHarnessBindings> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading harness bindings {}", path.display()))?;
    let bindings: HarnessBindingsFile = toml::from_str(&raw)
        .with_context(|| format!("parsing harness bindings {}", path.display()))?;
    let sha256 = sha256_hex(raw.as_bytes());
    Ok(LoadedHarnessBindings { bindings, sha256 })
}

/// Cross-check that every `(graft, tag)` in the sidecar exists as a real
/// poke arm in the matching `*-graft.toml`. Catches:
/// - typos in the sidecar's `tag` field
/// - sidecar entries for a graft that doesn't exist in `lib_dir`
/// - sidecar entries that reference a tag the graft's poke body doesn't
///   declare (most commonly: poke arm renamed in the manifest, sidecar
///   not updated)
///
/// Method-name uniqueness within a graft is also checked here — two
/// `[[graft.pokes]]` entries with the same `method` would produce a
/// duplicate-method-name compile error in the generated code; bail
/// early with a clearer message.
pub(crate) fn validate_bindings_against_grafts(
    bindings: &HarnessBindingsFile,
    grafts: &[Graft],
) -> Result<()> {
    for gb in &bindings.grafts {
        let graft_full_name = format!("{}-graft", gb.name);
        let graft = grafts.iter().find(|g| g.name == graft_full_name);
        let Some(graft) = graft else {
            bail!(
                "harness-bindings.toml references graft `{}` (full name `{}`) \
                 but no manifest with that name was discovered under the lib dir",
                gb.name,
                graft_full_name,
            );
        };

        let valid_tags: HashSet<String> = extract_graft_cause_tags(graft).into_iter().collect();

        let mut seen_methods: HashSet<&str> = HashSet::new();
        for poke in &gb.pokes {
            if !valid_tags.contains(&poke.tag) {
                bail!(
                    "harness-bindings.toml: graft `{}` poke `{}` (method `{}`) \
                     references tag `%{}`, but the graft's `[graft.blocks.poke]` body \
                     declares no such arm. Valid tags: {:?}",
                    gb.name,
                    poke.builder,
                    poke.method,
                    poke.tag,
                    valid_tags.iter().collect::<Vec<_>>(),
                );
            }
            if !seen_methods.insert(poke.method.as_str()) {
                bail!(
                    "harness-bindings.toml: graft `{}` declares duplicate method `{}` — \
                     two pokes cannot share a method name (Rust impl-block collision)",
                    gb.name,
                    poke.method,
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use std::fs;

    #[test]
    fn load_minimal_bindings() {
        let dir = tempdir_for_test("load_minimal_bindings");
        let path = dir.join("harness-bindings.toml");
        fs::write(
            &path,
            r#"schema_version = 1
[[graft]]
name = "counter"

[[graft.pokes]]
tag     = "counter-set"
method  = "counter_set"
builder = "build_counter_set_poke"
args    = [{ name = "name", rust = "&str" }, { name = "value", rust = "u64" }]
"#,
        )
        .unwrap();
        let loaded = load_harness_bindings(&path).expect("loads");
        assert_eq!(loaded.bindings.schema_version, Some(1));
        assert_eq!(loaded.bindings.grafts.len(), 1);
        let g = &loaded.bindings.grafts[0];
        assert_eq!(g.name, "counter");
        assert_eq!(g.pokes.len(), 1);
        assert_eq!(g.pokes[0].method, "counter_set");
        assert_eq!(g.pokes[0].args.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_unknown_tag() {
        // Sidecar claims a tag that doesn't appear in the graft's poke
        // body — must bail with a clear error.
        let mut graft = synthetic_graft("counter-graft", 60);
        graft.blocks.poke = Some(crate::manifest::Block {
            body: "  %counter-set\n  %counter-reset".to_string(),
        });
        let bindings = HarnessBindingsFile {
            schema_version: Some(1),
            grafts: vec![HarnessGraftBindings {
                name: "counter".to_string(),
                pokes: vec![HarnessPoke {
                    tag: "counter-nuke".to_string(),
                    method: "counter_nuke".to_string(),
                    builder: "build_counter_nuke_poke".to_string(),
                    args: vec![],
                }],
                errors: vec![],
                rejected: vec![],
                denied: vec![],
            }],
        };
        let err = validate_bindings_against_grafts(&bindings, &[graft]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("counter-nuke") && msg.contains("declares no such arm"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn validate_rejects_missing_graft() {
        let bindings = HarnessBindingsFile {
            schema_version: Some(1),
            grafts: vec![HarnessGraftBindings {
                name: "missing".to_string(),
                pokes: vec![],
                errors: vec![],
                rejected: vec![],
                denied: vec![],
            }],
        };
        let err = validate_bindings_against_grafts(&bindings, &[]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing") && msg.contains("no manifest"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn validate_rejects_duplicate_method() {
        let mut graft = synthetic_graft("counter-graft", 60);
        graft.blocks.poke = Some(crate::manifest::Block {
            body: "  %counter-set".to_string(),
        });
        let bindings = HarnessBindingsFile {
            schema_version: Some(1),
            grafts: vec![HarnessGraftBindings {
                name: "counter".to_string(),
                pokes: vec![
                    HarnessPoke {
                        tag: "counter-set".to_string(),
                        method: "counter_set".to_string(),
                        builder: "build_counter_set_poke".to_string(),
                        args: vec![],
                    },
                    HarnessPoke {
                        tag: "counter-set".to_string(),
                        method: "counter_set".to_string(),
                        builder: "build_counter_set_alt_poke".to_string(),
                        args: vec![],
                    },
                ],
                errors: vec![],
                rejected: vec![],
                denied: vec![],
            }],
        };
        let err = validate_bindings_against_grafts(&bindings, &[graft]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("duplicate method"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn validate_accepts_valid_bindings() {
        let mut graft = synthetic_graft("counter-graft", 60);
        graft.blocks.poke = Some(crate::manifest::Block {
            body: "  %counter-set\n  %counter-reset".to_string(),
        });
        let bindings = HarnessBindingsFile {
            schema_version: Some(1),
            grafts: vec![HarnessGraftBindings {
                name: "counter".to_string(),
                pokes: vec![
                    HarnessPoke {
                        tag: "counter-set".to_string(),
                        method: "counter_set".to_string(),
                        builder: "build_counter_set_poke".to_string(),
                        args: vec![],
                    },
                    HarnessPoke {
                        tag: "counter-reset".to_string(),
                        method: "counter_reset".to_string(),
                        builder: "build_counter_reset_poke".to_string(),
                        args: vec![],
                    },
                ],
                errors: vec![],
                rejected: vec![],
                denied: vec![],
            }],
        };
        validate_bindings_against_grafts(&bindings, &[graft]).unwrap();
    }
}
