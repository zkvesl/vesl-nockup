//! Shared test helpers + scaffold constants for the crate's
//! `#[cfg(test)]` modules.
//!
//! The audit §3.2 split scattered tests across `cli.rs`, `codegen.rs`,
//! `gates.rs`, `inject.rs`, `lint.rs`, and `manifest.rs`. The helpers
//! and Hoon scaffolds those tests rely on used to live in
//! `lib.rs::mod tests`; this module consolidates them so each
//! per-module test block can `use crate::test_support::*;` without
//! duplicating the boilerplate.
//!
//! Everything is `pub(crate)` — this module is `#[cfg(test)]`-gated
//! and never crosses the crate boundary.

use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::Cli;
use crate::manifest::{Block, Graft, GraftBlocks, GraftTypes, load_manifest};

// ---------------------------------------------------------------------
// Scaffolds — Hoon kernel fixtures parameterized for different markers.
// ---------------------------------------------------------------------

pub(crate) const BARE_SCAFFOLD: &str = "\
::  test scaffold
/+  lib
::  nockup:imports
/=  *  /common/wrapper
::
=>
|%
+$  versioned-state
  $:  %v1
      ::  nockup:state
      ~
  ==
::
+$  effect  *
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
|%
++  moat  (keep versioned-state)
::
++  inner
  |_  state=versioned-state
  ++  load
    |=  old=versioned-state
    old
  ++  peek
    |=  =path
    ^-  (unit (unit *))
    ?+  path
      ::  nockup:peek
      ~
      [%count ~]  ``0
    ==
  ++  poke
    |=  =ovum:moat
    ^-  [(list effect) _state]
    =/  act  ((soft cause) cause.input.ovum)
    ?~  act  [~ state]
    ::  nockup:poke-prelude
    =/  out=[efx=(list effect) new=_state]
      ?-  -.u.act
          %cause  [~ state]
        ::  nockup:poke
      ==
    ::  nockup:poke-postlude
    out
  --
--
((moat |) inner)
";

/// Bare scaffold + a `nockup:effect-union` marker. Used as the
/// codegen test fixture so the existing BARE_SCAFFOLD tests keep
/// running unmodified.
pub(crate) const SCAFFOLD_WITH_UNION_MARKER: &str = "\
::  test scaffold with codegen marker
::  nockup:effect-union
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";

/// Same as above plus a `nockup:domain-effect` marker and a
/// developer-declared `+$ domain-effect` block.
pub(crate) const SCAFFOLD_WITH_BOTH_MARKERS: &str = "\
::  test scaffold with both codegen markers
::
::  nockup:domain-effect
+$  domain-effect
  $%  [%user-thing ~]
  ==
::
::  nockup:effect-union
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";

pub(crate) const SCAFFOLD_NARROW_BINDING: &str = "\
::  test scaffold with narrow effect bindings
::
::  nockup:domain-effect
+$  domain-effect
  $%  [%set-done ~]
  ==
::
::  nockup:effect-union
+$  effect  *
::
+$  cause
  $%  [%cause ~]
      [%set name=@t value=@]
      ::  nockup:cause
  ==
::
=/  [efx-c=(list counter-effect) new-counter=counter-state]
  (counter-poke counter.state [%counter-increment name.u.act])
=/  [efx-k=(list kv-effect) new-kv=kv-state]
  (kv-poke kv.state [%kv-set name.u.act value.u.act])
(weld efx-c efx-k)
--
";

/// Scaffold with a `nockup:load-defaults` marker followed by the
/// legacy `old-state` placeholder. Phase 04 load-defaults marker tests:
/// codegen replaces it with a `=/  defaults  ^*(versioned-state)` +
/// `%_  defaults  ...  ==` overlay block.
pub(crate) const SCAFFOLD_WITH_LOAD_DEFAULTS_MARKER: &str = "\
::  test scaffold with load-defaults marker
::  nockup:load-defaults
old-state
::  nockup:effect-union
::
+$  cause
  $%  [%cause ~]
      ::  nockup:cause
  ==
--
";

// ---------------------------------------------------------------------
// Path + tempdir helpers.
// ---------------------------------------------------------------------

pub(crate) fn settle_graft_manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("hoon")
        .join("lib")
        .join("settle-graft.toml")
}

pub(crate) fn tempdir_for_test(label: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("graft-inject-test-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------
// Graft constructors — synthetic in-memory grafts for tests.
// ---------------------------------------------------------------------

pub(crate) fn settle_only_grafts() -> Vec<Graft> {
    let path = settle_graft_manifest_path();
    let g = load_manifest(&path)
        .expect("load settle-graft.toml")
        .expect("settle-graft.toml has [graft] table");
    vec![g]
}

/// Build a minimal in-memory Graft for synthetic multi-graft tests.
/// `name` doubles as the binding stub in the peek chain (no `-graft`
/// suffix), so assertions can match `<name>-res` directly.
pub(crate) fn synthetic_graft(name: &str, priority: i32) -> Graft {
    Graft {
        name: name.to_string(),
        version: "0.1.0".to_string(),
        priority,
        after: vec![],
        blocks: GraftBlocks {
            imports: Some(Block {
                sentinel: format!("*{name}"),
                body: format!("/+  *{name}"),
            }),
            state: Some(Block {
                sentinel: format!("{name}={name}-state"),
                body: format!("{name}={name}-state"),
            }),
            cause: Some(Block {
                sentinel: format!("{name}-cause"),
                body: format!("{name}-cause"),
            }),
            poke_prelude: None,
            poke: Some(Block {
                sentinel: format!("%{name}-do"),
                body: format!(
                    "  %{name}-do\n=/  lc=cause  [%{name}-do ~]\n[~ state]"
                ),
            }),
            poke_postlude: None,
            peek: Some(Block {
                sentinel: format!("{name}-peek"),
                body: format!("({name}-peek state path)"),
            }),
        },
        gates: None,
        types: None,
        sha256: String::new(),
    }
}

pub(crate) fn synthetic_graft_with_effect(name: &str, priority: i32) -> Graft {
    let mut g = synthetic_graft(name, priority);
    g.types = Some(GraftTypes {
        effect: Some(format!("{name}-effect")),
        cause: Some(format!("{name}-cause")),
    });
    g
}

// ---------------------------------------------------------------------
// CLI + manifest fixture builders.
// ---------------------------------------------------------------------

pub(crate) fn cli_with(lib_dir: PathBuf) -> Cli {
    Cli {
        command: None,
        path: None,
        grafts: Vec::new(),
        exclude: Vec::new(),
        lib_dir,
        list: false,
        json: false,
        dry_run: false,
        apply: false,
        no_migrate: false,
    }
}

/// Build a temp lib dir with settle-graft.toml and an alpha synthetic
/// manifest so multi-manifest selection logic can be tested without
/// the real hoon/lib tree.
pub(crate) fn tempdir_with_two_manifests(label: &str) -> PathBuf {
    let dir = tempdir_for_test(label);
    let settle_src = fs::read_to_string(settle_graft_manifest_path()).unwrap();
    fs::write(dir.join("settle-graft.toml"), settle_src).unwrap();
    fs::write(
        dir.join("alpha.toml"),
        r#"[graft]
name     = "alpha"
version  = "0.1.0"
priority = 50
after    = []

[graft.blocks.imports]
sentinel = "*alpha"
body     = "/+  *alpha"

[graft.blocks.state]
sentinel = "alpha=alpha-state"
body     = "alpha=alpha-state"

[graft.blocks.cause]
sentinel = "alpha-cause"
body     = "alpha-cause"

[graft.blocks.poke]
sentinel = "%alpha-do"
body     = """
  %alpha-do
[~ state]"""

[graft.blocks.peek]
sentinel = "alpha-peek"
body     = "(alpha-peek state path)"
"#,
    )
    .unwrap();
    dir
}

/// Write a synthetic manifest with the given `name` into `dir` at
/// `file_name`, so `discover_grafts` can exercise collision + name
/// validation paths without touching the real hoon/lib tree.
pub(crate) fn write_manifest(dir: &Path, file_name: &str, name: &str) {
    fs::write(
        dir.join(file_name),
        format!(
            r#"[graft]
name     = "{name}"
version  = "0.1.0"
priority = 50
after    = []

[graft.blocks.imports]
sentinel = "*{name}"
body     = "/+  *{name}"

[graft.blocks.poke]
sentinel = "%{name}-do"
body     = """
  %{name}-do
[~ state]"""
"#,
        ),
    )
    .unwrap();
}

/// Like `write_manifest` but adds a `[graft.types]` table with the
/// caller-supplied effect/cause names. Used by the cross-graft type
/// uniqueness tests.
pub(crate) fn write_manifest_with_types(
    dir: &Path,
    file_name: &str,
    name: &str,
    effect: &str,
    cause: &str,
) {
    fs::write(
        dir.join(file_name),
        format!(
            r#"[graft]
name     = "{name}"
version  = "0.1.0"
priority = 50
after    = []

[graft.types]
effect = "{effect}"
cause  = "{cause}"

[graft.blocks.imports]
sentinel = "*{name}"
body     = "/+  *{name}"

[graft.blocks.poke]
sentinel = "%{name}-do"
body     = """
  %{name}-do
[~ state]"""
"#,
        ),
    )
    .unwrap();
}
