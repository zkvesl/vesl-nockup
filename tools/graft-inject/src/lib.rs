//! graft-inject library skeleton.
//!
//! Stage 1 of the audit §3.2 monolith split: lib target exists with a
//! single `pub fn run` placeholder. The two bins (`graft-inject` and
//! `nockup-graft`) still link their own copies of `main.rs` until the
//! next commit collapses it into here.

pub fn run() -> std::process::ExitCode {
    unreachable!("lib.rs::run is not yet wired; bins still use main.rs directly")
}
