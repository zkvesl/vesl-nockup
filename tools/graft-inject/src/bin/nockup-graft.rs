// Same source as `graft-inject`, different binary name. Lets nockup's
// plugin-discovery hook (`nockup graft <subcmd>` → execs `nockup-graft
// <subcmd>` from $PATH) delegate without an upstream subcommand.

#[path = "../main.rs"]
mod inner;

fn main() -> std::process::ExitCode {
    inner::main()
}
