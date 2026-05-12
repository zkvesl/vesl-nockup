// Same logic as `graft-inject`, different binary name. Lets nockup's
// plugin-discovery hook (`nockup graft <subcmd>` → execs `nockup-graft
// <subcmd>` from $PATH) delegate without an upstream subcommand.

fn main() -> std::process::ExitCode {
    graft_inject::run()
}
