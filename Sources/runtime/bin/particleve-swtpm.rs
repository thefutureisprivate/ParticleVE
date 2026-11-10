// SPDX-License-Identifier: LGPL-2.1-or-later
fn main() -> std::process::ExitCode {
    particleve::earlyboot::exit(
        particleve::confinement::swtpm_handoff(&std::env::args().skip(1).collect::<Vec<_>>()),
        "TPM handoff",
    )
}
