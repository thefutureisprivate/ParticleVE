// SPDX-License-Identifier: LGPL-2.1-or-later
fn main() -> std::process::ExitCode {
    particleve::earlyboot::exit(particleve::earlyboot::assemble(), "initrd storage")
}
