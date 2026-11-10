// SPDX-License-Identifier: LGPL-2.1-or-later
fn main() -> std::process::ExitCode {
    particleve::earlyboot::exit(particleve::radio::serve(), "radio policy")
}
