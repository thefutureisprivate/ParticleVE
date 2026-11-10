// SPDX-License-Identifier: LGPL-2.1-or-later
fn main() -> std::process::ExitCode {
    // A failed finish deliberately leaves the firmware witness dirty.
    particleve::earlyboot::exit(particleve::admission::finish(), "storage shutdown")
}
