// SPDX-License-Identifier: LGPL-2.1-or-later
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(u8::try_from(particleve::cli::main()).unwrap_or(1))
}
