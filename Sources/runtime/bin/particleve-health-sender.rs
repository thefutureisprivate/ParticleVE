// SPDX-License-Identifier: LGPL-2.1-or-later
fn main() -> std::process::ExitCode {
    particleve::earlyboot::exit(
        particleve::reporting::sender_main()
            .and_then(|value| particleve::earlyboot::json_output(&value)),
        "health sender",
    )
}
