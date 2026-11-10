// SPDX-License-Identifier: LGPL-2.1-or-later
fn main() -> std::process::ExitCode {
    if particleve::accounts::authorize_login(&std::env::var("PAM_USER").unwrap_or_default()).is_ok()
    {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
