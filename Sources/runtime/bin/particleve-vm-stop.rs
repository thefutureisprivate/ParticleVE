// SPDX-License-Identifier: LGPL-2.1-or-later
fn main() -> std::process::ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [name] = arguments.as_slice() else {
        eprintln!("usage: particleve-vm-stop INSTANCE");
        return std::process::ExitCode::FAILURE;
    };
    particleve::vms::wait_for_stop(name);
    std::process::ExitCode::SUCCESS
}
