// SPDX-License-Identifier: LGPL-2.1-or-later
fn main() -> std::process::ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let result = match arguments.as_slice() {
        [name] => particleve::confinement::start_guard(name).map(|_| ()),
        _ => Err(particleve::common::Error::new(
            "usage: particleve-vm-start-guard INSTANCE",
        )),
    };
    particleve::earlyboot::exit(result, "VM start guard")
}
