// SPDX-License-Identifier: LGPL-2.1-or-later
fn main() -> std::process::ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() < 2 {
        eprintln!("usage: particleve-vm-run INSTANCE /usr/bin/systemd-vmspawn ARGUMENTS...");
        return std::process::ExitCode::FAILURE;
    }
    match particleve::vmrun::supervise(&arguments[0], &arguments[1..]) {
        Ok(code) => std::process::ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(error) => particleve::earlyboot::exit(Err(error), "VM runner"),
    }
}
