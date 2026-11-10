//! Signal supervisor for native vmspawn, including uncertain or incomplete starts.
use crate::common::{Error, Result, command, require};
use crate::confinement::{check_tpm_arguments, own_cgroup, start_guard};
use crate::processes::Process;
use crate::vms::cgroup_processes;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
pub fn validate_command(name: &str, command: &[String]) -> Result<()> {
    require(
        command.first().map(String::as_str) == Some("/usr/bin/systemd-vmspawn"),
        "supervisor requires native vmspawn",
    )?;
    for argument in [
        "--register=yes".to_owned(),
        "--keep-unit".to_owned(),
        format!("--machine={name}"),
    ] {
        require(
            command.iter().filter(|s| **s == argument).count() == 1,
            "native vmspawn registration/ownership arguments required",
        )?;
    }
    Ok(())
}
struct Signals(Vec<signal_hook::SigId>);
impl Drop for Signals {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}
pub fn supervise(name: &str, arguments: &[String]) -> Result<i32> {
    validate_command(name, arguments)?;
    let stopping = Arc::new(AtomicBool::new(false));
    let mut signals = Signals(Vec::new());
    for number in [libc::SIGTERM, libc::SIGINT, libc::SIGRTMIN() + 4] {
        signals
            .0
            .push(signal_hook::flag::register(number, Arc::clone(&stopping))?);
    }
    let Some((mut child, group)) = launch_checked(
        &stopping,
        || start_guard(name).map(|_| ()),
        || check_tpm_arguments(name, arguments),
        || {
            let group = own_cgroup()?;
            // Direct ownership deliberately has no kill-on-drop cleanup guard.
            Ok((native_command(arguments).spawn()?, group))
        },
    )?
    else {
        return Ok(0);
    };
    supervise_observations(
        &stopping,
        || {
            Ok(child.try_wait()?.map(|status| {
                status
                    .code()
                    .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
            }))
        },
        || live_children(&group),
        || {
            let response = command(
                &["machinectl", "poweroff", "--", name].map(str::to_owned),
                None,
                Some(Duration::from_secs(15)),
                8 * 1024 * 1024,
                false,
            )?;
            Ok(response.code == 0)
        },
        || std::thread::sleep(Duration::from_secs(1)),
        |message| eprintln!("{message}"),
    )
}
fn native_command(arguments: &[String]) -> Command {
    let mut command = Command::new(&arguments[0]);
    command.args(&arguments[1..]).env_remove("WATCHDOG_PID");
    command
}
fn launch_checked<T, G, A, S>(
    stopping: &AtomicBool,
    guard: G,
    arguments: A,
    spawn: S,
) -> Result<Option<T>>
where
    G: FnOnce() -> Result<()>,
    A: FnOnce() -> Result<()>,
    S: FnOnce() -> Result<T>,
{
    guard()?;
    arguments()?;
    if stopping.load(Ordering::Relaxed) {
        return Ok(None);
    }
    spawn().map(Some)
}
fn live_children(group: &str) -> Result<bool> {
    let mut live = false;
    for entry in cgroup_processes(group)? {
        let value = match Process::open(entry.pid, Some(entry.starttime), Path::new("/proc"))
            .and_then(|p| p.text("attr/current", 4096))
        {
            Ok(value) => value,
            Err(error) if error.is_not_found() || error.is_errno(libc::ESRCH) => continue,
            Err(error) => return Err(error),
        };
        let kind = value
            .split(':')
            .nth(2)
            .ok_or_else(|| Error::new("invalid VM process SELinux context"))?;
        if ["svirt_t", "swtpm_t"].contains(&kind) {
            live = true;
        }
    }
    Ok(live)
}
// The loop receives observations and an ACPI request, never an interface capable
// of signalling the native child. Failed observations preserve supervision.
fn supervise_observations<C, O, R, P, N>(
    stopping: &AtomicBool,
    mut poll: C,
    mut observe: O,
    mut poweroff: R,
    mut pause: P,
    mut notice: N,
) -> Result<i32>
where
    C: FnMut() -> Result<Option<i32>>,
    O: FnMut() -> Result<bool>,
    R: FnMut() -> Result<bool>,
    P: FnMut(),
    N: FnMut(&str),
{
    let mut requested = false;
    let mut last_error = None;
    loop {
        let observation = (|| -> Result<Option<i32>> {
            let result = poll()?;
            let live = observe()?;
            if let Some(code) = result
                && !live
            {
                return Ok(Some(code));
            }
            if stopping.load(Ordering::Relaxed) && !requested {
                requested = poweroff()?;
                if !requested && last_error.as_deref() != Some("not registered") {
                    notice(
                        "Waiting for native VM registration or owner-assisted graceful shutdown",
                    );
                    last_error = Some("not registered".to_owned());
                }
            }
            Ok(None)
        })();
        match observation {
            Ok(Some(code)) => return Ok(code),
            Ok(None) => {}
            Err(error) => {
                let message = error.to_string();
                if last_error.as_ref() != Some(&message) {
                    notice(&format!(
                        "Cannot confirm graceful VM exit; waiting for owner assistance: {message}"
                    ));
                    last_error = Some(message);
                }
            }
        }
        pause();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_exact_native_registration() {
        let command = [
            "/usr/bin/systemd-vmspawn",
            "--register=yes",
            "--keep-unit",
            "--machine=test",
        ]
        .map(str::to_owned);
        assert!(validate_command("test", &command).is_ok());
        assert!(validate_command("other", &command).is_err());
        let mut repeated = command.to_vec();
        repeated.push("--keep-unit".into());
        assert!(validate_command("test", &repeated).is_err());
    }
}

#[cfg(test)]
mod supervision_tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    #[test]
    fn inspection_failure_after_native_exit_preserves_supervision() {
        let stopping = AtomicBool::new(false);
        let attempts = Cell::new(0);
        let pauses = Cell::new(0);
        let notices = RefCell::new(Vec::new());
        let result = supervise_observations(
            &stopping,
            || Ok(Some(0)),
            || {
                attempts.set(attempts.get() + 1);
                if attempts.get() == 1 {
                    Err(std::io::Error::from_raw_os_error(libc::EACCES).into())
                } else {
                    Ok(false)
                }
            },
            || panic!("no stop was requested"),
            || pauses.set(pauses.get() + 1),
            |message| notices.borrow_mut().push(message.to_owned()),
        )
        .unwrap();
        assert_eq!(result, 0);
        assert_eq!(pauses.get(), 1);
        assert!(notices.borrow()[0].contains("waiting for owner assistance"));
    }
    #[test]
    fn interrupted_activation_retries_registration_without_child_signal_authority() {
        let stopping = AtomicBool::new(false);
        let polls = Cell::new(0);
        let poweroffs = Cell::new(0);
        let result = supervise_observations(
            &stopping,
            || {
                polls.set(polls.get() + 1);
                Ok((polls.get() == 4).then_some(0))
            },
            || Ok(false),
            || {
                poweroffs.set(poweroffs.get() + 1);
                Ok(poweroffs.get() != 1)
            },
            || stopping.store(true, Ordering::Relaxed),
            |_| {},
        )
        .unwrap();
        assert_eq!(result, 0);
        assert_eq!(poweroffs.get(), 2);
        let arguments = [
            "/usr/bin/systemd-vmspawn",
            "--register=yes",
            "--keep-unit",
            "--machine=test",
            "--tpm=no",
        ]
        .map(str::to_owned);
        let command = native_command(&arguments);
        assert_eq!(command.get_program(), "/usr/bin/systemd-vmspawn");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            arguments[1..]
                .iter()
                .map(std::ffi::OsStr::new)
                .collect::<Vec<_>>()
        );
        assert!(
            command
                .get_envs()
                .any(|(name, value)| name == "WATCHDOG_PID" && value.is_none())
        );
        assert!(!command.get_envs().any(|(name, _)| name == "NOTIFY_SOCKET"));
    }
    #[test]
    fn pending_stop_runs_both_guards_and_never_spawns() {
        let stopping = AtomicBool::new(false);
        let calls = RefCell::new(Vec::new());
        let result = launch_checked(
            &stopping,
            || {
                calls.borrow_mut().push("guard");
                stopping.store(true, Ordering::Relaxed);
                Ok(())
            },
            || {
                calls.borrow_mut().push("arguments");
                Ok(())
            },
            || {
                calls.borrow_mut().push("spawn");
                Ok(())
            },
        )
        .unwrap();
        assert!(result.is_none());
        assert_eq!(*calls.borrow(), ["guard", "arguments"]);
    }
    #[test]
    fn missing_tpm_choice_fails_before_native_launch() {
        let stopping = AtomicBool::new(false);
        let spawned = Cell::new(false);
        assert!(
            launch_checked(
                &stopping,
                || Ok(()),
                || check_tpm_arguments("test", &["--register=yes".into()]),
                || {
                    spawned.set(true);
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(!spawned.get());
    }
    #[test]
    fn remaining_auxiliaries_delay_completion_after_main_child_exit() {
        let stopping = AtomicBool::new(false);
        let observations = Cell::new(0);
        let pauses = Cell::new(0);
        assert_eq!(
            supervise_observations(
                &stopping,
                || Ok(Some(143)),
                || {
                    observations.set(observations.get() + 1);
                    Ok(observations.get() == 1)
                },
                || panic!("no stop requested"),
                || pauses.set(pauses.get() + 1),
                |_| {}
            )
            .unwrap(),
            143
        );
        assert_eq!(pauses.get(), 1);
    }
}
