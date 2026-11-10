//! Public administrative command line. Mutating host operations require root.
use crate::common::{
    Error, Result, atomic_write, command, digest, field, list, lock, read_json, require, run, text,
    write_json,
};
use crate::coordinator::Coordinator;
use crate::linux::Linux;
use crate::{config, install, inventory, network, reconfigure, release};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
const KEYRING: &str = "/usr/lib/particleve/trust/releases.gpg";
const CERTIFICATE: &str = "/usr/lib/particleve/trust/secure-boot.crt";
#[derive(Parser)]
#[command(about = "ParticleVE installation and serialized host maintenance")]
pub struct Arguments {
    #[arg(long, default_value = "/etc/particleve/host.json")]
    pub config: PathBuf,
    #[arg(long, default_value = "/var/lib/particleve")]
    pub state_dir: PathBuf,
    #[command(subcommand)]
    pub command: Commands,
}
#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Read-only hardware capability report")]
    Preflight,
    #[command(about = "Apply this image's host-input policy to the configured host")]
    ApplyFirewall,
    RenderNetwork {
        #[arg(long)]
        output: PathBuf,
    },
    FetchRelease {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        version: Option<String>,
        #[arg(long,default_value=KEYRING)]
        keyring: PathBuf,
        #[arg(long,default_value=CERTIFICATE)]
        certificate: PathBuf,
    },
    Plan {
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long,default_value=KEYRING)]
        keyring: PathBuf,
        #[arg(long,default_value=CERTIFICATE)]
        certificate: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Install {
        #[arg(long)]
        release_dir: PathBuf,
        #[arg(long,default_value=KEYRING)]
        keyring: PathBuf,
        #[arg(long,default_value=CERTIFICATE)]
        certificate: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        confirm: String,
        #[arg(long)]
        recovery_key_file: PathBuf,
    },
    Prepare {
        #[arg(long)]
        manual: bool,
    },
    Activate {
        #[arg(long)]
        manual: bool,
    },
    EnrollTpm {
        #[arg(long)]
        recovery_key_file: PathBuf,
    },
    Assess,
    BlessCurrent,
    RuntimeGuard,
    RecoverVms,
    FinalizeReplacement,
    CheckUsers,
    FailBoot,
    Status,
    SecurityStatus,
    StartupInventory,
    HealthReport,
    SendHealthReport,
    DisableAutomation,
    Maintenance {
        #[arg(value_parser=["enter","leave"])]
        action: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        reviewed: bool,
    },
    Commission {
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        enable: bool,
    },
    Reconfigure {
        #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
        previous_config: Option<PathBuf>,
        #[arg(long, conflicts_with = "previous_config")]
        resume: bool,
        #[arg(long)]
        proposed: Option<PathBuf>,
        #[arg(long)]
        confirm: Option<String>,
    },
    ReplaceDisk {
        #[arg(long,value_parser=["a","b"])]
        role: String,
        #[arg(long)]
        disk: String,
        #[arg(long)]
        serial: String,
        #[arg(long)]
        rebuild_quarantined: bool,
        #[arg(long)]
        confirm: Option<String>,
        #[arg(long)]
        recovery_key_file: Option<PathBuf>,
    },
}
fn root() -> Result<()> {
    // SAFETY: geteuid has no arguments and observes only process identity.
    require(
        unsafe { libc::geteuid() } == 0,
        "host maintenance commands require root",
    )
}
fn absolute(path: &Path) -> Result<PathBuf> {
    Ok(if path.exists() {
        std::fs::canonicalize(path)?
    } else if path.is_absolute() {
        path.into()
    } else {
        std::env::current_dir()?.join(path)
    })
}
fn inspect_security(backend: &Linux) -> Result<Value> {
    use crate::vms::{LinuxVMs, VmPlatform};
    backend.health()?;
    let mut processes = Vec::new();
    for vm in LinuxVMs.inventory(false)? {
        for process in list(field(&vm, "processes")?)? {
            let identity = crate::processes::Identity {
                pid: u32::try_from(crate::common::uint(field(process, "pid")?)?)
                    .map_err(|_| Error::new("invalid VM process PID"))?,
                starttime: crate::common::uint(field(process, "starttime")?)?,
            };
            processes.push(crate::security::process_evidence(
                &identity,
                Path::new("/proc"),
            )?);
        }
    }
    Ok(
        json!({"image_version":backend.current_version()?,"radio_policy":crate::radio::baseline(&backend.config["physical"]["radios"],Path::new("/sys"),Path::new("/proc"),Path::new("/dev/rfkill"),Path::new("/etc/particleve/radio-policy.json"))?,"console_policy":crate::consoles::baseline(&backend.config,Path::new("/proc"),Path::new("/sys"))?,"kernel":crate::security::live_baseline(Path::new("/"),true)?,"administration":crate::security::ssh_baseline()?,"selinux_booleans":crate::security::selinux_baseline()?,"selinux_interfaces":crate::security::selinux_access()?,"listeners":{"ip":run(&["ss","-H","-lntup"])?.stdout,"unix":run(&["ss","-H","-lxnp"])?.stdout,"vsock":run(&["ss","-H","-l","-A","vsock","-p"])?.stdout,"socket_units":run(&["systemctl","list-sockets","--all","--no-pager"])?.stdout},"privileged_files":crate::security::check_privileges(Path::new("/"),None)?,"vm_processes":processes}),
    )
}
pub fn execute(args: Arguments) -> Result<(i32, Value)> {
    let Arguments {
        config: config_file,
        state_dir,
        command: action,
    } = args;
    match &action {
        Commands::DisableAutomation => {
            root()?;
            return Ok((0, reconfigure::disable_automation(&state_dir)?));
        }
        Commands::Reconfigure {
            previous_config,
            resume,
            proposed,
            confirm,
        } => {
            root()?;
            require(
                proposed.is_some() != *resume,
                "supply --proposed for a new review, or --resume alone",
            )?;
            let previous = previous_config.as_ref().map(read_json).transpose()?;
            let proposed = proposed.as_ref().map(read_json).transpose()?;
            return Ok((
                0,
                reconfigure::reconfigure(
                    &state_dir,
                    &config_file,
                    previous,
                    proposed,
                    confirm.as_deref(),
                    *resume,
                )?,
            ));
        }
        Commands::Status => {
            let result = reconfigure::binding_status(&config_file, &state_dir)?;
            if result["config_binding"]["valid"] != true
                || result["reconfiguration_pending"] == true
            {
                return Ok((0, result));
            }
        }
        _ => (),
    };
    let current_config = read_json(&config_file)?;
    let host = if matches!(&action, Commands::Maintenance{action,..} if action == "enter") {
        reconfigure::maintenance_input(current_config, &state_dir)?
    } else {
        config::validate(
            current_config,
            !matches!(action, Commands::Preflight | Commands::RenderNetwork { .. }),
        )?
    };
    match action {
        Commands::Preflight => {
            let report = inventory::collect(&host)?;
            Ok((if report["ok"] == true { 0 } else { 1 }, report))
        }
        Commands::RenderNetwork { output } => {
            network::write(&host, &output)?;
            atomic_write(
                output.join("host.nft"),
                network::firewall(&host)?.as_bytes(),
                0o644,
            )?;
            Ok((
                0,
                json!({"output":absolute(&output)?.display().to_string()}),
            ))
        }
        Commands::ApplyFirewall => {
            root()?;
            command(
                &["nft".into(), "--file".into(), "-".into()],
                Some(network::firewall(&host)?.as_bytes()),
                Some(Duration::from_secs(120)),
                8 * 1024 * 1024,
                true,
            )?;
            Ok((0, json!({"firewall":"active"})))
        }
        Commands::FetchRelease {
            output,
            version,
            keyring,
            certificate,
        } => {
            let (destination, manifest) = release::fetch(
                text(field(&host, "feed")?)?,
                &output,
                &keyring,
                &certificate,
                version.as_deref(),
            )?;
            Ok((
                0,
                json!({"release_dir":absolute(&destination)?.display().to_string(),"version":manifest["version"]}),
            ))
        }
        Commands::Plan {
            release_dir,
            keyring,
            certificate,
            output,
        } => {
            let manifest = release::verify_directory(&release_dir, &keyring, &certificate, true)?;
            let proposed = install::plan(&host, &manifest)?;
            write_json(&output, &proposed)?;
            Ok((
                0,
                json!({"plan":absolute(&output)?.display().to_string(),"confirmation":proposed["confirmation"]}),
            ))
        }
        Commands::Install {
            release_dir,
            keyring,
            certificate,
            plan,
            confirm,
            recovery_key_file,
        } => {
            let mut proposed = read_json(plan)?;
            Ok((
                0,
                install::install(
                    &host,
                    &release_dir,
                    &mut proposed,
                    &confirm,
                    &recovery_key_file,
                    &keyring,
                    &certificate,
                )?,
            ))
        }
        action => {
            if !matches!(action, Commands::Status) {
                root()?;
            }
            let allow_unbound =
                matches!(&action,Commands::Maintenance{action,..}if action=="enter");
            let mut backend = Linux::new(host.clone(), &state_dir, allow_unbound)?;
            let result = match action {
                Commands::Prepare { manual } => {
                    Coordinator::new(&state_dir, &backend).prepare(!manual)?
                }
                Commands::Activate { manual } => {
                    Coordinator::new(&state_dir, &backend).reboot(None, !manual)?
                }
                Commands::Assess => Coordinator::new(&state_dir, &backend).assess()?,
                Commands::BlessCurrent => Coordinator::new(&state_dir, &backend).bless()?,
                Commands::EnrollTpm { recovery_key_file } => {
                    let _ownership = lock(&state_dir)?;
                    install::enroll_tpm(
                        &backend,
                        &recovery_key_file,
                        &crate::coordinator::load_state(&state_dir)?,
                    )?
                }
                Commands::RuntimeGuard => {
                    crate::admission::watch()?;
                    backend.check_storage(false)?;
                    Coordinator::new(&state_dir, &backend).runtime_guard()?;
                    json!({"runtime_state":"compatible"})
                }
                Commands::Maintenance {
                    action,
                    reason,
                    reviewed,
                } => {
                    require(
                        action != "enter" || reason.is_some(),
                        "maintenance enter requires --reason",
                    )?;
                    Coordinator::new(&state_dir, &backend).maintenance(
                        if action == "enter" {
                            reason.as_deref()
                        } else {
                            None
                        },
                        reviewed,
                    )?
                }
                Commands::Commission { evidence, enable } => {
                    let _ownership = lock(&state_dir)?;
                    crate::commission::commission(&backend, &evidence, enable)?
                }
                Commands::RecoverVms => {
                    let _ownership = lock(&state_dir)?;
                    backend.recover_vms()?
                }
                Commands::FinalizeReplacement => {
                    let _ownership = lock(&state_dir)?;
                    install::finalize_replacement(&mut backend)?
                }
                Commands::CheckUsers => crate::accounts::check()?,
                Commands::SecurityStatus => inspect_security(&backend)?,
                Commands::StartupInventory => crate::startup::inventory(Path::new("/"))?,
                Commands::HealthReport => crate::reporting::snapshot(&backend, 172800, None)?,
                Commands::SendHealthReport => crate::reporting::send(&backend)?,
                Commands::FailBoot => {
                    let _ownership = lock(&state_dir)?;
                    let coordinator = Coordinator::new(&state_dir, &backend);
                    let mut state = coordinator.load()?;
                    let mut completed = true;
                    for unit in ["boot-complete.target", "systemd-bless-boot.service"] {
                        if command(
                            &[
                                "systemctl".into(),
                                "is-active".into(),
                                "--quiet".into(),
                                unit.into(),
                            ],
                            None,
                            Some(Duration::from_secs(120)),
                            65536,
                            false,
                        )?
                        .code
                            != 0
                        {
                            completed = false;
                        }
                    }
                    if completed {
                        json!({"boot":"already complete"})
                    } else if !state["pending"].is_null()
                        && state["pending"]["version"] == backend.current_version()?
                    {
                        state["pending"]["phase"] = "booting".into();
                        state["pending"]["boot_id"] = backend.boot_id()?.into();
                        coordinator.save(&mut state)?;
                        run(&["systemctl", "--no-block", "reboot"])?;
                        json!({"failed_candidate":"retry/fallback requested through boot counting"})
                    } else {
                        run(&["systemctl", "--no-block", "isolate", "emergency.target"])?;
                        json!({"boot_failure":"owner recovery required"})
                    }
                }
                Commands::ReplaceDisk {
                    role,
                    disk,
                    serial,
                    rebuild_quarantined,
                    confirm,
                    recovery_key_file,
                } => {
                    let _ownership = lock(&state_dir)?;
                    install::replace(
                        &host,
                        &mut backend,
                        &role,
                        &json!({"role":role,"path":disk,"serial":serial}),
                        confirm.as_deref(),
                        recovery_key_file.as_deref(),
                        rebuild_quarantined,
                    )?
                }
                Commands::Status => {
                    json!({"bootloaders":crate::bootloaders::Loaders::new(&backend).load()?,"state":crate::coordinator::load_state(&state_dir)?,"installation_sha256":digest(&backend.manifest)?,"capacity":backend.check_storage(false)?,"resources":backend.check_resources(false)?,"commissioned":backend.directory.join("commissioned.json").exists()})
                }
                _ => return Err(Error::new("command dispatch invariant violated")),
            };
            Ok((0, result))
        }
    }
}
pub fn main() -> i32 {
    let args = Arguments::parse();
    match execute(args) {
        Ok((status, result)) => match serde_json::to_string_pretty(&result) {
            Ok(output) => {
                println!("{output}");
                status
            }
            Err(error) => {
                eprintln!("particleve: {error}");
                1
            }
        },
        Err(error) => {
            eprintln!("particleve: {error}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_commands_keep_required_review_and_recovery_flags() {
        for command in [
            "assess",
            "bless-current",
            "runtime-guard",
            "recover-vms",
            "finalize-replacement",
            "check-users",
            "fail-boot",
            "status",
            "security-status",
            "startup-inventory",
            "health-report",
            "send-health-report",
            "disable-automation",
        ] {
            assert!(
                Arguments::try_parse_from(["particleve", command]).is_ok(),
                "{command}"
            );
        }
        assert!(Arguments::try_parse_from(["particleve", "reconfigure"]).is_err());
        assert!(Arguments::try_parse_from(["particleve", "reconfigure", "--resume"]).is_ok());
        assert!(
            Arguments::try_parse_from([
                "particleve",
                "reconfigure",
                "--resume",
                "--previous-config",
                "previous.json"
            ])
            .is_err()
        );
        assert!(
            Arguments::try_parse_from([
                "particleve",
                "install",
                "--release-dir",
                "release",
                "--plan",
                "plan",
                "--confirm",
                "hash"
            ])
            .is_err()
        );
        assert!(
            Arguments::try_parse_from([
                "particleve",
                "replace-disk",
                "--role",
                "c",
                "--disk",
                "/dev/disk/by-id/disk",
                "--serial",
                "serial"
            ])
            .is_err()
        );
        assert!(Arguments::try_parse_from(["particleve", "activate", "--manual"]).is_ok());
    }
}
