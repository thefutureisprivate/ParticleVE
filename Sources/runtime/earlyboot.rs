//! Initrd assembly admits firmware-authorized members before opening storage.
use crate::common::{Error, Result, atomic_write, field, list, read_json, require, run, text};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

fn block(path: &str) -> Result<()> {
    require(
        fs::metadata(path)?.file_type().is_block_device(),
        format!("not a block device: {path}"),
    )
}

pub fn assemble() -> Result<()> {
    run(&["udevadm", "settle", "--timeout=30"])?;
    fs::create_dir_all("/run/particleve-root-probe")?;
    fs::create_dir_all("/sysroot")?;
    // SAFETY: firmware authority is persisted before unlock, scanning or writable mounts.
    crate::admission::begin()?;
    let session = read_json(crate::admission::SESSION)?;
    let witness = field(&session, "witness")?;
    let roles = list(field(witness, "allowed")?)?;
    require(
        (1..=2).contains(&roles.len()),
        "invalid admitted member count",
    )?;
    let mut mapped = Vec::new();
    let mut swap_members = Vec::new();
    for role in roles {
        let role = text(role)?;
        require(matches!(role, "a" | "b"), "invalid admitted role")?;
        let member = field(field(witness, "members")?, role)?;
        let state = text(field(member, "state")?)?;
        let partition = format!("/dev/disk/by-partuuid/{state}");
        require(
            run(&["blkid", "-t", &format!("PARTUUID={state}"), "-o", "device"])?
                .stdout
                .lines()
                .count()
                == 1,
            "state partition identity is absent or duplicated",
        )?;
        require(
            run(&["cryptsetup", "luksUUID", &partition])?.stdout.trim()
                == text(field(member, "luks")?)?,
            "state LUKS identity changed",
        )?;
        // The native service's 240-second startup timeout and signed five-minute
        // watchdog own the console-unlock deadline, as in the shell integration.
        // A shorter per-child deadline would cut off owner recovery prompts.
        crate::common::command(
            &[
                "/usr/lib/systemd/systemd-cryptsetup",
                "attach",
                &format!("particleve-state-{role}"),
                &partition,
                "-",
                "tpm2-device=auto",
            ]
            .map(str::to_owned),
            None,
            None,
            8 * 1024 * 1024,
            true,
        )?;
        let mapper = format!("/dev/mapper/particleve-state-{role}");
        require(
            run(&["blkid", "-s", "UUID", "-o", "value", &mapper])?
                .stdout
                .trim()
                == text(field(witness, "btrfs_uuid")?)?,
            "state filesystem identity changed",
        )?;
        mapped.push(mapper);
        let swap = format!("/dev/disk/by-partuuid/{}", text(field(member, "swap")?)?);
        block(&swap)?;
        swap_members.push(swap);
    }
    let mut scan = vec!["btrfs", "device", "scan"];
    scan.extend(mapped.iter().map(String::as_str));
    run(&scan)?;
    let probe = Path::new("/run/particleve-root-probe");
    run(&[
        "mount",
        "-t",
        "btrfs",
        "-o",
        if mapped.len() == 2 {
            "ro,rescue=nologreplay"
        } else {
            "ro,rescue=nologreplay,degraded"
        },
        &mapped[0],
        "/run/particleve-root-probe",
    ])?;
    // Preserve the failed, read-only probe for diagnosis. No later root mount is
    // permitted until both persistent authority and startup hooks are checked.
    let manifest = read_json(probe.join("var/lib/particleve/installation.json"))?;
    crate::admission::verify_manifest(&manifest, None)?;
    crate::startup::check(probe)?;
    let swap_uuid = text(field(field(&manifest, "swap")?, "md_uuid")?)?;
    require(
        regex::Regex::new(r"^[0-9a-f]{8}(:[0-9a-f]{8}){3}$")
            .expect("constant expression")
            .is_match(swap_uuid),
        "invalid swap array UUID",
    )?;
    atomic_write(
        "/run/particleve-mdadm.conf",
        format!("HOMEHOST <ignore>\nAUTO -all\nARRAY /dev/md/particleve-swap UUID={swap_uuid}\n")
            .as_bytes(),
        0o600,
    )?;
    run(&["umount", "/run/particleve-root-probe"])?;
    run(&[
        "mount",
        "-t",
        "btrfs",
        "-o",
        if mapped.len() == 2 {
            "rw,compress=zstd:1"
        } else {
            "rw,compress=zstd:1,degraded"
        },
        &mapped[0],
        "/sysroot",
    ])?;
    crate::allocator::prepare_root(Path::new("/sysroot"))?;
    let uuid_option = format!("--uuid={swap_uuid}");
    let mut assemble = vec![
        "mdadm",
        "--assemble",
        "--run",
        "--config=/run/particleve-mdadm.conf",
        &uuid_option,
        "/dev/md/particleve-swap",
    ];
    assemble.extend(swap_members.iter().map(String::as_str));
    run(&assemble)?;
    block("/dev/md/particleve-swap")?;
    let detail = run(&["mdadm", "--detail", "--export", "/dev/md/particleve-swap"])?.stdout;
    let observed = detail
        .lines()
        .filter_map(|line| line.strip_prefix("MD_UUID="))
        .collect::<Vec<_>>();
    require(
        observed == [swap_uuid],
        "assembled swap array identity changed",
    )
}

pub fn admission_cli(arguments: &[String]) -> Result<()> {
    // SAFETY: geteuid has no memory arguments or ownership effects.
    require(
        unsafe { libc::geteuid() } == 0,
        "storage admission requires root",
    )?;
    match arguments {
        [command] if command == "begin" => crate::admission::begin(),
        [command] if command == "finish" => crate::admission::finish(),
        [command] if command == "watch" => crate::admission::watch().map(|_| ()),
        [command, path] if command == "verify" => {
            crate::admission::verify_manifest(&read_json(path)?, None).map(|_| ())
        }
        [command, path] if command == "startup" => {
            crate::startup::check(Path::new(path)).map(|_| ())
        }
        [command, role, uuid] if command == "recover" && matches!(role.as_str(), "a" | "b") => {
            crate::admission::recover(role, uuid)
        }
        _ => Err(Error::new(
            "expected begin, finish, watch, verify MANIFEST, startup ROOT or recover ROLE INSTALLATION_UUID",
        )),
    }
}

pub fn exit(result: Result<()>, context: &str) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ParticleVE {context}: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

pub fn json_output(value: &Value) -> Result<()> {
    use std::io::Write;
    std::io::stdout()
        .lock()
        .write_all(&crate::common::canonical(value)?)?;
    Ok(())
}
