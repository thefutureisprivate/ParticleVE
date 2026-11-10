//! Read-only platform discovery; destructive targets remain explicitly selected.
use crate::common::{self, Error, Result, field, list, require, run, text, uint};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::Read,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};
const INSTALL_TOOLS: &[&str] = &[
    "lsblk",
    "sfdisk",
    "udevadm",
    "mdadm",
    "cryptsetup",
    "systemd-cryptenroll",
    "mkfs.btrfs",
    "btrfs",
    "mkfs.vfat",
    "mkswap",
    "mount",
    "umount",
    "efibootmgr",
    "sbverify",
    "gpgv",
    "bootctl",
    "systemd-sysusers",
    "systemd-tmpfiles",
    "systemd-firstboot",
    "systemctl",
    "systemd-analyze",
    "tpm2_pcrread",
    "tpm2_testparms",
    "restorecon",
    "setfiles",
    "veritysetup",
    "blkid",
    "nft",
];
pub fn block_tree(path: Option<&str>) -> Result<Value> {
    let mut args = vec![
        "lsblk",
        "--json",
        "--bytes",
        "--paths",
        "--output",
        "NAME,TYPE,SIZE,SERIAL,WWN,LOG-SEC,PHY-SEC,RO,RM,MOUNTPOINTS,PKNAME,PARTN,PARTUUID,PARTLABEL,PARTTYPE,PTUUID",
    ];
    if let Some(path) = path {
        args.push(path);
    }
    let result = common::parse_json(run(&args)?.stdout.as_bytes())?;
    Ok(field(&result, "blockdevices")?.clone())
}
pub fn walk(tree: &Value) -> Result<Vec<Value>> {
    fn visit(tree: &Value, out: &mut Vec<Value>) -> Result<()> {
        for node in list(tree)? {
            require(
                out.len() < 16384,
                "block-device tree exceeds its entry limit",
            )?;
            out.push(node.clone());
            if let Some(children) = node.get("children") {
                visit(children, out)?;
            }
        }
        Ok(())
    }
    let mut result = Vec::new();
    visit(tree, &mut result)?;
    Ok(result)
}
pub fn observe_disk(selected: &Value, unused: bool) -> Result<Value> {
    let path = Path::new(text(field(selected, "path")?)?);
    require(
        fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()),
        format!("stable disk identity does not exist: {}", path.display()),
    )?;
    let tree = block_tree(path.to_str())?;
    let nodes = list(&tree)?;
    require(
        nodes.len() == 1,
        format!("ambiguous selected disk: {}", path.display()),
    )?;
    let disk = &nodes[0];
    require(
        text(field(disk, "type")?)? == "disk"
            && field(disk, "ro")? == &json!(false)
            && field(disk, "rm")? == &json!(false),
        format!("not a writable fixed disk: {}", path.display()),
    )?;
    let serial = disk["serial"].as_str().unwrap_or("").trim();
    require(
        serial == text(field(selected, "serial")?)?,
        format!("disk serial changed: {}", path.display()),
    )?;
    if unused {
        for node in walk(&tree)? {
            let mounts = node.get("mountpoints").and_then(Value::as_array);
            require(
                mounts.is_none_or(|a| a.iter().all(|v| v.is_null() || v.as_str() == Some(""))),
                format!(
                    "selected disk is mounted/in use: {}",
                    text(field(&node, "name")?)?
                ),
            )?;
            require(
                matches!(text(field(&node, "type")?)?, "disk" | "part"),
                format!(
                    "selected disk has active holders: {}",
                    text(field(&node, "name")?)?
                ),
            )?;
            let name = Path::new(text(field(&node, "name")?)?)
                .file_name()
                .ok_or_else(|| Error::new("invalid block-device name"))?;
            let holders = Path::new("/sys/class/block").join(name).join("holders");
            require(
                !holders.exists() || fs::read_dir(holders)?.next().is_none(),
                format!(
                    "selected disk has holders: {}",
                    text(field(&node, "name")?)?
                ),
            )?;
        }
    }
    let info = path.metadata()?;
    // Linux dev_t major/minor decoding is provided by libc and does not access memory.
    let identity = format!("{}:{}", libc::major(info.rdev()), libc::minor(info.rdev()));
    Ok(
        json!({"identity":identity,"size":field(disk,"size")?,"serial":serial,"wwn":field(disk,"wwn")?,"logical_sector":field(disk,"log-sec")?,"physical_sector":field(disk,"phy-sec")?}),
    )
}
fn matching_entries(
    directory: &Path,
    prefix: &str,
    suffix: &str,
) -> Result<Vec<std::path::PathBuf>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(prefix) && name.ends_with(suffix) {
            require(
                result.len() < 4096,
                "platform inventory exceeds its entry limit",
            )?;
            result.push(entry.path());
        }
    }
    Ok(result)
}
pub fn secure_boot() -> bool {
    (|| -> Result<bool> {
        let vars = matching_entries(Path::new("/sys/firmware/efi/efivars"), "SecureBoot-", "")?;
        Ok(vars.len() == 1 && common::read_bounded(&vars[0], 4096)?.get(4..) == Some(&[1]))
    })()
    .unwrap_or(false)
}
pub fn kvm_available() -> bool {
    let Ok(fd) = File::open("/dev/kvm") else {
        return false;
    };
    // SAFETY: KVM_GET_API_VERSION takes no pointer and the fd remains open.
    unsafe { libc::ioctl(fd.as_raw_fd(), 0xAE00) == 12 }
}
pub fn measured_boot(normal: bool) -> Result<bool> {
    run(&["systemd-analyze", "has-tpm2"])?;
    let mut logs = Vec::new();
    for p in matching_entries(Path::new("/sys/kernel/security"), "tpm", "")? {
        let log = p.join("binary_bios_measurements");
        if log.exists() {
            logs.push(log);
        }
    }
    require(logs.len() == 1, "one firmware TPM event log is required")?;
    let mut one = [0];
    require(
        File::open(&logs[0])?.read(&mut one)? == 1,
        "firmware TPM event log is empty",
    )?;
    let registers = if normal { vec![7, 11] } else { vec![7] };
    let temporary = tempfile::Builder::new()
        .prefix("particleve-pcr-")
        .tempdir_in("/run")?;
    let output = temporary.path().join("pcrs.bin");
    run(&[
        "tpm2_pcrread",
        "--pcrs_format=values",
        &format!("--output={}", output.display()),
        &format!(
            "sha256:{}",
            registers
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
    ])?;
    let data = common::read_bounded(output, 65)?;
    require(
        data.len() == 32 * registers.len(),
        "unexpected SHA256 PCR data",
    )?;
    for (offset, register) in registers.iter().enumerate() {
        require(
            data[offset * 32..(offset + 1) * 32].iter().any(|b| *b != 0),
            format!("firmware SHA256 PCR{register} has no measurements"),
        )?;
    }
    if normal {
        run(&[
            "systemd-analyze",
            "condition",
            "ConditionSecurity=measured-uki",
        ])?;
    }
    Ok(true)
}
fn which(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| {
            let file = d.join(name);
            file.metadata()
                .is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0)
        })
    })
}
pub fn installer_utilities() -> Result<bool> {
    let missing = INSTALL_TOOLS
        .iter()
        .filter(|n| !which(n))
        .copied()
        .collect::<Vec<_>>();
    require(
        missing.is_empty(),
        format!("missing installer utilities: {}", missing.join(", ")),
    )?;
    Ok(true)
}
fn add_check(checks: &mut Vec<Value>, name: &str, result: Result<bool>) -> bool {
    let (ok, detail) = match result {
        Ok(true) => (true, "passed".to_owned()),
        Ok(false) => (false, "unavailable".to_owned()),
        Err(e) => (false, e.to_string()),
    };
    checks.push(json!({"name":name,"ok":ok,"detail":detail}));
    ok
}
pub fn collect(config: &Value) -> Result<Value> {
    let mut checks = Vec::new();
    add_check(
        &mut checks,
        "architecture",
        Ok(std::env::consts::ARCH == "x86_64"),
    );
    let cpu = fs::read_to_string("/proc/cpuinfo")?;
    let flags = cpu
        .lines()
        .find(|l| l.starts_with("flags"))
        .and_then(|l| l.split_once(':'))
        .map_or(Vec::new(), |(_, f)| {
            f.split_whitespace().collect::<Vec<_>>()
        });
    add_check(
        &mut checks,
        "x86-64-v2",
        Ok(["cx16", "lahf_lm", "popcnt", "sse4_1", "sse4_2", "ssse3"]
            .iter()
            .all(|f| flags.contains(f))),
    );
    add_check(
        &mut checks,
        "CPU virtualization",
        Ok(flags.contains(&"vmx") || flags.contains(&"svm")),
    );
    add_check(&mut checks, "KVM API", Ok(kvm_available()));
    add_check(
        &mut checks,
        "UEFI",
        Ok(Path::new("/sys/firmware/efi").is_dir()),
    );
    add_check(&mut checks, "Secure Boot", Ok(secure_boot()));
    let tpm = (|| -> Result<bool> {
        for p in matching_entries(Path::new("/sys/class/tpm"), "tpm", "")? {
            if fs::read_to_string(p.join("tpm_version_major"))?.trim() == "2" {
                return Ok(true);
            }
        }
        Ok(false)
    })();
    add_check(&mut checks, "TPM2", tpm);
    add_check(
        &mut checks,
        "TPM RSA4096 PCR policy",
        run(&["tpm2_testparms", "rsa4096"]).map(|o| o.code == 0),
    );
    add_check(
        &mut checks,
        "firmware TPM measurements",
        measured_boot(false),
    );
    let mem = fs::read_to_string("/proc/meminfo")?;
    let ram = mem
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .ok_or_else(|| Error::new("physical RAM is unavailable"))?
        .parse::<u64>()
        .map_err(|_| Error::new("invalid physical RAM"))?;
    add_check(
        &mut checks,
        "physical RAM",
        Ok(ram / 1024 >= uint(field(config, "minimum_ram_mib")?)?),
    );
    add_check(&mut checks, "installer utilities", installer_utilities());
    let physical = match crate::physical::collect(Path::new("/sys")) {
        Ok(p) => {
            add_check(&mut checks, "physical-interface inventory", Ok(true));
            p
        }
        Err(e) => {
            add_check(&mut checks, "physical-interface inventory", Err(e));
            Value::Null
        }
    };
    let mut devices = Vec::new();
    for selected in list(field(config, "disks")?)? {
        let outcome = match observe_disk(selected, true) {
            Ok(d) => {
                devices.push(d);
                Ok(true)
            }
            Err(e) => Err(e),
        };
        add_check(
            &mut checks,
            &format!("disk {}", text(field(selected, "role")?)?),
            outcome,
        );
    }
    for nic in list(field(field(config, "network")?, "links")?)? {
        let outcome = (|| -> Result<bool> {
            let observed = common::parse_json(run(&["ip", "--json", "link"])?.stdout.as_bytes())?;
            Ok(list(&observed)?
                .iter()
                .any(|d| d.get("permaddr").or_else(|| d.get("address")) == nic.get("mac")))
        })();
        add_check(
            &mut checks,
            &format!("NIC {}", text(field(nic, "name")?)?),
            outcome,
        );
    }
    let firmware = if which("fwupdmgr") {
        Some(common::command(
            &["fwupdmgr", "get-devices", "--json"].map(str::to_owned),
            None,
            Some(std::time::Duration::from_secs(120)),
            8 * 1024 * 1024,
            false,
        )?)
    } else {
        None
    };
    add_check(
        &mut checks,
        "fwupd discovery",
        Ok(firmware.as_ref().is_some_and(|f| matches!(f.code, 0 | 2))),
    );
    let fw = match firmware {
        Some(f) if f.code == 0 => common::parse_json(f.stdout.as_bytes())?,
        _ => Value::Null,
    };
    Ok(
        json!({"schema":1,"ok":checks.iter().all(|c|c["ok"]==true),"checks":checks,"devices":devices,"physical_ram_mib":ram/1024,"physical_interfaces":physical,"firmware":fw,"validation":"capability inventory; boot and firmware flashing still require commissioning"}),
    )
}
pub fn partition_path(disk_path: &str, number: u64) -> Result<String> {
    let matches = walk(&block_tree(Some(disk_path))?)?
        .into_iter()
        .filter(|n| n.get("partn").and_then(Value::as_u64) == Some(number))
        .collect::<Vec<_>>();
    require(
        matches.len() == 1,
        format!("cannot resolve partition {number} on {disk_path}"),
    )?;
    Ok(text(field(&matches[0], "name")?)?.into())
}
