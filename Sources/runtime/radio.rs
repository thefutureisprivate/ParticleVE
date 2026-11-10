//! A zero-capability service reconciles only its inherited RFKill descriptor.
use crate::common::{
    Error, Result, canonical, digest, field, list, read_bounded, read_json, require, run, text,
};
use crate::physical::{MAX_NODES, Observation};
use crate::processes::Process;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;
use std::time::{Duration, Instant};
pub const TYPES: &[&str] = &[
    "wlan",
    "bluetooth",
    "ultrawideband",
    "wimax",
    "wwan",
    "gps",
    "fm",
    "nfc",
];
pub const POLICY_PATH: &str = "/etc/particleve/radio-policy.json";
pub const UNIT: &str = "particleve-radio-policy.service";
pub const BLOCK_TIMEOUT: Duration = Duration::from_secs(5);
pub fn validate(policy: &Value) -> Result<()> {
    let object = policy
        .as_object()
        .ok_or_else(|| Error::new("declare the radio allowed_types policy"))?;
    require(
        object.len() == 1 && object.contains_key("allowed_types"),
        "declare the radio allowed_types policy",
    )?;
    let allowed = list(&object["allowed_types"])?;
    let mut unique = BTreeSet::new();
    require(
        allowed.len() <= TYPES.len(),
        "radio allowed_types must be unique canonical RFKill types",
    )?;
    for value in allowed {
        let name = text(value)?;
        require(
            TYPES.contains(&name) && unique.insert(name),
            "radio allowed_types must be unique canonical RFKill types",
        )?;
    }
    Ok(())
}
pub fn render(policy: &Value) -> Result<BTreeMap<String, String>> {
    validate(policy)?;
    Ok([(
        POLICY_PATH.trim_start_matches('/').to_owned(),
        String::from_utf8(canonical(policy)?)?,
    )]
    .into_iter()
    .collect())
}
fn write_event(file: &mut File, index: u32, kind: u8, operation: u8, blocked: u8) -> Result<()> {
    let mut data = [0u8; 8];
    data[..4].copy_from_slice(&index.to_ne_bytes());
    data[4] = kind;
    data[5] = operation;
    data[6] = blocked;
    require(
        file.write(&data)? == data.len(),
        "incomplete RFKill policy write",
    )
}
pub struct Control {
    file: File,
    allowed: BTreeSet<u8>,
    pub pending: BTreeMap<u32, Instant>,
}
impl Control {
    pub fn new(file: File, policy: &Value) -> Result<Self> {
        validate(policy)?;
        let mut allowed = BTreeSet::new();
        for name in list(field(policy, "allowed_types")?)? {
            let name = text(name)?;
            let index = TYPES
                .iter()
                .position(|s| *s == name)
                .ok_or_else(|| Error::new("unknown RFKill type"))?;
            allowed.insert((index + 1) as u8);
        }
        Ok(Self {
            file,
            allowed,
            pending: BTreeMap::new(),
        })
    }
    pub fn initialize(&mut self) -> Result<()> {
        for kind in 1..=TYPES.len() as u8 {
            if !self.allowed.contains(&kind) {
                write_event(&mut self.file, 0, kind, 3, 1)?;
            }
        }
        for kind in &self.allowed {
            write_event(&mut self.file, 0, *kind, 3, 0)?;
        }
        Ok(())
    }
    pub fn event(&mut self, data: &[u8]) -> Result<()> {
        require(data.len() == 8, "incomplete RFKill event")?;
        let index = u32::from_ne_bytes(
            data[..4]
                .try_into()
                .map_err(|_| Error::new("incomplete RFKill index"))?,
        );
        let (kind, operation, soft, hard) = (data[4], data[5], data[6], data[7]);
        require(
            (1..=TYPES.len() as u8).contains(&kind)
                && [0, 1, 2].contains(&operation)
                && soft <= 1
                && hard <= 1,
            "unknown RFKill event",
        )?;
        if operation == 1 || soft == 1 {
            self.pending.remove(&index);
        } else if !self.allowed.contains(&kind) {
            self.block(index, kind)?;
        }
        Ok(())
    }
    fn block(&mut self, index: u32, kind: u8) -> Result<()> {
        self.pending.entry(index).or_insert_with(Instant::now);
        require(
            self.pending.len() <= MAX_NODES,
            "too many pending RFKill blocks",
        )?;
        write_event(&mut self.file, index, kind, 2, 1)
    }
    pub fn reconcile(&mut self, sysfs: &Path) -> Result<()> {
        let radios = Observation::new(sysfs)?.radios()?;
        require(
            radios["sysfs_present"] == true,
            "RFKill class is unavailable",
        )?;
        let mut unblocked = BTreeSet::new();
        for radio in list(field(&radios, "devices")?)? {
            let node = text(field(radio, "node")?)?;
            let index = node
                .strip_prefix("rfkill")
                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or_else(|| Error::new("unknown RFKill device"))?;
            let kind = TYPES
                .iter()
                .position(|s| Some(*s) == radio["type"].as_str())
                .ok_or_else(|| Error::new("unknown RFKill device"))? as u8
                + 1;
            if !self.allowed.contains(&kind) && radio["soft_blocked"] == false {
                unblocked.insert(index);
                self.block(index, kind)?;
            }
        }
        self.pending.retain(|index, _| unblocked.contains(index));
        Ok(())
    }
    pub fn drain(&mut self) -> Result<bool> {
        for _ in 0..256 {
            let mut data = [0u8; 8];
            let size = match self.file.read(&mut data) {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(true),
                Err(e) => return Err(e.into()),
            };
            require(size > 0, "RFKill event descriptor closed")?;
            self.event(&data[..size])?;
        }
        Ok(false)
    }
    pub fn check_pending(&self) -> Result<()> {
        let now = Instant::now();
        require(
            self.pending
                .values()
                .all(|started| now.duration_since(*started) < BLOCK_TIMEOUT),
            "radio driver did not acknowledge its required software block",
        )
    }
    fn fd(&self) -> i32 {
        self.file.as_raw_fd()
    }
}
pub fn inherited_descriptor() -> Result<File> {
    // SAFETY: UID queries have no pointer or resource ownership.
    require(
        unsafe { libc::getuid() } != 0 && unsafe { libc::geteuid() } != 0,
        "run radio policy through its unprivileged service",
    )?;
    let status = Process::open(std::process::id(), None, Path::new("/proc"))?.status()?;
    require(
        ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]
            .iter()
            .all(|name| {
                status
                    .get(*name)
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    == Some(0)
            })
            && status.get("NoNewPrivs").map(String::as_str) == Some("1"),
        "radio policy must have no capabilities and no new privileges",
    )?;
    require(
        std::env::var("LISTEN_PID").ok().as_deref()
            == Some(std::process::id().to_string().as_str())
            && std::env::var("LISTEN_FDS").ok().as_deref() == Some("1")
            && std::env::var("LISTEN_FDNAMES").ok().as_deref() == Some("rfkill-control"),
        "radio policy requires exactly one PID1-opened RFKill descriptor",
    )?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit(); // SAFETY: fstat initializes the complete provided record on success; fd3 remains inherited until ownership below.
    require(
        unsafe { libc::fstat(3, metadata.as_mut_ptr()) } == 0,
        "cannot inspect inherited RFKill descriptor",
    )?; // SAFETY: successful fstat initialized metadata.
    let metadata = unsafe { metadata.assume_init() };
    let expected =
        Observation::attribute(Path::new("/sys/devices/virtual/misc/rfkill/dev"), false)?;
    // SAFETY: fcntl F_GETFL does not mutate or transfer descriptor ownership.
    let flags = unsafe { libc::fcntl(3, libc::F_GETFL) };
    require(
        metadata.st_mode & libc::S_IFMT == libc::S_IFCHR
            && expected
                == Some(format!(
                    "{}:{}",
                    libc::major(metadata.st_rdev),
                    libc::minor(metadata.st_rdev)
                ))
            && flags >= 0
            && flags & libc::O_ACCMODE == libc::O_RDWR,
        "inherited descriptor is not the writable RFKill device",
    )?;
    crate::platform::nonblocking(3)?; // SAFETY: fd3 has been validated; F_SETFD only changes its close-on-exec flag.
    require(
        unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
        "cannot seal inherited RFKill descriptor",
    )?;
    for key in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        // SAFETY: the service is still single-threaded and starts no threads; no concurrent environment access exists.
        unsafe { std::env::remove_var(key) };
    }
    // SAFETY: PID1 supplied exactly this descriptor, whose sole Rust owner is returned.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(3) }))
}
pub fn inhibit_input(fd: i32, kernel_config: &Path) -> Result<()> {
    // SAFETY: RFKILL_IOCTL_NOINPUT takes no pointer and affects this validated RFKill descriptor only.
    if unsafe { libc::ioctl(fd, 0x5201) } < 0 {
        let error = std::io::Error::last_os_error();
        let config = String::from_utf8(read_bounded(kernel_config, 8 * 1024 * 1024)?)?;
        require(
            error.raw_os_error() == Some(libc::ENOTTY)
                && config
                    .lines()
                    .any(|line| line == "# CONFIG_RFKILL_INPUT is not set"),
            "cannot inhibit the kernel RFKill input handler",
        )?;
    }
    Ok(())
}
pub fn serve() -> Result<()> {
    let fd = inherited_descriptor()?;
    let directory = std::env::var("CREDENTIALS_DIRECTORY")
        .map_err(|_| Error::new("radio policy requires its unit credential"))?;
    require(
        directory == format!("/run/credentials/{UNIT}"),
        "radio policy requires its unit credential",
    )?;
    let path = Path::new(&directory).join("radio-policy");
    require(
        path.metadata()?.len() <= 1024,
        "radio policy credential exceeds its bound",
    )?;
    let policy = read_json(path)?;
    validate(&policy)?;
    let mut control = Control::new(fd, &policy)?;
    let destination = std::env::var("NOTIFY_SOCKET")
        .map_err(|_| Error::new("radio policy requires service supervision"))?;
    require(
        !destination.is_empty(),
        "radio policy requires service supervision",
    )?; // SAFETY: this service has not created threads and no further environment mutation occurs.
    unsafe { std::env::remove_var("NOTIFY_SOCKET") };
    let notify = UnixDatagram::unbound()?;
    if let Some(name) = destination.strip_prefix('@') {
        notify.connect_addr(&SocketAddr::from_abstract_name(name.as_bytes())?)?;
    } else {
        notify.connect(destination)?;
    }
    inhibit_input(control.fd(), &Path::new(&directory).join("kernel-config"))?;
    control.initialize()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_ping = Instant::now();
    let mut next_reconcile = Instant::now();
    let mut ready = false;
    loop {
        let drained = control.drain()?;
        if Instant::now() >= next_reconcile {
            control.reconcile(Path::new("/sys"))?;
            next_reconcile = Instant::now() + Duration::from_secs(1);
        }
        control.check_pending()?;
        if !ready {
            require(
                Instant::now() < deadline,
                "radio initialization did not settle",
            )?;
            if drained && control.pending.is_empty() {
                notify.send(
                    format!("READY=1\nSTATUS=RFKill policy {}", digest(&policy)?).as_bytes(),
                )?;
                ready = true;
            }
        }
        if last_ping.elapsed() >= Duration::from_secs(5) {
            notify.send(b"WATCHDOG=1")?;
            last_ping = Instant::now();
        }
        if drained {
            crate::platform::poll(
                &mut [libc::pollfd {
                    fd: control.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                }],
                1000,
            )?;
        }
    }
}
fn verify_service(policy: &Value, observed: &str) -> Result<()> {
    let props: BTreeMap<_, _> = observed.lines().filter_map(|s| s.split_once('=')).collect();
    require(
        props.len() == 3
            && props.get("ActiveState") == Some(&"active")
            && props.get("SubState") == Some(&"running")
            && props.get("StatusText").copied()
                == Some(format!("RFKill policy {}", digest(policy)?).as_str()),
        "radio policy service is inactive or using a different configuration",
    )?;
    Ok(())
}
fn verify_radios(policy: &Value, radios: &Value) -> Result<()> {
    require(
        radios["sysfs_present"] == true,
        "RFKill class is unavailable",
    )?;
    for radio in list(field(radios, "devices")?)? {
        let kind = text(field(radio, "type")?)?;
        require(TYPES.contains(&kind), "unknown RFKill radio type")?;
        require(
            list(field(policy, "allowed_types")?)?.contains(&radio["type"])
                || radio["soft_blocked"] == true,
            format!(
                "denied radio lacks its software block: {}",
                text(field(radio, "node")?)?
            ),
        )?;
    }
    Ok(())
}
pub fn baseline(
    policy: &Value,
    sysfs: &Path,
    proc: &Path,
    device: &Path,
    policy_path: &Path,
) -> Result<Value> {
    validate(policy)?;
    require(
        read_bounded(policy_path, 1024)? == canonical(policy)?,
        "radio policy differs from the bound installation",
    )?;
    let cmdline = String::from_utf8(read_bounded(proc.join("cmdline"), 1024 * 1024)?)?;
    require(
        cmdline
            .split_whitespace()
            .any(|s| s == "rfkill.default_state=0")
            && Observation::attribute(
                &sysfs.join("module/rfkill/parameters/default_state"),
                false,
            )?
            .as_deref()
                == Some("0"),
        "RFKill early default is not blocked",
    )?;
    let info = device.metadata()?;
    require(
        info.file_type().is_char_device()
            && info.uid() == 0
            && info.gid() == 0
            && info.mode() & 0o7777 == 0o600,
        "RFKill device must be writable only by root",
    )?;
    for unit in ["systemd-rfkill.service", "systemd-rfkill.socket"] {
        let result = run(&["systemctl", "show", "--property=LoadState", "--value", unit])?;
        require(
            result.stderr.trim().is_empty(),
            format!("RFKill inspection diagnostics: {}", result.stderr.trim()),
        )?;
        require(
            result.stdout.trim() == "masked",
            "native RFKill state restoration is not masked",
        )?;
    }
    let result = run(&[
        "systemctl",
        "show",
        "--property=ActiveState,SubState,StatusText",
        UNIT,
    ])?;
    require(
        result.stderr.trim().is_empty(),
        format!("RFKill inspection diagnostics: {}", result.stderr.trim()),
    )?;
    verify_service(policy, &result.stdout)?;
    let radios = Observation::new(sysfs)?.radios()?;
    verify_radios(policy, &radios)?;
    Ok(
        json!({"allowed_types":policy["allowed_types"],"devices":radios["devices"],"early_default_blocked":true}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::fd::IntoRawFd;
    #[test]
    fn event_acknowledgment_and_stricter_allowed_block() {
        let (service, kernel) = std::os::unix::net::UnixStream::pair().unwrap();
        let file = unsafe { File::from_raw_fd(service.into_raw_fd()) };
        let mut control = Control::new(file, &json!({"allowed_types":["wlan"]})).unwrap();
        control.event(&[10, 0, 0, 0, 2, 0, 0, 1]).unwrap();
        assert!(control.pending.contains_key(&10));
        let mut ack = [0; 8];
        (&kernel).read_exact(&mut ack).unwrap();
        assert_eq!(ack, [10, 0, 0, 0, 2, 2, 1, 0]);
        control.event(&[10, 0, 0, 0, 2, 2, 1, 1]).unwrap();
        assert!(control.pending.is_empty());
        control.event(&[11, 0, 0, 0, 1, 0, 1, 0]).unwrap();
        assert!(control.pending.is_empty());
        assert!(control.event(&[0, 0, 0, 0, 9, 0, 0, 0]).is_err());
    }
    fn control_pair(allowed: &[&str]) -> (Control, std::os::unix::net::UnixStream) {
        let (service, kernel) = std::os::unix::net::UnixStream::pair().expect("RFKill channel");
        service.set_nonblocking(true).expect("nonblocking service");
        kernel.set_nonblocking(true).expect("nonblocking kernel");
        let file = File::from(OwnedFd::from(service));
        (
            Control::new(file, &json!({"allowed_types":allowed})).expect("control"),
            kernel,
        )
    }
    #[test]
    fn initialization_blocks_denied_types_before_enabling_reviewed_types() {
        let (mut control, mut kernel) = control_pair(&["wlan"]);
        control.initialize().expect("initialize");
        for kind in 2..=TYPES.len() as u8 {
            let mut event = [0; 8];
            kernel.read_exact(&mut event).expect("denied default");
            assert_eq!(event, [0, 0, 0, 0, kind, 3, 1, 0]);
        }
        let mut event = [0; 8];
        kernel.read_exact(&mut event).expect("allowed default");
        assert_eq!(event, [0, 0, 0, 0, 1, 3, 0, 0]);
    }
    #[test]
    fn malformed_lost_lifecycle_events_and_pending_timeouts_fail_safely() {
        let (mut control, _kernel) = control_pair(&[]);
        for event in [
            vec![0; 3],
            vec![0, 0, 0, 0, 0, 0, 1, 0],
            vec![0, 0, 0, 0, 9, 0, 1, 0],
            vec![0, 0, 0, 0, 1, 3, 1, 0],
            vec![0, 0, 0, 0, 1, 0, 2, 0],
            vec![0, 0, 0, 0, 1, 0, 1, 2],
        ] {
            assert!(control.event(&event).is_err());
        }
        for event in [
            [0, 0, 0, 0, 1, 0, 1, 0],
            [0, 0, 0, 0, 1, 0, 1, 0],
            [0, 0, 0, 0, 2, 2, 1, 0],
            [9, 0, 0, 0, 1, 1, 1, 0],
        ] {
            control.event(&event).expect("lost lifecycle event");
        }
        control.pending.insert(1, Instant::now());
        control.check_pending().expect("pending acknowledgement");
        control.pending.insert(1, Instant::now() - BLOCK_TIMEOUT);
        assert!(
            control
                .check_pending()
                .expect_err("unacknowledged")
                .message
                .contains("acknowledge")
        );
    }
    #[test]
    fn missing_acknowledgements_cannot_grow_beyond_the_native_node_bound() {
        let (mut control, _kernel) = control_pair(&[]);
        for index in 0..MAX_NODES as u32 {
            control.pending.insert(index, Instant::now());
        }
        let mut event = (MAX_NODES as u32).to_ne_bytes().to_vec();
        event.extend([1, 0, 0, 0]);
        assert!(
            control
                .event(&event)
                .expect_err("pending bound")
                .message
                .contains("too many pending")
        );
    }
    #[test]
    fn independent_reconciliation_recovers_lost_acknowledgement_and_removal() {
        let root = tempfile::tempdir().expect("sysfs");
        let nodes = root.path().join("class/rfkill");
        fs::create_dir_all(&nodes).expect("class");
        for (index, kind) in [(0, "wlan"), (1, "bluetooth")] {
            let device = root.path().join(format!("devices/rfkill{index}"));
            fs::create_dir_all(&device).expect("device");
            std::os::unix::fs::symlink(&device, nodes.join(format!("rfkill{index}")))
                .expect("sysfs reference");
            for (name, value) in [("type", kind), ("soft", "0"), ("hard", "1")] {
                fs::write(device.join(name), value).expect("attribute");
            }
        }
        let (mut control, mut kernel) = control_pair(&["wlan"]);
        control.reconcile(root.path()).expect("recover ADD");
        let mut event = [0; 8];
        kernel.read_exact(&mut event).expect("software block");
        assert_eq!(event, [1, 0, 0, 0, 2, 2, 1, 0]);
        assert!(control.pending.contains_key(&1));
        fs::write(root.path().join("devices/rfkill1/soft"), "1").expect("driver ACK");
        control.reconcile(root.path()).expect("recover ACK");
        assert!(control.pending.is_empty());
        control.pending.insert(1, Instant::now() - BLOCK_TIMEOUT);
        fs::remove_file(nodes.join("rfkill1")).expect("hot unplug");
        control.reconcile(root.path()).expect("recover DEL");
        control
            .check_pending()
            .expect("removed device cannot time out");
    }
    #[test]
    fn event_flood_yields_before_starving_deadlines_and_closed_control_fails() {
        let (mut control, mut kernel) = control_pair(&["wlan"]);
        let mut events = Vec::new();
        for index in 0u32..300 {
            events.extend(index.to_ne_bytes());
            events.extend([1, 0, 0, 0]);
        }
        kernel.write_all(&events).expect("kernel flood");
        assert!(!control.drain().expect("bounded batch"));
        assert!(control.drain().expect("remaining batch"));
        drop(kernel);
        assert!(
            control
                .drain()
                .expect_err("closed channel")
                .message
                .contains("closed")
        );
    }
    #[test]
    fn noinput_ioctl_only_accepts_the_explicit_compiled_out_kernel_capability() {
        let root = tempfile::tempdir().expect("kernel fixture");
        let config = root.path().join("config");
        let (service, _kernel) = std::os::unix::net::UnixStream::pair().expect("descriptor");
        fs::write(&config, "# CONFIG_RFKILL_INPUT is not set\n").expect("disabled input");
        inhibit_input(service.as_raw_fd(), &config).expect("ENOTTY with compiled-out input");
        for text in ["CONFIG_RFKILL_INPUT=y\n", ""] {
            fs::write(&config, text).expect("kernel input");
            assert!(inhibit_input(service.as_raw_fd(), &config).is_err());
        }
        fs::write(&config, "# CONFIG_RFKILL_INPUT is not set\n").expect("disabled input");
        assert!(inhibit_input(-1, &config).is_err());
    }
    #[test]
    fn service_digest_and_denied_software_blocks_are_independent_requirements() {
        let policy = json!({"allowed_types":[]});
        let live = format!(
            "ActiveState=active\nSubState=running\nStatusText=RFKill policy {}",
            digest(&policy).expect("digest")
        );
        verify_service(&policy, &live).expect("service");
        assert!(verify_service(&policy, &(live + " stale")).is_err());
        let mut radios = json!({"sysfs_present":true,"devices":[{"node":"rfkill0","type":"bluetooth","soft_blocked":true,"hard_blocked":true}]});
        verify_radios(&policy, &radios).expect("blocked");
        radios["devices"][0]["soft_blocked"] = false.into();
        assert!(verify_radios(&policy, &radios).is_err());
        radios["sysfs_present"] = false.into();
        assert!(verify_radios(&policy, &radios).is_err());
    }
}
