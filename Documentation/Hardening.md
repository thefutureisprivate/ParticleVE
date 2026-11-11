# Security and hardening

ParticleVE is built around a security goal: use the applicable mitigations
provided by current Linux, systemd, and supported hardware to contain untrusted
workloads and limit exploitation. A hypervisor continuously handles guest I/O,
network traffic, persistent guest state, update artifacts, and privileged host
configuration. The project aims to make vulnerabilities harder to exploit and
constrain what a compromised component can access or affect.

That goal drives the architecture and implementation. Verified host code,
explicit storage authority, narrow native service permissions, and bounded
observations reduce opportunities for one component to acquire another's
privileges. Security claims depend on effective settings and focused behavioral
verification, not a list of enabled flags or a service-hardening score.

The [architecture](Architecture.md) defines ownership and non-negotiable
invariants. This guide describes the hardening baseline, selected policies,
evaluation decisions, and limitations. Historical checkboxes and implementation
notes are not current feature-status indicators.
Installation-specific evidence remains governed by
[commissioning](Commissioning.md). Completed implementation is not a claim that
an untested machine or firmware transport has passed those checks.

## Contents

- [Kernel and platform baseline](#kernel-and-platform-baseline)
- [QEMU containment](#qemu-containment)
- [Administration and privileged programs](#administration-and-privileged-programs)
- [Build and update authority](#build-and-update-authority)
- [Persistent startup inputs](#persistent-startup-inputs)
- [Service confinement](#service-confinement)
- [Authenticated time and DNS](#authenticated-time-and-dns)
- [Physical interfaces and radios](#physical-interfaces-and-radios)
- [USB authorization evaluation](#usb-authorization-evaluation)
- [Stock-kernel interface policy](#stock-kernel-interface-policy)
- [Memory privacy](#memory-privacy)
- [Resource containment and capacity](#resource-containment-and-capacity)
- [Trust rotation and old-image retirement](#trust-rotation-and-old-image-retirement)
- [Advanced userspace and kernel mitigations](#advanced-userspace-and-kernel-mitigations)
- [Verification](#verification)

## Kernel and platform baseline

ParticleVE uses Fedora's supported kernel packages with Fedora's configuration
and downstream patches. Kernel updates flow through the configured Fedora
repositories and OBS dependency rebuilds into matching kernel/modules, UKIs,
initrds, and verified userspace. Exact package identities and effective settings
are bound to the complete release. Failed checks leave the usable signed release
available and produce external attention.

The [toolchain baseline](Toolchain.md) and [build procedures](Build.md) describe
package selection and the maintenance workflow. Record the exact kernel package
versions and observed protections with each release. Further kernel hardening
is an optional final phase; a custom Fedora-derived build requires its own
justified adoption decision and is not the default update path.

Build checks assert SELinux, seccomp, required privileged BPF, module signatures,
lockdown, IOMMU support, strict kernel/module memory permissions, Landlock,
memfd support, and the required resource controllers. Runtime assessment checks
the actual kernel, effective lockdown, signature policy, mitigation reporting,
and nested-virtualization setting. Existing upstream defaults remain
assertions where appropriate; they are not credited as new downstream controls.

Built-in, secondary, machine, and firmware platform keyrings have different
roles. Presence in the platform keyring does not establish that a certificate
can authorize a kernel module. See the upstream
[module-signing documentation](https://docs.kernel.org/admin-guide/module-signing.html).
CPU vulnerability strings, microcode, IOMMU groups, and individual fwupd security
attributes are recorded separately; group presence or an aggregate score is not
proof of DMA isolation or firmware qualification.

Production guest nesting is disabled for Intel and AMD. The disposable outer
hypervisor may expose virtualization so ParticleVE itself can exercise KVM;
that fixture exception is outside the production policy. Supported drivers,
firmware, and architecture coverage remain generic rather than being pruned to
one build worker or host.

## QEMU containment

Trusted native vmspawn setup retains only the capabilities required for labels,
namespace mappings, resource limits, and privilege drops. The QEMU child clears
every capability set, the bounding set, and supplementary groups, and sets
no-new-privileges. A specific SELinux transition preserves the VM's domain and
MCS pair. QEMU's seccomp sandbox denies obsolete operations, privilege elevation,
process spawning, and resource-control calls. Runtime inventory verifies both
the selected option and the effective privilege/filter state.

QEMU's UID remains subject to the root-owned VM-storage contract. Dropping Linux
capabilities does not make UID 0 an unprivileged user. Native vmspawn's
[`--private-users`](https://www.freedesktop.org/software/systemd/man/262/systemd-vmspawn.html#--private-users=)
maps virtiofs identities; it is not a QEMU UID-selection option. A different UID
model requires an explicitly reviewed storage and retained-identity decision.

SELinux separates the trusted vmspawn controller, `svirt_t` QEMU, and `swtpm_t`.
Each VM has a unique permanent MCS pair. The handoff labels newly allocated
console descriptors and private temporary state; it does not relabel retained
VM storage. Real-resource checks cover each VM's own data and console, peer
storage, root-private paths, and privileged management sockets. A successful
self-access control is needed alongside the rejected foreign-access probe.

QEMU's [sandbox semantics](https://www.qemu.org/docs/master/system/invocation.html)
and [security boundary](https://www.qemu.org/docs/master/system/security.html)
remain part of dependency review. An OS update may not widen the externally
supplied VM unit contract or replace graceful maintenance with process killing.

## Administration and privileged programs

Human administration uses homed, userdb, PAM, OpenSSH, and native run0/polkit.
Inactive non-root homes require the public-key-plus-password path; root keeps
independent public-key recovery. FIDO2 signatures require both user presence
and verification. Spare authenticators and lost-token recovery belong to the
installation's acceptance record, not automatic enrollment during an update.

SSH forwarding, tunnelling, agent forwarding, and X11 are disabled. The signed
UKI selects `systemd.ssh_auto=no`; explicitly requested listeners need their own
review. Management packet filtering and local Unix/vsock/D-Bus authorization
are checked independently. An authorized shell can still use a network client.

The final image has a reviewed SUID/SGID, file-capability, ownership, service,
and socket inventory. Each retained privilege has a purpose in
[`.obs/particleve/security-policy.json`](../.obs/particleve/security-policy.json). The PAM
account helper and polkit authentication helper retain their required privilege;
unneeded privileges are removed individually. Unexpected expansion fails before
revocation, while vendor removal of an unused privilege is accepted.

Final verification inspects actual EROFS file metadata. The extractor preserves
xattrs without changing ownership, reads original UID/GID with `dump.erofs`,
and checks a non-executable capability canary and a user-attribute canary.
Extraction diagnostics fail the check; disabling xattr extraction is not a
fallback. This verifies the selected artifact within the trusted build boundary,
not independently against a compromised builder.

Human credentials are separate from unattended automation. OBS source refresh
uses package-scoped credentials; health delivery uses an installation-scoped
submission token. Neither requires a human SSH key or general run0 authority.
Repository and OBS administration use strong authentication and reviewed minimal
access, including protection of source-update, signing, and publication policy.

## Build and update authority

Source, recipe, configuration, patch, installed payload, and final-artifact
identities are verified at their relevant boundaries. Private signing material
stays outside source control and deployed hosts. Public verification roots are
bound into the image. Package provenance and a signed manifest describe the
claims made by the producer; they are not independent proof that the producer
was uncompromised.

OBS rebuilds on relevant package/source changes. Complete releases are published
through one signed feed; failed or incomplete builds do not replace the last
usable release. External observation authenticates publication metadata, checks
source lag and required builds, and detects continuously pending or stale work
across fresh observer processes. Build-network restrictions are recorded according
to what the selected platform actually enforces. See [Build.md](Build.md) for
the producer trust boundary and observer scheduling/freshness contract.

Host maintenance verifies the same complete release on both disks, a usable
fallback, the stored-state contract, actual health, and confirmed graceful VM
exits. Firmware staging and persistent owner maintenance exclude OS activation.
External receiving-side freshness detection makes a silent local reporter
visible without allowing reporting failures to stop guests or request reboots.

## Persistent startup inputs

Host executables, libraries, upstream interpreter modules, and security policy
normally come from verified `/usr`. The visible mount must itself be read-only
verified EROFS.
Sysext, confext, and portable host-service activation are masked. Writable service
executables, generators, PAM/udev/polkit code, and loader paths may not substitute
for the verified source of code.

The bounded descriptor-relative inventory accepts approved installation settings
and narrow native VM/console drop-ins, rejecting unsafe ownership, writes,
ACLs, hard links, special files, and links to writable code. Commissioning binds
content and metadata; the signed initrd checks the read-only configuration before
installed PID 1 starts. Account and credential contents retain their own policy
and are not exported into the inventory.

Deliberate startup-policy changes require invalidating the old approval and
collecting new evidence. Retained images must enforce the accepted contract.
Verified boot alone does not clean malicious writable configuration, and
`noexec` or `MemoryDenyWriteExecute=yes` alone does not establish code origin.
See [persistent startup operations](Operations.md#persistent-startup-configuration).

## Service confinement

Service policy follows demonstrated needs for devices, filesystem writes,
process visibility, kernel interfaces, address families, and egress. Native
host syscall ABI restrictions do not restrict the guest kernel's supported ABI.
Trusted namespace brokers and privileged systemd BPF remain available where
required. General login/service domains cannot create user namespaces, PF_KEY,
or XFRM interfaces; AF_ALG remains available only in demonstrated administrative
and native-service cryptsetup contexts. QEMU and swtpm retain their own domains.

Effective SELinux checks include domain-permissive flags and detect policy
reloads during observation. An image policy hash cannot substitute for effective
permission decisions. Local storage requires `virt_use_nfs`, `virt_use_samba`,
and `virt_use_execmem` disabled. Drift is reported and blocks applicable health
checks; it is not silently repaired.

Read-only inspection and network delivery use different privilege phases.
After collecting a bounded report, native setpriv replaces the root inspector
with PID 1's private dynamic user. The sender verifies empty capability sets,
private real/effective/saved identities, no supplementary groups,
no-new-privileges, seccomp, and sealed input before processing credentials/TLS.
PID 1 grants credential access only to that dynamic identity and root. The sender
checks the exact current-manager ACL or ownership representation, the read-only
mount and the opened file identity; extra principals, write access and links are
rejected. See the [credential handoff](Operations.md#external-health-reporting)
for the access contract.
There is no privileged parent parsing receiver responses.

The report sandbox keeps kernel-tunable protection and its `/proc/kcore` mask.
PID 1 supplies a separate read-only bind of the original interface for metadata
inspection, removed with the service runtime directory. Its availability must
match the verified kernel configuration; a missing bind cannot hide an enabled
interface. The inspector requires `0400 root:root` and never opens kernel memory.
Neither inspection nor delivery receives `CAP_SYS_RAWIO`.

The sender closes inherited descriptors and requires Landlock ABI 5 or later.
Its profile denies filesystem data writes, creation/removal, link/rename,
truncation, and device ioctls; it does not claim to mediate every metadata-only
operation. No reduced profile is substituted. The SELinux access-query file is
writable only for the privileged inspection transaction, while policy, booleans,
and enforcing controls remain read-only. See
[external reporting](Operations.md#external-health-reporting).

## Authenticated time and DNS

Chrony's restricted NTS client is the sole clock owner. Its daemon uses the
chrony UID and only `CAP_SYS_TIME`, with no UDP command listener. Local queries
run as chrony with empty capabilities, including the narrow SELinux
no-new-privileges transition needed for the native client. Drift and NTS state
remain on encrypted storage. The unconfigured factory image supplies no time
sources; installation selects reviewed independent operators.

HTTPS downloads, health reporting, NTS and DNS-over-TLS use the system CA trust
store. Owner-required anchors are installed through Fedora's trust configuration.
ParticleVE's Rust and Python HTTPS clients load the distribution roots directly;
per-tool CA bundles and `SSL_CERT_FILE`/`SSL_CERT_DIR` are not their trust
configuration paths. Certificate-name and validity checks remain mandatory.
Transport roots do not replace release-signing, Secure Boot or PCR authorization keys.
The chrony service disables per-user PKCS#11 configuration, preserving the system
trust policy even when its writable state contains a user module configuration.

Generated CA bundles and OpenSSL's hashed directory live under `/run` and are
rebuilt from the active image and reviewed local inputs before TLS services start.
The extraction service has no capabilities, no IP sockets and write access only
to its volatile output directory. Refresh restarts long-running TLS clients;
chrony retains its drift state but discards cached client sessions after a trust
change. Both native source policies and generated output bind those sessions,
including distrust changes that leave a generated bundle unchanged. Local inputs,
rather than generated output bytes, bind commissioning.
See the [shared trust refresh procedure](Operations.md#authenticated-time-and-dns).

Automatic activation requires two authenticated agreeing operators, fresh
samples and authentication evidence, and the configured error/step bounds.
Loss of trust defers work before guest shutdown, or restores guests if it occurs
later. An owner-verified clock recovery path handles a bad RTC without disabling
certificate-time validation or adopting unauthenticated NTP. Authenticated time
does not eliminate packet-delay or denial-of-service attacks.

Resolved requires strict DNS-over-TLS with explicit certificate identities and
DNSSEC policy. Private domains and negative anchors are scoped to their selected
links; local discovery is disabled. Transport authentication and DNSSEC are
verified separately. Resolver/time bootstrap, wrong identities, expired
certificates, source disagreement, private-route leakage, and plaintext/public
fallback belong to native acceptance. See
[authenticated time and DNS](Operations.md#authenticated-time-and-dns).

## Physical interfaces and radios

Read-only discovery reports USB classes and authorization, RFKill blocks,
Thunderbolt security/DMA attributes, PCI/IOMMU membership, and network ancestry.
Missing buses, empty buses, and failed observations are distinct. The report
omits descriptor blobs, serial/MAC/Thunderbolt UUID attributes, and PCI
configuration/resource contents. Kernel node names and topology can still
identify a machine, so this detailed inventory stays owner-local.

Installation policy names required recovery input, selected storage, management
adapters, authenticators, operational devices, and firmware mode transitions.
Device-provided identifiers do not authenticate hardware. Observing everything
currently attached is not a basis for automatically trusting it.

RFKill starts blocked, with an explicit allowed-type list. A zero-capability
dynamic-user service receives only its root-opened RFKill descriptor and reviewed
read-only policy, reconciles ADD/CHANGE events, repairs missed notifications,
and establishes readiness before networkd. Denied radios need a software block
even when hardware-blocked. Later stricter manual blocks on allowed types are
preserved.

RFKill controls cooperating drivers. Persistent hardware may transmit before
userspace observes registration; devices without RFKill need reviewed firmware
disablement or removal when unused. Thunderbolt authorization, firmware security
level, and IOMMU DMA protection are separate facts. Commission the actual
switches, reconnects, recovery paths, and required peripherals; virtual-driver
checks do not prove physical transmitter or DMA behavior.

## USB authorization evaluation

USBGuard remains optional and deferred in the generic image. The evaluation
established useful authorization behavior and integration hazards; it did not
select a package, daemon, D-Bus activation, or automatic peripheral enrollment
for every host. An installation that adopts it needs reviewed image/service and
SELinux policy, explicit device rules, and independent recovery/firmware tests.
Userspace USB authorization is neither preboot authentication nor a guarantee
against a malicious device that imitates an allowed identity.

The recorded evaluation used upstream USBGuard 1.1.4 at
`f22233175f7a4539bc96ede8e3d67f7017b6675b`, Fedora `1.1.4-7.fc45`, and signed
virtual USB controllers/gadgets on image 63.1. It covered real grabbed keyboard
events, strict composite-interface matching, unknown firmware identities,
root-only IPC, temporary grants, baseline reload, and cleanup. No physical USB
passthrough or firmware write occurred. The staged daemon ran in `init_t`, so
those observations do not qualify a production SELinux transition.

Three observed hazards determine the supported procedure:

- Removing a temporary rule changed memory before returning an error on a
  read-only policy file.
- With a writable baseline, removing one rule persisted another temporary grant.
- Removing a rule did not deauthorize its already connected device.

The pinned [rule implementation](https://github.com/USBGuard/usbguard/blob/f22233175f7a4539bc96ede8e3d67f7017b6675b/src/Daemon/Daemon.cpp#L751-L776)
explains those results. Restarting from the original read-only baseline revoked
all temporary grants and the outstanding flashing identity while recovery
keyboard input remained usable. That restart is permitted only after firmware
writing/recovery no longer needs the temporary identity. A returning command
does not prove the updater daemon is idle.

Keep baseline rules read-only, IPC root-only, `AuthorizedDefault=none`, and
`RestoreControllerDeviceState=false`. Review present-device/controller policy,
boot storage, recovery input, and complete composite interfaces. Firmware
exceptions must be temporary and scoped to trusted normal/flashing identities,
ports/topology, and interfaces. Verify cleanup, required-device I/O, rejection,
and failure/power-cycle recovery. See the
[fwupd transition discussion](https://github.com/USBGuard/usbguard/discussions/620)
and [operational procedure](Operations.md#usb-authorization).

The [evaluator](../Tests/acceptance/usbguard-policy.py),
[virtual fixture](../Tests/acceptance/usb_gadget_fixture.py), and
[bundle exporter](../Tests/acceptance/export-usbguard-bundle.py) require an
explicit disposable installation and reviewed package receipt. The exporter
runs in a disposable Fedora environment with DNF signature checking and writes
a new `--output` directory. Stage it privately under `/run`; the evaluator needs
`--expect-installation`, `--runtime-dir`, and reviewed `--preserve-unit` checks.
Never replace those inputs with a production device inventory. Historical logs
are identified under [verification](#verification).

## Stock-kernel interface policy

The runtime policy builds on Fedora's stock kernel. The initrd and installed
OS reuse the authored sysctl/udev assets; build checks bind their bytes and
runtime assessment checks effective settings. Missing or unsupported required
settings fail assessment rather than silently selecting weaker values.

The following table preserves the measured image-63.1 comparison against
`7.2.15-300.fc45.x86_64`. The selected policy column describes the contract;
its historical observations are not measurements of later Fedora kernel builds.
Release and installation checks must establish the same behavior for the
selected kernel.

| Interface | Observed 63.1 baseline → selected policy | Purpose, owner and compatibility evidence |
| --- | --- | --- |
| `kernel.unprivileged_bpf_disabled` | `2` → assert `2` | Fedora default; preserve privileged systemd BPF. An inert privileged socket-filter program loaded and closed without any attachment; VM device-policy setup and launch passed. |
| `kernel.perf_event_paranoid` | `2` → assert `2` | Fedora default excludes unprivileged kernel/system-wide profiling. Own-process software perf events remained available at both `2` and `3`; no claim that `3` globally disables perf. |
| `vm.unprivileged_userfaultfd` | `0` → assert `0` | Fedora default restricts kernel-fault handling. Zero-capability probes denied ordinary userfaultfd but allowed `UFFD_USER_MODE_ONLY`; this is deliberately not a ban on that API. |
| `kernel.yama.ptrace_scope` | `1` → `2` | ParticleVE sysctl policy requires `CAP_SYS_PTRACE` for attach/traceme. A disposable zero-capability parent/child was denied; privileged tracing, homed SSH/run0, namespace setup and VM restarts passed. |
| `kernel.kptr_restrict` | `0` → `2` | ParticleVE policy suppresses `%pK` kernel-pointer printing even for root. This does not assert that every kernel address format or diagnostic source is concealed. |
| `kernel.dmesg_restrict` | `1` → assert `1` | Fedora default retains privileged kernel-log access; ordinary users do not gain a diagnostic bypass. |
| `kernel.kexec_load_disabled` | `0` → `1` | ParticleVE policy disables kernel loading for the rest of each boot. UEFI owns normal updates and recovery. Bad-fd `kexec_file_load` changed from `EBADF` to `EPERM` after the native policy application. |
| `dev.tty.ldisc_autoload` | `1` → `0` | ParticleVE policy denies unprivileged module autoload requests. A private PTY selected unloaded signed `n_hdlc` before enforcement and was denied afterward; explicit privileged loading still allowed selection. Already registered/built-in disciplines are unaffected. |
| `vm.memfd_noexec` | `0` → `1` | ParticleVE policy changes an unspecified memfd to non-executable with `F_SEAL_EXEC`; adding execute bits failed. Explicit `MFD_EXEC` remained executable. Value `2` is not selected. Homed, run0 and VM launch passed. |
| `vm.mmap_rnd_bits`, `vm.mmap_rnd_compat_bits` | `28`, `8` → `32`, `16` | ParticleVE policy uses the observed kernel maxima. New privileged services, homed sessions and VM controllers launched successfully. |
| `vm.mmap_min_addr`, `kernel.randomize_va_space` | `65536`, `2` → assert unchanged | Fedora defaults retain low-address mapping protection and full supported ASLR. Entropy settings do not by themselves prove resistance to a particular exploit. |
| `fs.protected_fifos`, `fs.protected_regular` | `1`, `1` → `2`, `2` | ParticleVE policy extends confused-creation protection to group-writable sticky directories. Native `O_CREAT` attempts on another owner's regular file/FIFO failed; explicit existing-file opens and creation of an owned file worked. |
| `fs.protected_hardlinks`, `fs.protected_symlinks` | `1`, `1` → assert unchanged | Fedora shared-directory defaults, checked for effective drift. |
| Raw memory devices | `/dev/mem` `0640 root:kmem` → `0600 root:root`; `/dev/userfaultfd` already `0600 root:root` | ParticleVE udev rules remove group/seat grants before seat activation. Native generated add events set both nodes correctly. Absent interfaces are allowed; a device symlink or non-character substitute is rejected. Present `/proc/kcore` must remain root-owned read-only `0400`; no contents are opened. |


`kernel.io_uring_disabled=0` retains the native I/O path. No blanket BPF,
user-namespace, or io_uring ban is inferred from the table. The
[memfd interface](https://docs.kernel.org/userspace-api/mfd_noexec.html) distinguishes
non-executable defaults from denying explicit executable requests. Larger numeric
settings are not accepted as unreviewed compatibility changes.

`kernel.kexec_load_disabled=1` is irreversible for the current boot. Updates and
recovery use UEFI; neither kexec reboot nor kdump is an ordinary substitute.
ParticleVE service-prefix and VM-template restrictions select the native host ABI.
Native component tests rejected an inert ELF32 host executable under that filter
while both nested guests could still execute ELF32. These are different ABI
boundaries.

The [interface probe](../Tests/acceptance/kernel-interfaces.py) requires an
explicit disposable installation UUID and QEMU hardware. It restores reversible
settings, uses private PTYs, and unloads only its initially absent signed test
module. The positive autoload control briefly changes policy in that disposable
host; the one-way kexec test runs last, followed by an ordinary UEFI reboot.
Do not run this probe against a live production host as a read-only health check.

## Memory privacy

The guarded QEMU handoff enforces `mem-merge=off,dump-guest-core=off`. KSM stays
stopped with zero ordinary shared and zero-page counters; process mapping and
per-process KSM observations reject mergeable backends even when machine-level
properties appear correct. The host never automatically unmerges live memory,
which can exhaust RAM. No guest memory contents or mapping addresses enter
routine reports.

System/user managers default to zero core limits. VM units and the reporter
require zero hard/soft limits and an empty core mapping filter; the handoff also
lowers QEMU's hard limit. `fs.suid_dumpable=0` covers privilege-changing processes.
The selected native coredump handler retains metadata only with `Storage=none`,
`ProcessSizeMax=0`, and `EnterNamespace=no`. Both handler settings matter because
piped core handling does not obey ordinary file-core size limits.

Sensitive capture requires owner-reviewed maintenance, an identified process,
purpose, size bound, access policy, cleanup, and a signed diagnostic release
when additional tools are needed. Use bounded root-only volatile storage; do not
execute downloaded debug code from writable state or enable general crash
collection. Cleanup does not claim forensic erasure. See
[memory diagnostics](Operations.md#memory-privacy-and-diagnostics).

## Resource containment and capacity

Host policy declares normal and maintenance physical RAM headroom, with
maintenance at least normal, plus CPU/memory/I/O `avg60` pressure thresholds.
The example 512/1024 MiB reserves and 50/10/20 percent thresholds are starting
points, not measured production minima. `MemAvailable` is the capacity measure;
zswap and encrypted swap do not count as additional physical RAM.

The `bounded-native-vmspawn-v2` interface requires finite positive memory-high,
memory-max, and task limits, with high below max. CPU, memory, task, I/O, and
pressure observations cover the whole cgroup and auxiliaries. External
provisioning owns allocation, quotas, originating-device I/O limits, and restart
policy. Mapper and physical-layer I/O records are kept separate to avoid double
counting. A successful maxima check is necessary but does not reserve space for
all host and maintenance overhead.

Group OOM is fatal to the complete unit. The native `kill` policy,
`memory.oom.group=1`, and ordinary `OOMScoreAdjust=0` prevent an OOM-exempt
launcher from leaving a partial stack. A kernel kill can lose uncommitted guest
or TPM writes; it is never a substitute for ACPI/graceful maintenance. Pressure,
OOM, failed units, insufficient reserves, and policy drift retain their
measurements, require attention, and defer automatic work without stopping
otherwise running peers.

Historical component measurements used image 63.1, kernel 7.2.15, a 6-GiB QEMU
host, and two 1-GiB/two-vCPU guests with retained disk/EFI/TPM state. Kernel
`MemTotal` was about 5825 MiB; initial per-VM limits were 1536 MiB high, 2048 MiB
max, and 256 tasks. The table records that fixture, not production defaults.

| Experiment | Observed result |
| --- | --- |
| Actual guest CPU load at 25% of one host CPU | Twelve-second bounded guest job; 135 additional throttled periods, with peer operation and host administration retained. |
| Real guest direct I/O through the mirrored encrypted Btrfs backing | Deterministic incompressible 64-MiB payload; baseline write/read about 0.18/0.07 seconds, then about 8.14/6.42 seconds with 8-MiB/s limits on both originating disks. Kernel limits and device counters were captured; cache/burst behavior prevents treating these times as a precise sustained-rate guarantee. |
| Native host task controller | A bounded inert unit reached 16 tasks, then `fork` returned `EAGAIN` and `pids.events:max` increased. Guest process counts are not host task counts. |
| Too-small 768-MiB memory-high boundary | A 512-MiB guest working-set probe could not finish touching its pages before its 90-second deadman. VM memory PSI `avg60` reached about 69.7%; no kernel OOM occurred. Host `MemAvailable` stayed above about 3580 MiB and root SSH queries continued succeeding. The limit is unsuitable for that profile. |
| Larger 1280-MiB experimental memory-high | The same guest working set completed, including its 15-second hold. Minimum sampled host available RAM was about 3280 MiB, VM peak about 1104 MiB, with up to 53 sampled host tasks. These are observations, not allocation defaults. |
| Live pressure policy | A separate inert 192-MiB-max transient probe produced fresh kernel stalls; a deliberately low 1% fixture `avg60` threshold raised host memory-pressure attention with measurements retained. Host available RAM remained over 3.5 GiB. |
| Deliberate 384-MiB hard VM limit | Kernel OOM was fatal and reported, never considered a graceful shutdown. The original `stop` policy briefly left a partial stack; all old processes subsequently exited. The selected native `kill` policy set `memory.oom.group=1`, killed the complete four-process VM group and left no surviving old PID before recovery. The peer controller stayed running. Ordinary ACPI stop/start also passed under that policy. |


The I/O probe used deterministic incompressible data after a repetitive pattern
proved unsuitable for bandwidth measurement. The measurements include QEMU,
supervisor, vmspawn, and swtpm; they do not cover every workload, virtiofsd,
maintenance peak, or physical device. RSS, guest allocation, and cgroup charge
are different quantities. Both fatal-limit tests used disposable state and
independently checked disk, EFI, TPM, and retained markers after recovery.

Bounded reports include attention results and explicit detail-limit flags.
Resource summaries retain eight VMs, eight OOM records, and eight alert strings;
SELinux has its separate 32-event cap, and reports remain within 64 KiB. Cursor-
derived OOM identities avoid exporting raw kernel messages or process arguments.
Local status retains its larger bounded inventory. Reports do not allocate
resources, repair an undersized limit, or enforce an external workload budget.

The installation's `resource_limits` evidence records complete VM/auxiliary
budgets, normal and maintenance peaks, CPU/task/I/O behavior, pressure, fatal-limit
recovery, administration responsiveness, and storage exhaustion. The generic
example remains `not-run` until populated with that installation's evidence;
an earlier approval cannot silently satisfy a changed acceptance contract.
See [resource commissioning](Commissioning.md#vm-state-and-resource-limits).

## Trust rotation and old-image retirement

Trust roles are explicit: release verification, Secure Boot authorization,
kernel-module authorization, and PCR authorization are separate decisions.
Introduction and retirement use a narrow owner-reviewed transition, including
both independent boot paths, TPM unlock, and recovery. Verify the effective
anchors and which artifacts each can authorize after every step.

Separate trust decisions can share an authority. A kernel that accepts
firmware-derived module keys also changes module admission when its firmware
trust changes. Include that effect in the reviewed transition and test valid
module signatures from the affected signers; keyring names or unchanged kernel
packages alone do not establish the accepted set.

Retiring a vulnerable signed image must preserve a usable reviewed recovery
path. OS-slot cleanup alone does not revoke a key, and selecting an older image
does not reverse firmware `db`/`dbx` changes. Security-sensitive trust changes
are supervised maintenance, never implicit configuration cleanup. Record the
selected release/firmware mechanisms and accepted/rejected artifact evidence;
do not invent a generic command that rotates every trust store together.
Use the [supervised transition sequence](Operations.md#trust-rotation-and-image-retirement)
and [trust-transition acceptance matrix](ReleaseDiagnostics.md#trust-transition-acceptance)
to bind introduction, overlap, retirement and recovery to the actual verifiers.

Generic deployments use authenticated external health reporting. Independent
boot attestation is an installation-specific extension, separate from that reporting.
Its deployment contract requires fresh challenges, expected measurements and
image identities, verification outside the host trust domain, and rejection
of replayed, stale, or missing evidence. State which writable configuration is
covered. Expected boot measurements do not prove absence of runtime compromise;
[GrapheneOS Auditor](https://attestation.app/about) is an architectural reference,
not an installed ParticleVE component.

## Advanced userspace and kernel mitigations

Advanced mitigations have explicit adoption or deferral decisions and release-
specific evidence. An evaluation does not silently become a global runtime
policy. Optional selections are not implied by the project's completed baseline.

For [hardened_malloc](https://github.com/GrapheneOS/hardened_malloc), evaluation
starts per process with a pinned OBS package delivered through verified `/usr`.
An adopted selection records allocator variant, integration method, actual
loading, exceptions, and tests of QEMU, swtpm, fwupd, authentication, storage,
and maintenance. Measurements cover resident memory, map counts, startup,
representative disk/network behavior, and pressure. `vm.max_map_count` changes
need measured justification. A completed evaluation can conclude with deferral;
no host-wide preload or allocator variant is assumed here.

The generic allocator selection is glibc, with no global preload. The disposable
signed-image evaluation on 2026-11-11 (`45.0.2.3-0.1`, Fedora kernel
`7.3.3-300.fc45`) loaded both hardened_malloc variants in vmspawn and its
supervisor, while QEMU and swtpm retained their original allocators. QEMU's
`AT_SECURE=1` execution remained intact. The scoped fwupd evaluation also
observed higher mapping counts and resident memory. These results support
deferral of allocator adoption; they do not establish representative guest
performance. Adoption requires integration that reaches the intended workers
with their existing confinement and passes the compatibility and measurement
requirements above.

Additional kernel hardening is optional and stays last in the priority order.
Audit Fedora's effective configuration and protections before proposing changes
to memory initialization, CFI, stack/slab/usercopy defenses, or compatibility
interfaces. Prefer supported Fedora settings and upstream improvements. Any
custom Fedora-derived build needs a specific security or compatibility benefit,
an explicit adoption decision, and a maintenance path that preserves timely
Fedora updates. The generic image uses Fedora's supported kernel packages.

Evaluate proposed changes against generic driver, storage, TPM, firmware,
systemd, and QEMU requirements. Measure VM/storage latency, CPU cost, and memory
pressure, and bind any adopted configuration, patch, and toolchain changes to
release provenance.

LoadPin requires a separate decision covering initrd-to-root transition, early
firmware/module loading, verified filesystems, and owner recovery. Broad
exclusions introduced merely to obtain a boot are not an accepted outcome.
[Kernel self-protection guidance](https://docs.kernel.org/security/self-protection.html)
is an audit reference, not an unreviewed configuration to copy.

The same rule applies to other projects' policies. GrapheneOS, secureblue, and
Metropolis Nexus inform specific design decisions; their entire platform
assumptions are not imported. Blanket namespace/BPF/io_uring bans, automatic
panic/inactivity reboots, forced SMT disablement, indiscriminate privilege
removal, and downloaded moving hardening scripts are not baseline policy.

## Verification

Use the [required contributor checks](../CONTRIBUTING.md#required-verification),
[release diagnostics](ReleaseDiagnostics.md), and
[commissioning](Commissioning.md) for the change and installation being assessed.
Record image/source identity, effective settings, positive and negative probes,
fixture/hardware coverage, measured cost, cleanup, and narrow exceptions.
Historical results do not establish that a later signed image passes.

The following historical component observations retain their original image,
fixture and coverage limits. Use the procedures above to verify each release
and installation.

| Evidence | Recorded scope and limitation |
| --- | --- |
| `build/acceptance/signed-review-20261108/` | Signed-image 58.1–63.1 and staged native component observations. Component changes loaded temporarily into an older image are distinct from acceptance of a new combined image. |
| Broken/hung loader and independent-disk cases | Retained fixed loader paths and BootOrder were preserved; disk/EFI/TPM markers were checked. Hung EFI execution required an owner reset. |
| `native-reporting-dynamic-https-result.json` | Dynamic identity/capability handoff, bounded credentialed TLS, failure and recovery; no persistent external receiver was provisioned by the fixture. |
| `native-chrony-nnp-policy.log` under `build/acceptance/combined-20261109/` | Image 71.1 with a temporary narrow SELinux transition correction; actual chrony queries retained no-new-privileges and empty capabilities. Original policy was restored. |
| `Tests/acceptance/fido2-policy.py` | Native OpenSSH signature-flag tests with the official software regression provider; not proof of hardware provenance, PIN/biometric behavior, or spare-token recovery. |
| `Tests/acceptance/radio-policy.py` | Signed virtual Wi-Fi driver tests of event/restart/block/confinement behavior; no transmitter, physical switch, or non-WLAN qualification. Reruns follow the [compiled-helper prerequisites](Development.md#native-probes-with-compiled-helpers). |
| `native-63.1-usbguard-policy-evaluation.log` and `usbguard-evaluation/` | Reviewed virtual gadget behavior, temporary-rule hazards, baseline reload, and cleanup; no physical firmware update or production USBGuard SELinux qualification. |
| `native-63.1-stock-kernel-interface-probes.log`, `native-63.1-kernel-runtime-component.log`, `native-63.1-host-abi-denial-and-bpf.log` | Positive/negative kernel-interface and host/guest ABI checks on the named stock kernel, with reversible state restored. |
| `native-resource-receipt.json` and resource evaluation logs | The explicitly described 6-GiB disposable resource profile, not generic host minima or production workload sizing. |

Full component chronology and signed-image boundaries are retained in
Git history. Local evidence paths are not a
promise that private or temporary logs are shipped in the repository. Physical
firmware availability, DMA isolation, recovery peripherals, and capacity are
recorded for each selected installation. An unavailable observation remains a
coverage gap rather than a passing result.
