<h1 align="center">⸭ ParticleVE</h1>

<p align="center">
  <a href="https://scorecard.dev/viewer/?uri=github.com/thefutureisprivate/ParticleVE">
    <img src="https://api.scorecard.dev/projects/github.com/thefutureisprivate/ParticleVE/badge" alt="OpenSSF Scorecard">
  </a>
  <a href="https://www.bestpractices.dev/en/projects/16493/baseline-1">
    <img src="https://www.bestpractices.dev/projects/16493/baseline" alt="OpenSSF Baseline">
  </a>
</p>

<p align="center">
  Particle Virtual Environment — a modern and hardened virtualization host based on ParticleOS.
</p>

<p align="center">
  <strong>Requires supported KVM hardware, UEFI Secure Boot, TPM 2.0, and two independently bootable disks.</strong>
</p>

## Table of Contents

- [Purpose](#purpose)
- [Architecture](#architecture)
- [Features](#features)
- [Security and Hardening](#security-and-hardening)
- [Dependencies](#dependencies)
- [Build](#build)
- [Diagnostics and Tests](#diagnostics-and-tests)
- [Contributing](#contributing)

## Purpose

ParticleVE is a headless virtualization host built around a security goal: use
applicable mitigations offered by modern Linux and supported hardware to contain
untrusted workloads and limit exploitation. A virtualization host continuously
handles guest-controlled devices, storage, and network traffic. The project
aims to make vulnerabilities harder to exploit and constrain what a compromised
component can access or affect.

That goal drives the architecture and implementation. Bounded input, explicit
ownership, and strict diagnostics reduce opportunities for unsafe privileged
operations. QEMU runs with narrow process and device authority, separated from
host administration and other guests by SELinux, systemd confinement, and its
own seccomp sandbox. Signed boot artifacts, verified OS images, encrypted
mirrored storage, and authenticated updates provide further layers of protection
around the virtualization boundary and the host's persistent state.

Following current Fedora, systemd, QEMU, and toolchain capabilities is deliberate:
older-platform compatibility must not constrain the security design. These
protections belong in a practical host with a small, headless runtime, where
administration, OS maintenance, and recovery remain explicit and understandable.
ParticleVE is independently maintained and derived from
[ParticleOS](https://github.com/systemd/particleos).

## Architecture

ParticleVE retains ParticleOS's mkosi configuration, signed UKIs, systemd-boot,
verified EROFS `/usr`, and encrypted Btrfs writable state. Each selected boot
disk has its own ESP and two complete OS slots. Independently encrypted state
partitions form native Btrfs data and metadata RAID1; a separate encrypted
md RAID1 swap device backs zswap. A firmware-backed admission record keeps a
stale mirror member out of writable storage until it is explicitly rebuilt.

The complete upstream stable systemd package family supplies systemd-vmspawn,
the packaged `systemd-vmspawn@.service` template, machined, and machinectl.
QEMU/KVM supplies the virtualization runtime. External configuration owns VM
images, unit settings, resource allocations, network attachments, and startup
policy. ParticleVE provides the host contract and coordinates OS maintenance;
it does not generate workload definitions or provide a replacement management API.

ParticleVE's installed host and initrd helpers are native Rust executables.
Python supports image construction, publication tools and tests; upstream tools
retain their own runtime dependencies. The helpers use the existing systemd
units, command paths and persistent-state contracts.

TLS clients share Fedora's system CA trust store. The host regenerates its
volatile trust outputs from the active image and authorized local anchors and
distrust entries before network clients start. See the
[trust operating policy](Documentation/Operations.md#authenticated-time-and-dns)
for system-wide trust changes and service refreshes.

OBS builds and signs releases for one authenticated feed. The host coordinator
prepares the same release on both disks and requests an automatic reboot only
after readiness checks and confirmed graceful VM exits. OS fallback selects a
retained verified image without rewinding writable host or guest data. Firmware
installation remains supervised.

See [architecture and security decisions](Documentation/Architecture.md) for
ownership, lifecycle, and security invariants, and the
[documentation index](Documentation/README.md) for all guides. The preserved
[upstream documentation](https://github.com/systemd/particleos/blob/main/README.md) records ParticleOS's original
behavior; ParticleVE's operating procedures are documented separately.

## Features

- Install a shared architecture image using explicit disk, network, trust, and
  recovery configuration, with capability checks before disk changes.
- Boot either selected disk independently, with signed bootloader trials,
  verified OS slots, boot assessment, and retained-release recovery.
- Preserve encrypted host state, administrator homes, VM disks, EFI variables,
  and virtual TPM state across OS updates and fallback.
- Detect degraded storage, quarantine stale members, and rebuild a selected
  replacement without admitting an old replica as current data.
- Run VMs through native systemd units, machined, machinectl, and QEMU/KVM.
- Configure management networking with networkd, resolved, and nftables,
  including explicit VLAN and bridge ownership.
- Use systemd-homed accounts, hardware-backed FIDO2 SSH keys, run0/polkit
  administration, and independent owner recovery.
- Prepare OS updates automatically and begin eligible maintenance at
  **04:30 Europe/Berlin**, after each host has passed commissioning. No update
  means no scheduled reboot; a missed window does not cause a catch-up reboot.
- Defer maintenance when a VM refuses graceful shutdown, restore only guests
  stopped by that attempt, and report failed restoration.
- Refresh firmware metadata automatically while keeping firmware installation,
  capsule staging, and firmware reboots manual.
- Authenticate time with chrony NTS and use explicit DNS-over-TLS, DNSSEC, and
  private-resolution policies with systemd-resolved. HTTPS, reporting, NTS and
  DNS-over-TLS use the system CA trust store.
- Report storage health, security drift, update failures, resource pressure,
  and bounded health events to an installation-selected external receiver.
- Follow Fedora's supported kernel packages, configuration, and patches, with
  dependency-triggered OBS image rebuilds and release-specific hardening checks.

## Security and Hardening

- **Separate authority:** guest processes have dedicated SELinux/MCS ownership,
  restricted capabilities and devices, and QEMU seccomp confinement. Host
  management and guest forwarding have separate, explicit network policies.
- **Bounded input:** installation records, release metadata, runtime discovery,
  and external observations are validated before privileged mutation. Uncertain
  identities or incomplete transactions block the affected operation.
- **Data preservation:** durable maintenance and mirror-admission records track
  authority and interrupted work. OS updates never reset the writable root or
  silently roll back VM files. NOCOW raw disk contents have no Btrfs data
  checksums; mirroring does not remove that limitation.
- **Verified execution:** Secure Boot, signed UKIs, dm-verity, signed modules,
  TPM-authorized unlock, and reviewed writable startup configuration constrain
  the boot and execution paths. An OS fallback does not repair malicious
  writable configuration or establish the absence of runtime compromise.
- **Platform hardening:** effective lockdown, CPU mitigations, microcode,
  IOMMU/DMA policy, selective namespace and kernel-interface restrictions,
  disabled memory merging, and restricted core dumps form a measured baseline.
  Per-VM limits, capacity planning, and pressure checks protect host and
  maintenance headroom.
- **Constrained dependencies:** source pins, package origins, recipes, patches,
  installed payloads, and final signatures are checked together. Signing keys
  stay off deployed hosts; failed or incomplete builds preserve the last usable
  release. Kernel updates retain declared hardware and recovery support.

Optional USB authorization, allocator, attestation, and LoadPin policies require
their own adoption decisions; evaluation does not imply global enablement.
See [hardening policy](Documentation/Hardening.md) for the selected controls,
exceptions, and limits, and [release diagnostics](Documentation/ReleaseDiagnostics.md)
for the evidence required for a release. Hardware support and resource minima
belong to the selected release and installation records, not a universal promise.

Loss of the disk serving the active `/usr` can require a reboot to the surviving
disk. An unclean writable session can require owner recovery to establish mirror
authority. Neither independent boot paths nor OS fallback provide continuous
availability or VM backups. Workload deployment, backups, and clustering remain
outside this project's scope.

For vulnerability reporting, see the [security policy](SECURITY.md).
For boot, storage, administration, or maintenance problems, see
[troubleshooting and recovery](Documentation/Troubleshooting.md).

## Dependencies

| Dependency | Use | Authoritative inputs |
| --- | --- | --- |
| ParticleOS | Image, boot, and storage foundation | [Source lock](sources.lock.json) and retained upstream history. |
| Fedora 45 | Base userspace and package ecosystem | [Image configuration](mkosi.conf) and [ParticleVE profile](mkosi.profiles/particleve/mkosi.conf). |
| systemd stable | Boot, updates, networking, accounts, and VM lifecycle | [Repository selection](sources.lock.json), image profile, and signed release package manifest. |
| QEMU/KVM, guest firmware, and swtpm | Virtual machines and persistent guest firmware/TPM state | Image profile and signed release package manifest. |
| Fedora kernel and modules | Fedora's supported kernel packages, configuration, and patches | [ParticleVE profile](mkosi.profiles/particleve/mkosi.conf), [toolchain baseline](Documentation/Toolchain.md), and signed release package manifest. |
| Btrfs, cryptsetup, and mdadm | Encrypted mirrored state and block swap | Image profile and [storage contracts](Documentation/Architecture.md). |
| chrony, resolved, and nftables | Authenticated time, name resolution, and networking | Image profile and [operations](Documentation/Operations.md). |
| fwupd and fwupd-efi | Supervised firmware maintenance | [Source lock](sources.lock.json), [EFI helper recipe](.obs/fwupd-efi/fwupd-efi.spec), and release manifest. |
| mkosi and OBS | Image construction, dependency rebuilds, signing, and publication | Source lock, [mkosi recipe](.obs/mkosi/mkosi.spec), and [OBS configuration](.obs/project.xml). |
| Rust toolchain and libraries | Native ParticleVE host and initrd helpers | [Toolchain pin](rust-toolchain.toml), [Cargo manifest](Cargo.toml), [dependency lock](Cargo.lock), and [RPM recipe](.obs/particleve/rpm.spec). |

Build tools stay outside the deployed runtime unless an upstream runtime
dependency requires them. The [build guide](Documentation/Build.md) describes
source and payload identity checks, signing, and publication. The
[toolchain baseline](Documentation/Toolchain.md) distinguishes source pins from
the exact package versions recorded for each release.

## Build

Use the supported Linux tools in the
[toolchain baseline](Documentation/Toolchain.md). From the repository root:

```sh
make sources
PYTHONPATH=Sources:. python3 Tools/configure-build.py --site .obs/site.json
make summary
```

These commands fetch the pinned build inputs, generate public site configuration,
and validate the resolved runtime, initrd, and tools configuration. They do not
install a host or publish an image. Review generated tracked inputs before
committing them. Private signing material and installation secrets must not enter
the checkout or public OBS sources.

See the [development guide](Documentation/Development.md) for local builds,
incremental work, OBS reproduction, and safe cache cleanup. See
[build and publication](Documentation/Build.md) for the signed image workflow and
[release preparation](Documentation/ReleaseDiagnostics.md#preparing-a-release)
for retained evidence. Each installation follows the separate
[commissioning procedure](Documentation/Commissioning.md) before enabling
unattended OS maintenance.

## Diagnostics and Tests

The [contributor verification requirements](CONTRIBUTING.md#required-verification)
define which checks each change needs. With the pinned Rust toolchain, native
development headers, Python 3.14+, Ruff, and the test dependencies installed:

```sh
make check
```

The [development guide](Documentation/Development.md#tests-and-diagnostics)
links source checks, native acceptance fixtures, build verification, and
publication checks. [Release diagnostics](Documentation/ReleaseDiagnostics.md)
covers the signed image, lifecycle and recovery matrix, hardware coverage, and
evidence retention.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for shared design policy, the task reading
map, required verification, and documentation responsibilities. The
[coding standards](Documentation/CodingStandards.md) apply to all contributors.
[AGENTS.md](AGENTS.md) adds agent-specific workflow and mandatory reading.
