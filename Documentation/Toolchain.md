# Toolchain baseline

ParticleVE targets Fedora 45 with a Fedora-derived kernel built from pinned
Fedora packaging and the reviewed secureblue baseline, alongside the upstream
stable systemd package family from OBS. The runtime, initrd, and build
tools use that same distribution and systemd source policy. The current image
target is x86-64; the recorded CPU baseline is
x86-64-v2. Hardware virtualization, firmware, TPM, drivers, and recovery support
are checked separately during [commissioning](Commissioning.md).

Use Python 3.14 or newer for first-party tools and tests. The Python requirement
and Ruff settings live in [`pyproject.toml`](../pyproject.toml); the supported
source-check entry points live in the [`Makefile`](../Makefile).

Installed host and initrd code uses Rust 1.99.1, edition 2024, pinned in
[`rust-toolchain.toml`](../rust-toolchain.toml). [`Cargo.toml`](../Cargo.toml)
and [`Cargo.lock`](../Cargo.lock) own the exact dependency set. Rust builds keep
overflow checks in release mode, thin LTO, frame pointers, x86-64-v2 targeting,
RELRO and immediate symbol binding. No build-host CPU tuning is permitted.
`particleve.version` owns the full Fedora/PVE source version; Cargo uses its
three PVE components. `Tools/version.py` keeps both manifests, the Cargo lock
and RPM declarations consistent. Native Fedora RPM builds retain the distro
compiler flags, removing only its warning-cap flag before enforcing project
diagnostics as errors.

The locked vendor archive supplies `.cargo/config`. The RPM preparation step moves
that generated configuration to `.cargo/config.toml` before invoking the pinned
Cargo, retaining its contents and lock verification without deprecated-name
diagnostics. Local OBS reproduction emits the same vendor archive layout.

## Current build configuration

The [coding standards](CodingStandards.md#baseline-and-module-boundaries)
define language and boundary requirements. The following files are authoritative
for the build inputs; update their related checks and recipes together.

| Component | Baseline and authoritative input |
| --- | --- |
| Fedora runtime, initrd, and tools | Fedora 45; [`sources.lock.json`](../sources.lock.json), the [ParticleVE profile](../mkosi.profiles/particleve/mkosi.conf), and [initrd configuration](../mkosi.initrd.conf/mkosi.conf). |
| Kernel and modules | OBS-built `kernel-core`, `kernel-modules-core`, `kernel-modules`, and `kernel-modules-extra`; [`sources.lock.json`](../sources.lock.json), the [recipe](../.obs/kernel/kernel.spec), [source manifest](../.obs/kernel/kernel.inputs.json), and [policy deviations](../.obs/kernel/policy.json) bind the Fedora and secureblue inputs. |
| systemd | The complete `system:systemd:stable` family from the configured Fedora 45 OBS repository; exact installed versions and origins are recorded and checked per build. |
| ParticleOS | This fork retains the upstream revision recorded in `sources.lock.json`; no second upstream tree is composed over it. |
| mkosi | Exact upstream commit and declared version in `sources.lock.json`, with the reviewed [OBS continuation patch](../.obs/mkosi/mkosi-obs-continuation.patch), [initrd module-index patch](../.obs/mkosi/mkosi-initrd-module-indexes.patch), [build-metadata patch](../.obs/mkosi/mkosi-build-metadata.patch), and [RPM recipe](../.obs/mkosi/mkosi.spec). The configuration's minimum version is not a substitute for this pin. |
| fwupd EFI helper | Exact upstream commit and version in `sources.lock.json`; [recipe](../.obs/fwupd-efi/fwupd-efi.spec), [diagnostic patch](../.obs/fwupd-efi/fwupd-efi-sbom-linker-message.patch), separate PE signing, and SBAT/SBOM checks. |
| Rust | 1.99.1 with rustfmt and Clippy; runtime and initrd native binaries. |
| Source-check environment | The digest-pinned Fedora 45 container in the [source workflow](../.github/workflows/check.yml), with Rust packages selected from `rust-toolchain.toml` and native Fedora Python. Update its Fedora tag and Renovate constraint with the platform baseline. |
| Shared runtime/build policy | [`Sources/particleve/runtime-policy.json`](../Sources/particleve/runtime-policy.json); required kernel configuration, sysctls, TPM creation policy and SELinux boolean expectations. Rust embeds the same data read by Python build checks. |
| Python | `>=3.14` for build tools and tests; upstream Python tools retain their upstream dependency requirements. |
| Ruff | The repository's configured rules and formatter; exact CI version and wheel hashes in [CI requirements](../.github/requirements.txt). Record the version used for a verification run. |
| Image packages and privileged files | The ParticleVE profile, generated dependency summary, [privilege policy](../.obs/particleve/security-policy.json), and final-image checks. |
| OBS project, source branch, repositories, and feed | [`.obs/site.json`](../.obs/site.json); public generated inputs are reviewed source. |

Fedora and stable systemd packages intentionally advance through the OBS
dependency graph. Pinning the source tools does not freeze those repositories.
Each release records exact package versions, origins, source identities, and
artifact hashes so its inputs remain identifiable.

## Runtime and system interface contracts

`make check` runs Rust formatting, Clippy, runtime tests, the compiled contract
driver, Ruff, shell syntax checks and Python unittest with `-W error`. Source
publication uses the pinned native Cargo with the lock required and updates
disabled; OBS downloads the matching release archive, and compilation and checks
run offline. The `particleve-initrd` RPM carries the same storage admission
executable used by the host, without the host
administration dependency set or a first-party Python runtime.

The image uses native systemd-vmspawn service templates, machined/machinectl,
networkd, resolved, homed, and sysupdate. Package-family checks prevent mixing
unreviewed Fedora and OBS implementations across the runtime, initrd, and tools
trees. A new upstream feature must be present in the selected stable family
before the image depends on it.

The direct Linux syscall helpers validate their supported host ABI. The TLS
health sender requires the Landlock ABI checked by
[`Sources/runtime/landlock.rs`](../Sources/runtime/landlock.rs). Changes to these interfaces
require native verification in addition to source tests.

## Native build and signing contracts

TLS source checks select Fedora's canonical CA extraction paths using both
`ID` and `ID_LIKE` from the native release metadata. OBS's Fedora worker uses
`ID=generic` with `ID_LIKE=fedora`; it retains Fedora's system trust authority
even when OpenSSL's compatibility bundle alias is absent.

The RPM recipes declare the compiler and build-tool dependencies for native
components. ParticleVE's host and initrd RPMs are architecture-specific ELF
packages; the build-tools component retains Python. The native recipe pins
Rust, Cargo, rustfmt and Clippy to the toolchain release, preserves Fedora's
other compiler flags, and uses full GDB for Rust debug-script inspection during
normal RPM processing. Resolved dependency licenses and upstream notice texts
ship with both Rust runtime components.

The build-tools package uses distribution binutils for PE-section extraction and
kmod for initrd dependency-index verification. Its bounded initrd reader uses
Python's standard `compression.zstd` module and the selected mkosi newc format;
decompression, archive counts and module sizes have explicit limits in the
[verifier](../Sources/particleve/kernelinitrd.py).

The fwupd helper builds with warnings as errors and retains both
SBAT and SBOM sections. Its narrow patch changes a successful linker-selection
message to informational severity; it does not suppress compiler diagnostics.

Kernel modules use CRC32 XZ streams. Linux's in-kernel decoder does not accept
liblzma's default CRC64 check. The kernel recipe prepares the native OBS signing
continuation with an explicit CRC32, single-threaded encoder environment before
its repackaging generator runs, clearing inherited XZ options. This is a narrow
adaptation of the selected signing worker's CRC64 default. Final payload and
initrd verification reject other XZ checks while separately checking each module's
ELF body and signature. Userspace decompression alone does not establish that the
kernel can load a compressed module; the signed-image module tests cover that path.

OBS delivers extracted source files with normalized non-executable modes. Kernel
preparation authenticates every input before restoring only the executable Git
modes recorded by the reviewed source manifest. Restored inputs use private
inodes so a source-cache hard link retains its original permissions. Unexpected
modes, links and modified bytes fail preparation; strict byte and mode checks
run again before Fedora's recipe executes any source script.
Fedora's log and patch-declaration lookups use that authenticated original recipe,
independently of the worker's spec directory and OBS's counter/VCS rewrites.

The kernel's build-only `particleve-kernel-build` dependency supplies a PAM
`nofile` limit of 65536 for OBS's `abuild` account. It is installed before OBS
opens the build session and is excluded from host and initrd package selections.
Fedora's `linkdupes` raises its soft limit itself but retains open files while
comparing the large kernel source tree, so the inherited hard limit must also
allow that workload. Preparation checks the limit before compilation. Local
builders must provide the same limit. Fedora's debug normalization, SELinux-aware
deduplication and signing steps remain enabled.

Kernel packaging retains Fedora's compatibility HMAC files using Python's native
userspace SHA-512 HMAC with hmaccalc's published key and checksum format. It does
not require the build worker's AF_ALG interface. Native equivalence checks cover
the kernel and UKI inputs. The standalone signing continuation carries the same
authenticated public helper and regenerates the HMAC after attaching the PE
signature. PE and module signatures remain independently verified.

The mkosi continuation patch preserves native OBS signing while regenerating
split partitions after verity signing, avoiding duplicate artifact copies, and
handling absent optional signature classes. Recheck the patch against each
upstream pin and exercise the actual signing continuation when it changes.

Installed-payload identities are recorded after normal Fedora RPM build
transformations. EFI payload verification uses the SHA256 Authenticode digest,
which excludes signing-related fields; attached certificate verification is a
separate check. Other file bytes and symlink targets must match exactly.

Keep runtime/initrd storage and TPM drivers, both Intel and AMD KVM support,
microcode, and the declared firmware coverage independent of the OBS worker's
hardware. Do not use build-host CPU optimization or host-only module pruning.
The [build guide](Build.md) describes final-artifact inspection and publication.

## Kernel and mitigation inputs

The native namespace broker requires BPF LSM, user/network namespaces and kernel
probe events. Its [upstream cleanup probe](https://github.com/systemd/systemd/blob/63511d728/src/bpf/userns-restrict.bpf.c#L657)
reclaims namespace policy through `retire_userns_sysctls`.
The kernel policy retains `KPROBES` and `KPROBE_EVENTS` for
that privileged interface; image and runtime checks reject kernels without it.
Unprivileged BPF and perf restrictions remain part of the shared runtime policy.

The supported kernel uses the pinned Fedora packaging and reviewed secureblue
baseline described above. Reviewed source updates flow through OBS package and
dependency rebuilds and the ordinary signed-image publication path.
The trusted-base Fedora workflow verifies published SRPMs using
`RPM-GPG-KEY-fedora-45-primary` from the native `fedora-gpg-keys` package, in an
isolated RPM database. This package authority is separate from kernel PE/module
and image signing trust. Native `rpm2cpio` decoding has CPU, output-size and time
limits; the source reader accepts only bounded flat regular files and zero tail
padding before comparing the complete payload to Git and lookaside identities.
Record the exact kernel and module package versions, origins, source-package
identity, effective configuration, signature trust, and observed mitigations
with the release evidence. Recheck required drivers, systemd/QEMU interfaces,
storage, firmware maintenance, and recovery when the kernel changes.

Further kernel hardening requires an audit of the inherited protections,
measured compatibility and performance, and an explicit adoption decision that
preserves timely Fedora updates and owner recovery. The
[hardening guide](Hardening.md) describes these evaluation boundaries alongside
allocator and execution-policy decisions.

## Verification records

Use the [contributor verification requirements](../CONTRIBUTING.md#required-verification)
for new changes. Historical counts and successful earlier builds do not establish
that a changed toolchain or release passes.

Record the actual interpreter, Ruff, compiler and package versions used, relevant
source pins, configurations, reviewed diagnostics, and any required checks that
remain unperformed. Do not infer a physical machine's firmware, TPM behavior,
DMA isolation, or resource capacity from a successful source or image build.
