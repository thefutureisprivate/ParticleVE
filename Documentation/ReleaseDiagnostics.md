# Release and host diagnostics

These checks use the [pinned toolchain](Toolchain.md). The
[contributor verification requirements](../CONTRIBUTING.md#required-verification)
identify when to run them alongside source, build, native component and
signed-image checks.

## Contents

- [Preparing a release](#preparing-a-release)
- [Distribution release](#distribution-release)
- [Repeated lifecycle tests](#repeated-lifecycle-tests)
- [Release evidence](#release-evidence)
- [Investigating a boot or management failure](#investigating-a-boot-or-management-failure)
- [Physical firmware and capacity checks](#physical-firmware-and-capacity-checks)

## Preparing a release

1. Select the reviewed source revision and complete its
   [required verification](../CONTRIBUTING.md#required-verification). Use a clean
   checkout for the release build and record the commit. Source tests do not
   establish the behavior of a later package-only image rebuild.
2. Use the [source and image version contract](Build.md#versions-and-source-selection):
   the four source fields followed by both OBS counters. A dependency-only
   rebuild can change the kernel or other packages without changing the
   ParticleVE source revision. Do not edit a built manifest or reuse an earlier
   image version for different artifact bytes.
3. Review dependency pins, patch descriptions, kernel configuration and
   [third-party notices](ThirdPartyNotices.md). Resolve known build or
   verification failures and explicitly record any remaining coverage limits,
   including physical checks that a virtual fixture cannot perform.
4. Prepare concise release notes against the previous released revision: user
   behavior changes, fixes, dependency/security updates, platform requirements,
   and any persisted-data implications. A version bump does not itself authorize
   a migration; use the
   [compatibility policy](../CONTRIBUTING.md#design-and-compatibility).
5. Run the distribution procedure below. Retain the exact source revision,
   generated evidence, and matching artifacts together. Tie release notes and
   any source tag to the revision actually built, rather than rebuilding an
   unrecorded newer checkout for publication.

## Distribution release

Use the [build and publication procedure](Build.md) and the selected OBS project.
OBS resolves the declared Fedora and stable-systemd dependencies, builds the
host, initrd, build-tools and upstream packages, and signs the final image
through the native continuation. Package-only rebuilds follow the same identity
and publication checks as source changes.

Publication requires a complete authenticated artifact set, matching source and
installed-payload identities, the intended package origins, and verified boot
trust. RPM signing, the signed checksum index, UKI/PE signatures, verity,
systemd-boot, the fwupd EFI helper and PCR authorization serve different purposes;
checking one does not establish the others. Failed signing or final inspection
must not publish an eligible release manifest or replace the last usable feed.

Fedora kernel package updates follow the same dependency and publication
workflow. Record the exact kernel and module versions, Fedora package origins,
effective configuration, and signature trust. Repeat the relevant boot, storage,
virtualization, firmware, and recovery checks after kernel changes, including
retained-image compatibility. Optional custom-kernel experiments have a separate
adoption decision and do not change the normal Fedora kernel update path.

Verify the published release using the ordinary authenticated release client,
including full artifact hashes and PE/verity checks. The read-only publication
observer in [Build.md](Build.md#publication-monitoring-and-trust-boundary) checks
freshness and availability; it does not substitute for full payload verification
or deploy a release. Keep one production feed and the existing conditional host
update path. A separate promotion service or second production machine is not a
release requirement.

## Repeated lifecycle tests

Run the ordinary source checks from the repository root:

```sh
make check
```

Use [development](Development.md) for supported targeted checks and the
[commissioning procedure](Commissioning.md) for native fixture requirements.
Repeat the affected operations against the actual signed image, retaining
invocation identities and state markers:

| Boundary | Required observations |
| --- | --- |
| VM start, stop and restart | KVM and native readiness; actual process privileges, seccomp and MCS labels; disk/network I/O; graceful process exit; retained disk, EFI and optional TPM identity. |
| Maintenance interruption | Refused and late guest exits, concurrent starts/restarts, failed reboot requests and interrupted coordinator state. The host stays running on refusal; only VMs stopped by that attempt are restored. |
| Two-disk update | Complete authenticated sets, explicit disk identities, interruption at artifact boundaries, retained boot entries and no unrelated disk writes. |
| Boot assessment and fallback | Correct physical `/usr` backing, native counters/blessing, rejected-image quarantine and unchanged writable state. |
| EFI loader trial | A trusted deliberately broken or hanging loader fails before OS selection; known-working fixed paths and BootOrder remain intact. A real candidate boot is required for promotion. |
| Mirror authority | Degraded NOCOW writes, a returned stale member kept locked, stale-only refusal, explicit erased rebuild, independent readback and owner recovery after an unclean session. |
| Policy and trust changes | Positive and negative access probes, retained-image compatibility, both independent boot paths, current TPM authorization and independent recovery. |

Stop a repeated run on failure and retain its evidence. Do not use repeated
retries to turn an unchanged failing case into a passing result, or let an earlier
successful invocation hide a later failure. A request
accepted by machinectl is not evidence that a guest exited, and a healthy Btrfs
profile is not evidence that two NOCOW replicas contain the same bytes.

The reusable native probes under [Tests/acceptance](../Tests/acceptance) exercise
specific boundaries such as management networking, kernel interfaces, physical
policy and loader behavior. Read their arguments and fixture requirements before
running them. These are targeted diagnostics, not a single unattended test that
can safely run on arbitrary production hardware.

Use the [compiled-helper prerequisites](Development.md#native-probes-with-compiled-helpers)
for harnesses that require `--runtime-driver` or `--runtime-binary`. Retain the
helper hash and matching source, and distinguish staged component code from the
release's installed binaries. Source tests, a successful RPM build or a staged
helper cannot establish final signed-image acceptance.

## Release evidence

Retain matching artifacts and evidence together. The evidence must identify
what was actually executed rather than only the intended configuration:

| Evidence | Contents |
| --- | --- |
| Source and build identity | ParticleVE commit and full source/image versions, Rust toolchain and Cargo lock, upstream pins, recipes, patches, build environment, OBS project/build identifiers and package versions/origins. |
| Native ParticleVE payloads | Host/initrd/build-tools identities, final RPM-transformed ELF hashes, architecture and compiler flags, PIE/RELRO/NOW/non-executable-stack checks, dependency license records and any staged test-helper hashes. |
| Artifact identity and trust | Signed index, manifest, complete artifact hashes, applicable certificate/key identities and verification results for each trust chain. |
| Kernel baseline | Exact Fedora kernel/module package versions and origins, source-package identity, effective configuration, compiler protections, module-signature trust, loaded microcode and measured platform mitigations. |
| Host and fixture | CPU/firmware/TPM capabilities, actual storage/NIC topology, memory, selected disk identities, test-only substitutions and excluded hardware coverage. |
| Runtime security | Effective SELinux policy, launcher/QEMU authority, namespace/device/socket restrictions, writable-startup checks, authenticated time/DNS and positive/negative access results. |
| Lifecycle and persistent state | Booted ESP and `/usr` backing, loader hashes, guest process identities, disk/EFI/TPM markers, witness state and independent rebuilt-member readback. |
| Capacity and policy cost | Normal/maintenance RAM reserve, pressure and cgroup peaks, storage headroom, resource failure boundaries and overhead of adopted kernel/allocator changes. |
| Recovery and administration | Independent owner credentials and console, either-disk boot, encryption recovery, stale-member/unclean-state recovery, retained-image behavior and reviewed trust rotation. |
| Outcome and limits | Successful and failed cases, unavailable hardware/firmware tests, narrow exceptions, retained diagnostics and the exact source/image to which each result applies. |

The signed manifest contains producer-authenticated provenance. It does not
independently prove that a compromised build worker behaved correctly. Likewise,
expected boot measurements do not prove the absence of runtime compromise.
Document optional attestation or allocator/LoadPin adoption separately; the
presence of an evaluation does not establish an enforced runtime control.

Keep sensitive diagnostic material privately alongside its matching release.
Public evidence must omit private signing keys, recovery keys, credentials,
unredacted host topology and guest/TPM state.

## Investigating a boot or management failure

Identify the affected image, source revision, boot attempt, selected ESP and
verified `/usr` backing before changing state. Collect the bounded host reports
and relevant journal entries using [troubleshooting](Troubleshooting.md):

```sh
particleve status
particleve security-status
particleve startup-inventory
```

Use root recovery or the independent console when the ordinary management path
is unavailable. Keep the failure record and distinguish loader execution, initrd
storage admission, OS assessment, network readiness and guest startup. An older
OS boot cannot authorize an uncertain storage member or repair untrusted writable
configuration by itself.

Do not clear exhausted counters, reconstruct a missing witness from an arbitrary
disk, reset VM firmware/TPM state or relax SELinux to obtain a successful boot.
Follow the relevant [recovery procedure](Operations.md) and preserve data when an
outcome is uncertain. Routine core dumps of sensitive processes are disabled;
any temporary debugging exception requires controlled access, a bounded capture
and cleanup without changing the normal image policy.

## Physical firmware and capacity checks

Physical acceptance uses the selected host with independent recovery access.
Record firmware update availability, transport, helper trust, actual result and
post-update TPM/boot behavior. Firmware installation and its reboot remain
supervised. If no eligible update exists, report flashing as unvalidated rather
than converting metadata discovery into a successful update.

Exercise required recovery input, management NICs, allowed peripherals, radio
policy, external-PCIe/DMA behavior and firmware-mode identity transitions.
Virtual controllers demonstrate only their own fixture behavior. USBGuard is
optional; the generic image's deferral does not establish that an installation's
physical interfaces are adequately protected.

Measure normal and maintenance headroom with the intended VM population. Include
QEMU and auxiliary overhead, zswap residence, page cache, storage metadata and
recovery operations. Exercise the consequences of hard resource limits and show
that administration and peer guests retain their declared reserves. An OOM kill
is an abrupt guest failure, not graceful shutdown. Publish measured minima and
coverage with the selected release; do not promote example values or an old
fixture's configured RAM into a supported minimum.
