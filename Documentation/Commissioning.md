# Commissioning and automatic updates

Commissioning verifies the installed image and the owner's selected hardware,
configuration, and recovery paths before automatic OS maintenance is enabled.
Completed implementation does not replace this installation-specific evidence.
Start with [installation and operation](Operations.md); use the
[release diagnostics](ReleaseDiagnostics.md) for reproducible image acceptance
and [troubleshooting](Troubleshooting.md) when a check fails.

## Contents

- [Evidence and installation identity](#evidence-and-installation-identity)
- [VM state and resource limits](#vm-state-and-resource-limits)
- [Firmware and physical interfaces](#firmware-and-physical-interfaces)
- [Enable automatic OS work](#enable-automatic-os-work)
- [Reporting and persistent startup policy](#reporting-and-persistent-startup-policy)
- [Bootloader and mirror recovery](#bootloader-and-mirror-recovery)

## Evidence and installation identity

Automatic OS work is disabled in the factory presets. Initial TPM enrollment
runs explicitly from the first verified normal boot using `particleve enroll-tpm`;
commissioning checks its record and the live token policies on all three current
LUKS devices, including the configured PCR authorization key. Commission only the exact
installed image, selected disk pair and installation configuration, after the
acceptance matrix has passed. `Tools/Examples/acceptance.json` is an evidence
schema, not a record of completed validation. Fill its image/installation identity,
owner, measured RAM minimum, hardware coverage, gaps and each scenario's evidence
file/hash. A missing, changed or failing scenario blocks commissioning.

Confirm firmware can durably store and read back the admission witness, up to
4 KiB, and retain its installation identity in the independent recovery record.
Record the explicit discard-through-encryption decision; it is not enabled
automatically.

Run tests on disposable disks/VMs or the explicitly selected target with console
and independent recovery credentials available. Never substitute unit-test output
for real boot, TPM, Secure Boot, verity, SELinux or guest I/O evidence. Test cold-home
SSH for a non-root homed user (`PYTHONPATH=Sources:. python3 Tools/check-homed-ssh.py` on the target), root recovery, both boot disks alone, bounded degraded
writes, replacement/profile restoration, corruption rejection, every update boundary,
failed boot/quarantine, Berlin DST/no catch-up and graceful guest refusal/late exits.
Confirm temporary inhibition does not change externally owned startup/restart policy.

## VM state and resource limits

For each disposable VM, record the packaged template/arguments, machined ownership,
KVM acceleration, console, disk/network I/O, per-VM subvolume/raw file attributes and
persistent EFI/optional TPM paths. Restart across an OS update and fallback to prove
that retained host software can access current auxiliary state. Btrfs scrub evidence
must explicitly exclude checksum protection of NOCOW raw contents. Exercise pressure
with configured reserves and report minimum host memory measured without counting swap.

The required `resource_limits` scenario records the selected image/kernel,
physical RAM, normal and maintenance headroom, host overhead and maximum planned
VM population. Record each external unit's guest allocation, memory-high/max,
swap policy, task limit, CPU quota and originating-device I/O controls, including
QEMU/auxiliary overhead. Demonstrate effective counters and throttling rather
than configuration strings alone. Include normal operation, concurrent peak VM
working sets and maintenance, reporting minimum `MemAvailable`, cgroup peaks,
PSI, task peaks, storage free space/metadata and administration responsiveness.
Choose pressure thresholds from the installation's latency and capacity needs.
The example headroom values and the disposable 6-GiB profile are not hardware
minima or production allocation defaults.

Exercise a safely isolated memory-high boundary and a deliberate fatal memory
limit with independent recovery. Verify `memory.oom.group=1`, no OOM-exempt
launcher, complete termination of the failed VM unit, retained peer operation,
failure reporting and guest disk/EFI/TPM recovery. OOM is abrupt loss, not graceful
shutdown; verify ordinary ACPI stop separately. Include task-denial and actual
read/write throttling on the selected mirrored/stacked storage devices. Show
normal/maintenance reserve and storage-exhaustion alerts without relying on swap
as physical RAM. External provisioning remains responsible for aggregate budgets
and workload limits; these checks do not deploy workload definitions. The example
scenario remains `not-run` and earlier approval fingerprints cannot satisfy it.

## Firmware and physical interfaces

Record firmware discovery and helper trust on both ESPs, unsupported devices and
untested transports. If no eligible firmware update exists, mark actual flashing
unvalidated; `firmware_flash.result=no-eligible-update` is accepted only with explicit
evidence. Firmware installation remains supervised after commissioning.

Physical-interface commissioning starts with the target's preflight and
`particleve security-status` discovery reports. Record the image/kernel and
interface capabilities, including missing observations. Keep these reports
owner-local; kernel node names and topology are not anonymized. Define each
required peripheral before enforcement:

| Role | Required review |
| --- | --- |
| Recovery input and media | Keyboard or serial path, required hubs/controllers, bootable recovery media and a separate console route. |
| Selected storage | Both boot/state disks and every USB/Thunderbolt ancestor required to keep either independent boot path reachable. |
| Management networking | The selected NIC, transport/driver and required USB or external-PCIe ancestors; verify SSH after reconnect. |
| Local authenticators | Only authenticators required by a selected local workflow; remote SSH authenticators normally stay on the client. |
| Operational devices | Selected UPS, USB NICs and other necessary devices, with complete composite-interface review. |
| Firmware mode transitions | Trusted normal/bootloader identities, necessary temporary authorization, reconnection and cleanup after success or failure. |

Record whether USB authorization enforcement is selected and why, together with
its reviewed rules and positive/negative reconnect evidence. Never enroll all
currently attached devices automatically. Select unused-radio restrictions and
external-PCIe policy without disconnecting required recovery or storage paths.
Exercise unauthorized peripherals when enforcement is selected, recovery input,
required devices, firmware-mode transitions and relevant DMA protections.
The discovery command performs no enforcement. Fresh configurations separately
declare `physical.radios.allowed_types`, empty unless a reviewed function is
required. Verify the signed image's blocked kernel default, root-only RFKill
node, active zero-capability policy service and matching policy identity. Test
denied and permitted radio reconnects, driver state changes, real hardware
switches, recovery console and management SSH. Identify transmitters outside
RFKill and any persistent radio that can transmit before userspace enforcement;
select firmware disablement or removal where required by the installation's
physical threat model. A populated inventory, virtual-driver test, group count
or unchanged descriptor is not physical acceptance. Record these checks for the installation; USB and external-PCIe authorization
require their separately reviewed policy.

The required `physical_interface_policy` scenario now binds this review to an
evidence file and its hash before commissioning can proceed. Record each required
peripheral/ancestor, the unused functions disabled in firmware or by OS policy,
selected USB authorization mode and rationale, radio allowlist, external-PCIe
authorization/security mode and independently tested DMA isolation. Include
reconnect, recovery input/media, management SSH and firmware-mode transitions
where applicable. An unexposed virtual bus does not prove a physical port is
disabled. USBGuard is optional and deferred in the generic image; selecting
it requires the reviewed image and device rules described in Operations, with
temporary-rule revocation and interrupted-update recovery tests. The virtual
USBGuard evaluation is evidence about its API and loopback gadgets, not physical
commissioning evidence or permission to enable it on an unreviewed host.
Commissioning also records a fingerprint of the required acceptance scenarios.
Automatic eligibility rejects an old or changed fingerprint before relying on
that approval. It requires owner review and recommissioning; it does not convert
an earlier record or migrate installation data.

## Enable automatic OS work

```sh
particleve commission --evidence /var/lib/particleve/evidence/acceptance.json
particleve commission --evidence /var/lib/particleve/evidence/acceptance.json --enable
```

The first command validates evidence and current health. `--enable` binds the record
to configuration and installation hashes and enables the guarded prepare timer and
`particleve-maintenance.timer`. Replacing a disk or changing installation settings
invalidates that binding. `particleve disable-automation` stops the timers and removes
the commissioning marker. Persistent manual maintenance independently inhibits both
preparation and activation under the same durable lock.

Operational policy changes use the reviewed
[`reconfigure` transaction](Operations.md) under persistent maintenance before
new commissioning evidence is supplied. Keep the previously bound configuration
for that review. Disk identities use the dedicated replacement procedure; the
policy transaction does not change layout, network, host identity, trust or access
settings. Diagnostics and automation-disable remain available with an invalid
configuration binding.

## Reporting and persistent startup policy

Commissioning also requires `external_health_reporting` evidence: the
selected endpoint must receive a correctly identified report, reject unauthorized
credentials, retain its own receipt time and detect a stopped sender. Exercise
TLS/redirect refusal, outage and recovery with both guests running. Record the
active report timer and selected endpoint/CA/age policy. Automatic OS eligibility
rejects an old record without this binding or a changed reporting policy. A missing
receiver blocks commissioning; supplying software does not provision a receiver
or commission the owner's machine.

`persistent_startup_policy` evidence must cover the signed initrd's read-only
configuration check, approved installation settings and native VM drop-ins,
rejection of changed settings/unsafe hooks, and attempted startup-file writes
from a confined disposable service. Exercise both the selected and retained OS
images with the same approved configuration; retire images lacking this guard
before commissioning. Earlier signed images do not gain the check retroactively.
Commissioning binds the metadata and content hashes reported by
`particleve startup-inventory`. It never imports a baseline automatically from
an old eligibility record. Account/credential contents are excluded from this
code-origin digest and retain their separate authentication/access policy.

Before deliberately changing a commissioned startup input, enter maintenance,
run `particleve disable-automation`, review and apply the change as root, and
collect new commissioning evidence. Without invalidating the old approval,
the next signed initrd refuses the changed configuration before installed PID 1
can interpret it. Recovery can remove eligibility explicitly; it must not silently
accept the changed digest. No persisted-data migration is implicit in this procedure.

## Bootloader and mirror recovery

The installation contract requires `broken_loader_fallback`,
`stale_member_return` and `unclean_mirror_authority` evidence. For the loader case,
use a disposable signing identity admitted only to copied virtual firmware to
try a trusted EFI application that fails before OS selection. Verify fixed-loader
hashes on both ESPs, continued reachability after failure/reset, quarantine when
the old loader actually ran, and promotion after a real healthy candidate boot.
For stale-member testing, record NOCOW content hashes before removal and after
degraded writes; return the stale disk, prove it stays locked/unscanned, and prove
stale-only boot refuses. Erase/rebuild it explicitly, then compare post-degradation
bytes independently from each member. Verify all allocated profiles are RAID1
before readmission; a successful replace alone does not convert SINGLE chunks
allocated during degraded operation. Any unclean writable session must require
owner authority selection. Earlier evidence that kept stale disks offline does
not satisfy these scenarios. Independent-disk tests revoke missing peers; rebuild
a quarantined peer before testing it as a sole authority.

The deliberately broken loader fixture is
`Tests/acceptance/build-loader-probe.sh error TEST_KEY TEST_CERT OUTPUT_EFI`.
Use `hang` in place of `error` for the reset case.
It requires gcc, binutils, gnu-efi and sbsigntools and builds an EFI application
that either returns `EFI_LOAD_ERROR` or prints an entry marker and hangs before
OS selection. For the hang case, record entry, perform an owner reset and verify
the retained loader is still reachable and the hung hash is quarantined.
Use only disposable signing material
admitted to copied virtual firmware. Never enroll its key on a physical host.
