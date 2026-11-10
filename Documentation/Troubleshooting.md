# Troubleshooting and recovery

Start with the exact message shown by ParticleVE. Host configuration, mirror
authority, boot state, and VM identity have different recovery paths. The
[architecture](Architecture.md) describes their contracts; this guide covers
supported actions and information useful for investigation.

Keep independent console access and owner recovery credentials available.
Start with bounded status and journal observations:

```sh
particleve status
systemctl --failed
journalctl -b -u particleve-boot-assess.service -u particleve-runtime-ready.service --no-pager
journalctl -b -u particleve-maintenance.service --no-pager
```

`particleve security-status`, `particleve startup-inventory`, and
`particleve health-report` provide more detailed root-only observations. A
failed prerequisite can stop a full security report; retain that error and use
the relevant service journal instead of weakening the check to obtain output.

## Host configuration cannot be loaded

An invalid or changed bound configuration does not authorize the host to adopt
default values. Normal backend operations remain blocked while the installation
binding is invalid or a reconfiguration journal is unfinished. `particleve status`
still reports binding problems, and `particleve disable-automation` remains
available even with unreadable host JSON.

Preserve the configuration, installation manifest, and any reconfiguration
journal together. For an already reviewed interrupted operation, use
`particleve reconfigure --resume` to inspect the stored operation, then finish
it only with its original confirmation. Recovery accepts no replacement input
files. See [operational reconfiguration](Operations.md#operational-reconfiguration).

This operation changes operational policy only. It cannot change disk roles,
layout, network, host identity or access settings. The only trust exception is
the reviewed one-way [NTS transition to system CA trust](Operations.md#operational-reconfiguration).
Deleting the installation binding or journal does not establish that a new
configuration is safe.

## Encrypted storage cannot be restored

First identify the selected disks and which boot path actually ran. TPM failure
does not by itself mean the data is lost: use the independent recovery
passphrase through the reviewed console or recovery environment. Do not enroll
the recovery environment into normal unattended authorization.

If a member was absent during writable operation, it is quarantined. Reconnecting
it does not readmit it; a stale-only boot must refuse. Keep failed hardware
disconnected until a degraded reboot has confirmed quarantine, then use the
[disk replacement procedure](Operations.md#disk-replacement). An exact returning
disk requires the explicit `--rebuild-quarantined` erasing workflow.

An unclean writable session requires owner selection of one previously admitted
authority with the installed Btrfs filesystem unmounted. Follow
[mirror recovery](Operations.md#unclean-shutdown-and-failed-members). Recovery
credentials, a matching serial, a successful scrub, or a newer-looking
superblock do not prove which NOCOW replica is current.

If firmware reset erased the admission witness, preserve the disks and restore
only an owner-reviewed admission record. Do not derive authority from whichever
member appears first or open both stale candidates to see what happens.

## Boot assessment did not finish

The normal initrd and boot-assessment watchdogs use bounded attempts. Inspect
the failing boot's journal from a working path or the independent recovery
environment. Keep the image version, boot ID, selected ESP, actual verity
backing disk, and exact assessment failure together.

Losing the disk serving active verified `/usr` can interrupt operation even when
the writable mirror survives. Select the other disk's retained boot path and
follow the normal degraded recovery procedure. OS fallback does not rewind
the writable root or VM state.

A loader that hangs before OS selection may require an owner reset. Both disks
retain normal and removable-media loader paths independently of the trial.
After recovery, inspect the trial/quarantine outcome; do not promote a candidate
merely because an OS eventually booted. See
[bootloader trials](Operations.md#bootloader-trials-and-fallback).

## Persistent startup verification failed

The signed initrd checks approved persistent configuration before installed
PID 1 interprets it. A changed unit, executable hook, ownership, permission, or
content hash can therefore stop normal startup before SSH is available.

Preserve the changed file and the prior approved context for review. Deliberate
changes need maintenance, invalidation of the old commissioning approval, and
new evidence. Recovery may explicitly remove eligibility; it must not silently
accept a new digest. Do not copy an approval from another host or select an
unguarded older image to bypass the check. See
[persistent startup configuration](Operations.md#persistent-startup-configuration).

## A VM cannot start or has missing state

Check the owning `systemd-vmspawn@NAME.service` journal and external definition.
The guard requires native unit ownership, KVM, enforcing SELinux, a private
per-VM subvolume, matching unique MCS categories, the packaged launch/stop
helpers, and finite memory/task limits. A temporary maintenance start inhibition
can independently block an otherwise valid unit.

Keep the raw disk, EFI variables, TPM directory, unit definition, and category
assignment together. Do not copy a different VM's TPM state, generate a fresh
EFI store over a retained identity, recursively relabel a running VM, or remove
one side of the state to force a match. TPM use must explicitly select `no`, or
`yes` with already provisioned private state. See
[VM storage and runtime](Operations.md#vm-storage-and-runtime).

After a kernel OOM, confirm that the whole failed unit exited and inspect the
guest filesystem, EFI/TPM state, and configured budget before restoring the
external restart policy. A hard-limit kill is abrupt data loss exposure, not
successful graceful maintenance. Swap and zswap cannot replace an adequate
physical memory budget.

## VM shutdown or update activation was interrupted

An interrupted shutdown or reboot request can have an unknown outcome. An error
does not prove that no VM stopped. The coordinator retains the attempted VM set
and reconciles actual process state before restoring only the guests stopped
by that attempt.

Inspect `particleve status` and the maintenance journal. Use
`particleve recover-vms` for the recorded interrupted attempt, then inspect
late exits and restoration failures before retrying. Do not delete the
transaction record or start every historical guest indiscriminately. Previously
stopped VMs must remain stopped, and still-running VMs must not be duplicated.

When there is no ready update, or verification, resource, firmware, clock, or
graceful-shutdown checks fail, the host stays running. Automatic
activation waits for another eligible 04:30 Europe/Berlin window. Supervised
`prepare --manual` and `activate --manual` are deliberate owner operations with
the same disk, firmware, fallback, and graceful-shutdown guards; they are not
repair commands for an unexplained failure. See
[OS maintenance](Operations.md#os-maintenance).

## Network or authenticated time is unavailable

Check the configured physical interface and permanent identity, management
sources, routing, resolved state, and the restricted chrony service. Missing
or changed required network policy can block health assessment. NTS source
disagreement or staleness defers automatic activation without stopping running
VMs.

A clock outside certificate validity can prevent both DNS-over-TLS and NTS
bootstrap. Use independent console access or the numeric management address,
verify time through an owner-trusted source, correct the RTC, and let normal
certificate authentication recover. Do not disable certificate-time validation
or substitute unauthenticated NTP. Private DNS failures do not authorize public
resolver fallback. See [time and DNS policy](Operations.md#authenticated-time-and-dns).

## TLS certificate trust errors

ParticleVE HTTPS clients, reporting, NTS and DNS-over-TLS use the system CA trust
store. Check the peer name, clock, distribution CA package and owner-installed
anchors. Provision an approved public CA through Fedora's trust configuration
and run `update-ca-trust`; a per-tool CA file or `SSL_CERT_FILE`/`SSL_CERT_DIR`
override is not the ParticleVE client configuration path. Do not disable
certificate or hostname checks to make a request succeed.

Reporting requires `private_ca=false`. NTS requires `trust=system` for each
source and empty `time.certificates`. An older bound NTS configuration can enter
maintenance and use the reviewed reconfiguration transition; retain its original
configuration and confirmation for interrupted recovery. Reporting changes also
need the documented commissioning review. See
[time and DNS policy](Operations.md#authenticated-time-and-dns) and
[external reporting](Operations.md#external-health-reporting).

## Human SSH access is rejected

A non-root homed account needs its public key and account password to activate
an inactive home. Test a fresh connection and a cold home; a previously active
session does not prove recovery works. New home subvolumes need the documented
Fedora labeling step before first login. Retained homes require a separately
reviewed repair rather than recursive relabeling during an update.

FIDO2 signatures require both presence and verification. Use the enrolled spare
authenticator or independent owner recovery when the primary is unavailable.
Do not weaken the global signature requirements to diagnose a lost token, or
copy private keys onto the host. See
[administration and accounts](Operations.md#administration-and-accounts).

## Health reports stop arriving

The receiver must use its own receipt time to detect a stopped sender. Inspect
`particleve-report.service`, the timer, endpoint, system CA trust and receiver-side
authentication. Redirects, an invalid certificate, an oversized response, or a
failed privilege/confinement check must not be bypassed to deliver a report.

Reporting failure is independent of guest lifecycle. It does not authorize a
reboot or stop running VMs. A missing receiver blocks commissioning, while
missing reports from an already configured sender require external attention.
See [external health reporting](Operations.md#external-health-reporting).

## Data ownership and preservation

| Data | Owner and location | Why it matters |
| --- | --- | --- |
| Host and reporting settings | Root-owned files under `/etc/particleve`. | Bind installation policy, management access, and the report destination. |
| Installation, update, commissioning, reconfiguration, and replacement records | Root-owned `/var/lib/particleve`. | Record disk identities, authority, in-progress operations, and approved policy. |
| Mirror admission witness | Firmware variable `ParticleVEStorage`. | Controls which exact encrypted members may join writable storage. |
| Loader trial records and retained loader blob | `/var/lib/particleve/bootloaders` and reviewed ESP paths. | Preserve proven recovery loaders independently of OS cache cleanup. |
| Human homes and records | Native homed storage on encrypted Btrfs; root recovery at `/root`. | Authentication, activation, and recovery have separate ownership. |
| Guest disks, EFI variables, and optional TPM state | Externally provisioned per-VM subvolumes under `/var/lib/machines`. | Must remain paired with their VM identity and SELinux category assignment. |
| Build products, probes, and caches | Repository/configured build directories. | Separate from installed host and guest data; see [development](Development.md). |

For diagnostic copies, preserve related state and its identity together. Raw
configuration, logs, account records, firmware metadata, and guest files can
contain private addresses, identifiers, credentials, or workload data. Share
only the specific material needed through an appropriate channel. External
backup and restore procedures must preserve guest consistency and identity;
this host recovery guide is not a VM backup implementation.

## Reporting a problem

Include the source revision and image version, architecture, kernel/systemd
versions, exact error text, approximate time and boot ID, reproduction steps,
and whether the result came from a disposable fixture or the selected host.
For storage failures include the booted ESP, member availability, whether writes
occurred while degraded, any power loss, and the last completed operation.
For VM failures include the unit contract and which disk/EFI/TPM state was
retained, without publishing its contents.

Remove secrets and unnecessary identifiers from public reports. Use
[GitHub issues](https://github.com/thefutureisprivate/particleve/issues) for
ordinary bugs and follow the [security policy](../SECURITY.md) for
vulnerabilities. Contributors can use the isolated
[release diagnostics](ReleaseDiagnostics.md) to investigate without
experimenting on the owner's live storage or guest workloads.
