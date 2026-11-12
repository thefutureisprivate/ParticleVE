# Development

Run commands from the repository root. Read the [contributor guide](../CONTRIBUTING.md)
and use the [pinned toolchain](Toolchain.md); these workflows do not replace the
required verification for a change. Distribution builds have a separate
[release procedure](ReleaseDiagnostics.md#preparing-a-release).

## Local builds

Use a Linux development environment with the pinned Rust toolchain, a C linker,
libselinux development headers, Python 3.14 or newer, Ruff, Git, GNU Make, Bash,
GnuPG, OpenSSL, cpio, and the OpenSSH client tools. The source tests use
`ssh-keygen` to check actual public-key parsing. Image builds also need the native
tools and project packages described in [build and publication](Build.md) and
the [mkosi RPM recipe](../.obs/mkosi/mkosi.spec). The runtime, initrd, and image
tools use Fedora 45, the pinned Fedora-derived kernel packages, and the selected
stable systemd package family.

Check the source and prepare the pinned build inputs:

```sh
make check
make sources
PYTHONPATH=Sources:. python3 Tools/configure-build.py --site .obs/site.json
make summary
```

`make sources` fetches the mkosi, fwupd-efi, Fedora kernel packaging, and
secureblue/kernel revisions in
[`sources.lock.json`](../sources.lock.json). This checkout is the ParticleOS
fork; its recorded upstream revision is provenance, not another tree to download.
Existing source checkouts must match their pins and have clean worktrees.
`configure-build.py` validates public trust and generates repository, initrd,
and image inputs. Review those tracked changes. `make summary` resolves and
checks the configuration of all three trees before image generation.

For a local signed image, first make the matching ParticleVE host, initrd,
build-tools, kernel, pinned mkosi, and fwupd-efi RPMs available to the selected build
environment and repositories. Their recorded source and payload identities must
match the checkout. Changing runtime code, trust, recipes, or patches requires
rebuilding the affected packages; published packages from another implementation
revision cannot stand in for those changes.

Configure the intended signing identity in the ignored `mkosi.local.conf`, with
private material outside the checkout. For a development identity shared by
Secure Boot, PCR authorization, and verity signing, the configuration is:

```ini
[Validation]
SecureBootKey=/absolute/path/to/development.key
SecureBootCertificate=/absolute/path/to/development.crt
SignExpectedPcrKey=/absolute/path/to/development.key
SignExpectedPcrCertificate=/absolute/path/to/development.crt
VerityKey=/absolute/path/to/development.key
VerityCertificate=/absolute/path/to/development.crt
```

Replace these paths with existing key and certificate files. Use the required
RSA4096 identity and matching public trust in the image and packages; changing
only the local key paths does not change the image's accepted authority. Keep
development trust and its firmware enrollment in disposable fixtures. OBS keeps
distribution private keys outside source checkouts and uses native deferred
signing; local builds use mkosi's normal signing inputs.

With those prerequisites in place, build the image:

```sh
build/sources/mkosi/bin/mkosi --force build
```

The builder assembles the image and runs the configured initrd, tools, and
runtime checks. Its output includes the disk image, UKIs, split OS partitions,
and package manifests under `mkosi.output/`, using the selected image version. Rebuilding
the same version with `--force` replaces its existing local output. Use the
release procedure for final publication and signed-image acceptance.

| Build or check | Command | Output |
| --- | --- | --- |
| Source checks | `make check` | Rust and Python tests, compiled contract checks, lint, formatting, shell syntax and version consistency. |
| Resolved image configuration | `make summary` | `build/summary.json`. |
| Local signed image | `build/sources/mkosi/bin/mkosi --force build` | `mkosi.output/ParticleVE_<version>_x86-64*`. |
| OBS dependency configuration | `PYTHONPATH=Sources:. python3 Tools/obs-project.py --site .obs/site.json --summary build/summary.json` | `build/obs-project/` and `.obs/fedora/x86-64/mkosi.conf`. |
| Image and ParticleVE RPM sources | `PYTHONPATH=Sources:. python3 Tools/prepare-obs.py --tree HEAD` | A fresh `build/obs-packages/particleve/`, including source and locked vendor archives. |

`prepare-obs.py` archives the exact Git commit or tree object supplied through
`--tree`; using `HEAD` excludes uncommitted edits. Source preparation does not
upload or publish a release. It invokes the pinned Cargo to vendor the selected
tree's lock without changing it; fetching missing crates needs network access at
this preparation stage. `--cargo` selects an explicit Cargo executable. The
resulting RPM build uses those vendored sources offline. The normal OBS source
services also prepare the separately pinned mkosi and fwupd-efi packages.

### Kernel source preparation

Generate the kernel package's public recipe, config overlay, source manifest,
and OBS services from its clean pinned upstream checkouts:

```sh
make sources
PYTHONPATH=Sources:. python3 Tools/prepare-kernel.py
PYTHONPATH=Sources:. python3 Tools/prepare-kernel.py --check
```

Review the generated files in [`.obs/kernel/`](../.obs/kernel). The adapter keeps
Fedora's native build machinery, applies the selected secureblue patch and config,
and records explicit [ParticleVE deviations](../.obs/kernel/policy.json).
The source manifest binds Fedora's packaging files, Git executable modes,
lookaside archive checksums and the adaptation inputs. The RPM preparation step
checks those inputs before unpacking the kernel. An independently authenticated
Fedora source RPM's extracted files can also be checked with
`--verify-srpm-sources /absolute/path/to/extracted-sources`.

The trusted-base [kernel PR workflow](../.github/workflows/kernel-source-update.yml)
performs that independent check automatically. Fedora RPM versions come from the
release and stable-updates source repositories; Koji supplies the corresponding
immutable Git identity. The workflow uses a separate RPM database containing only
the selected release's native public key, then decodes bounded regular source
members without executing the SRPM recipe. Source Git, package signatures and
lookaside checksums must agree before generated files are appended to the PR.

The retained public certificate bundle preserves the two Fedora built-in
authorities from the approved stock baseline. Changes to that bundle require
the separate trust-review and acceptance procedure. Private signing keys remain
external build inputs. Use the ordinary signed-image release gates before
publishing a kernel or changing the installed image's package selection.

Kernel source pins include an advertised branch for bounded source transport.
The fetcher verifies that the locked commit belongs to that history and checks
out the exact commit. A branch tip never substitutes for an unavailable pin.

The native recipe keeps Fedora's debug and strip processing, then records the
resolved configuration, build environment, kernel Authenticode digest and each
module's ELF body in `particleve-kernel.json` inside the kernel module tree.
OBS's standard signing continuation attaches the kernel/module signatures and
compresses modules with XZ. The public project certificate is required before
kernel preparation; the private key stays outside the worker. The
[payload verifier](../Sources/particleve/kernelpayload.py) compares module bodies
independently of compression and verifies their PKCS#7 signatures against the
selected certificate. A matching signature alone does not establish source
identity.

The image verifier accepts the installed subset of that signed module build,
checks the four runtime kernel RPM versions, and binds the UKI kernel bytes and
release name to the selected module tree. The build-tools package carries the
reviewed source manifest. A pin update therefore also requires matching
verification tools and refreshed image source metadata.

Final initrd verification uses the generated source policy, the matching native
initrd RPM record, and the selected userspace module tree. It checks the actual
UKI section after signing, including helper and unit identity, masks, dependency
indexes and module signatures. The
[archive verifier](../Sources/particleve/kernelinitrd.py) never materializes
archive symlinks and rejects ambiguous replacements before publication.

[`kernel-signing.py`](../Tests/acceptance/kernel-signing.py) exercises native RPM
stripping, the OBS signing continuation, XZ compression and rejection of changed
or untrusted payloads. Run it only in a disposable Fedora build environment with
`--workspace`, `--certificate`, `--key`, `--kernel` and `--helper` inputs. Configure
that environment's RPM `_topdir` as `WORKSPACE/rpmbuild`, including for child RPM
processes. Use a disposable external signing key and read-only PE input; the
probe neither loads a module nor executes the kernel. Full signed-image boot and
recovery acceptance remain separate release gates.

## Incremental work and isolated outputs

The image configuration enables mkosi's incremental cache. The project checks
source identities, recipes, patches, installed package payloads, and image
policy before accepting the build. Running the normal builder after preparing
matching packages is the ordinary incremental workflow. For a runtime iteration
that does not need an image, run the affected compiled tests directly:

```sh
cargo test --locked coordinator::tests
```

Run the checks required for the whole change before handing it off. After
dependency, patch, trust, image-profile, or toolchain changes, regenerate the
affected configuration and rebuild the affected packages. A single `--force`
allows replacement of an existing output; it does not invalidate every cache.
Keep one writer per worktree, source checkout, cache, and output directory;
use separate writable paths for concurrent experiments.

The main path controls are:

| Setting or argument | Purpose |
| --- | --- |
| `Tools/fetch-sources.py --output` | Pinned upstream checkouts; defaults to `build/sources`, which `make summary` also uses. |
| mkosi `OutputDirectory=` / `--output-directory` | Image products; defaults to `mkosi.output`. |
| mkosi `CacheDirectory=` / `--cache-directory` | Incremental build cache; defaults to `mkosi.cache`. |
| `Tools/obs-project.py --output` | Generated OBS project metadata; defaults to `build/obs-project`. The tool still updates the checkout's `.obs/fedora/x86-64/mkosi.conf`. |
| `Tools/prepare-obs.py --output` | Prepared source packages; defaults to `build/obs-packages`. Its `particleve/` package directory must be fresh. |
| Cargo `CARGO_TARGET_DIR` | Compiled binaries, tests and the contract driver; defaults to `target/`. Keep writable targets separate for concurrent work. |
| `mkosi.local.conf` | Ignored local configuration, including references to external signing material. |

For example, after configuring a separate worktree with its matching packages
and signing identity, give its image build dedicated output and cache paths:

```sh
build/sources/mkosi/bin/mkosi \
  --output-directory="$PWD/build/local-image" \
  --cache-directory="$PWD/build/local-cache" \
  --force build
```

Changing output paths alone does not isolate the tracked inputs written by the
configuration generators. Do not run competing generators in the same worktree.
Keep `build/sources/` pinned and clean; develop upstream changes separately, then
update the selected revision or reviewed patch with its recipe and lock inputs.

The image hooks already verify the installed trees through
[`Tools/check-build.py`](../Tools/check-build.py). Final distribution checks
also need the actual signed artifacts and their provenance; a successful source
test or configuration summary is insufficient. Use the matching image, source
revision, package identities, and trust when repeating the
[publication checks](Build.md#signing-and-release-publication).

For an isolated compiler environment, [`Tools/rust-build.py`](../Tools/rust-build.py)
accepts an immutable local Fedora compiler image ID, an installed pinned Rust
toolchain, a populated Cargo cache, a target directory and explicit Podman store
paths. See `python3 Tools/rust-build.py --help` for its required arguments. It
copies only public runtime/test inputs into a temporary source mount and runs
without network access; private signing inputs and acceptance disks are not
mounted. Use dedicated public caches and targets. Populate the dependency cache
with `cargo fetch --locked` before the offline run. When using this command as
`make`'s `CARGO` override, set `CARGO_TARGET_DIR` to the same host target directory
so Python tests find the resulting driver.

## Tests and diagnostics

The [required-check matrix](../CONTRIBUTING.md#required-verification) is
authoritative. These are the common local entry points:

```sh
make lint
make test
make check
```

`make lint` runs Rust formatting and Clippy with warnings as errors, Ruff, and
Bash syntax checks for the image and EFI-fixture scripts. `make test` runs Rust
tests, builds the test-only contract driver, then runs Python unittest with
warnings as errors. `make check` runs both and validates source versions. These
source checks do not require building an image first.

For a focused cross-language regression, build the driver before selecting the
relevant unittest modules:

```sh
cargo build --locked --example runtime-contract-driver
PYTHONPATH=Sources:. python3 -W error -m unittest \
  Tests.test_rust_common Tests.test_rust_storage Tests.test_rust_orchestration -v
```

With a custom Cargo target, also set `PVE_RUNTIME_DRIVER` to that target's
`debug/examples/runtime-contract-driver`. `make test` sets this path for its
Python invocation automatically. Focused commands supplement `make check`,
which applies the repository's complete diagnostics and hardening flags.

Rust tests exercise runtime policy and injected failure boundaries. Python
handles build tests, persisted-format checks and native acceptance orchestration.
Runtime harnesses invoke the compiled helpers with explicit fixture inputs and
expected outcomes. Small shell fixtures exercise shell interfaces or build native
test payloads. Keep the required whole-change checks alongside focused iterations;
selecting a module does not run Ruff or the shell checks.

For native coverage, prepare the disposable fixture described by the relevant
acceptance procedure first. The probes in [`Tests/acceptance/`](../Tests/acceptance/)
run separately from `make check`; some require root, selected installation
identities, test keys, or devices. For example, inside a disposable Fedora 45
systemd fixture, run this inert service/timer regression as root:

```sh
python3 Tests/acceptance/storage-monitor-cadence.py \
  mkosi.extra/usr/lib/systemd/system/particleve-storage-watch.service
```

That probe creates temporary units, checks actual start-limit behavior, and
removes its units afterward. It establishes that component's behavior on the
fixture. Boot, disk-loss, TPM, guest-lifecycle, and physical-firmware coverage
have their own prerequisites and procedures.

| Purpose | Guide or entry point |
| --- | --- |
| Package source, recipe, and installed-payload identity | [Build and publication](Build.md); [`test_package_provenance.py`](../Tests/test_package_provenance.py) and [`test_upstream_provenance.py`](../Tests/test_upstream_provenance.py). |
| Signed manifests, artifacts, and publication observation | [`test_signed_feed.py`](../Tests/test_signed_feed.py), [`test_buildartifacts.py`](../Tests/test_buildartifacts.py), and [`test_publication.py`](../Tests/test_publication.py). |
| Persisted JSON and compiled-policy equivalence | [`test_rust_common.py`](../Tests/test_rust_common.py), [`test_rust_storage.py`](../Tests/test_rust_storage.py), and [`test_rust_orchestration.py`](../Tests/test_rust_orchestration.py). |
| Update interruption, guest shutdown, and restoration | Rust tests in [`coordinator.rs`](../Sources/runtime/coordinator.rs), [`vms.rs`](../Sources/runtime/vms.rs), [`vmrun.rs`](../Sources/runtime/vmrun.rs), and [repeated lifecycle tests](ReleaseDiagnostics.md#repeated-lifecycle-tests). |
| Disk admission, stale members, and recovery | Rust tests in [`admission.rs`](../Sources/runtime/admission.rs), [`install.rs`](../Sources/runtime/install.rs), [`bootloaders.rs`](../Sources/runtime/bootloaders.rs), and [bootloader and mirror recovery](Commissioning.md#bootloader-and-mirror-recovery). |
| Guest authority and SELinux confinement | Rust tests in [`confinement.rs`](../Sources/runtime/confinement.rs), [`processes.rs`](../Sources/runtime/processes.rs), and [QEMU containment](Hardening.md#qemu-containment). |
| System CA trust | Native TLS tests in [`Tests/runtime/tls.rs`](../Tests/runtime/tls.rs), [`test_system_trust.py`](../Tests/test_system_trust.py), [`test_sourcegit.py`](../Tests/test_sourcegit.py), the [native trust lifecycle probe](../Tests/acceptance/system-trust.py), the [native Git probe](../Tests/acceptance/source-trust.py), and [TLS operating policy](Operations.md#authenticated-time-and-dns). |
| Native networking, kernel interfaces, and device policy | [`Tests/acceptance/`](../Tests/acceptance/), [hardening](Hardening.md), and the selected probe's arguments and prerequisites. |
| Trust transition | [`test_release_trust.py`](../Tests/test_release_trust.py) calls the compiled and publication checksum verifiers with real GPG keys. [`pe-trust.py`](../Tests/acceptance/pe-trust.py) takes `--efi READ_ONLY_PE_INPUT` and tests native PE signatures with ephemeral keys; it never executes its input. Both are component checks; use the [full transition matrix](ReleaseDiagnostics.md#trust-transition-acceptance) for firmware, TPM, modules and boot. |
| Allocator evaluation | The [scoped allocator procedure](#scoped-allocator-components) checks signed source, final RPMs, actual loading and bounded process behavior before the full adoption matrix. |
| EFI loader failure and fallback | [`build-loader-probe.sh`](../Tests/acceptance/build-loader-probe.sh). |
| Final signed-image and hardware behavior | [Release diagnostics](ReleaseDiagnostics.md) and [commissioning](Commissioning.md). |

Measurements are diagnostic. They do not replace correctness assertions or
establish VM capacity from an idle host or isolated fixture. Record the actual
source, image, fixture, configuration, results, and coverage limits.

The native trust lifecycle probe runs as uid 0 in a disposable **rootless Fedora
container**, with public source and the matching compiled contract driver mounted
read-only. Keep the container's `/etc` and `/usr/share/pki` private; do not bind
host trust directories into it. With `PYTHONPATH=Sources:.`, run:

```sh
python3 Tests/acceptance/system-trust.py --runtime-driver DRIVER \
  --source-revision FULL_COMMIT_SHA --confirm-disposable-container
```

It requires OpenSSL and Fedora's `ca-certificates`, `p11-kit` and `p11-kit-trust`.
The probe records their versions, bundle and binary identities, actual loopback
TLS/HTTP observations, certificate failures and attempted CA overrides. It adds,
removes and distrusts an ephemeral CA through the system inputs, observes the
stale-bundle interval before extraction, repairs a stale output and verifies
restoration. The Rust downloader, Rust health delivery and Python publication tool
use their production trust loaders. This component probe does not establish
the reporter's privilege handoff, daemon reload behavior,
chrony NTS, resolved DoT, package-update boot or signed-image acceptance; exercise
those boundaries separately in the selected disposable host.

To exercise ParticleVE's materialized layout, mount the matching Fedora factory
PKI subtree read-only, apply the generated `particleve-ca-trust.conf`, and run the
matching compiled extraction helper before starting the probe. Pass its path as
`--system-trust-helper HELPER`; every refresh then uses that native helper. Keep
the factory mount distinct from the container's local source and volatile output
directories. Verify the native unit ordering and the chrony-UID session boundary
in the same fixture, then test the daemons under PID 1 and SELinux in the selected
signed-image fixture.

In the same disposable materialized layout, run
`Tests/acceptance/source-trust.py --system-trust-helper HELPER --confirm-disposable-container`
with `PYTHONPATH=Sources:.`. Fedora's `git-core` supplies the native HTTP backend.
This probe serves ephemeral public Git objects over loopback TLS, fetches their
exact commit and checks the contents. It exercises CA addition, removal, distrust,
expiration, wrong names, stale outputs, redirect refusal and injected Git/SSL
configuration. Source pins remain checked independently of transport trust.

### Disposable UEFI trust transitions

[`uefi-trust.py`](../Tests/acceptance/uefi-trust.py) builds the
[`EFI controller and candidate probes`](../Tests/acceptance/efi-trust.c) for
OVMF. Preparation needs the supported Fedora GCC/gnu-efi toolchain, OpenSSL,
sbsigntools, pesign, virt-firmware, mtools, dosfstools and util-linux. Run preparation in a
disposable tool environment. Select a matching current 4-MiB Secure-Boot-capable
OVMF code image and blank variable template; the probe copies both into a new private
directory and never updates their originals.

```sh
mkdir -m 0700 /tmp/particleve-uefi-inputs
qemu-img convert -f qcow2 -O raw \
  /usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.qcow2 /tmp/particleve-uefi-inputs/code.fd
qemu-img convert -f qcow2 -O raw \
  /usr/share/edk2/ovmf/OVMF_VARS_4M.qcow2 /tmp/particleve-uefi-inputs/vars.fd
python3 Tests/acceptance/uefi-trust.py prepare \
  --firmware-code /tmp/particleve-uefi-inputs/code.fd \
  --firmware-vars /tmp/particleve-uefi-inputs/vars.fd \
  --work-directory /tmp/particleve-uefi-trust
unshare --user --map-root-user --mount --fork --kill-child \
  python3 -W error Tests/acceptance/uefi-trust.py run \
    --work-directory /tmp/particleve-uefi-trust --usb-controller ehci
python3 -W error Tests/acceptance/uefi-trust.py inspect \
  --work-directory /tmp/particleve-uefi-trust
```

The run phase requires QEMU/KVM, util-linux and an isolated development host with
KVM access and memory headroom. It refuses an ordinary host-root namespace.
Each 512-MiB VM exposes only copied firmware and a private read-only disk with a GPT ESP;
no OS, TPM, host installation disks or network is attached. QEMU process/file
limits and a bounded deadline contain failed probes. Fresh RSA4096 test keys
are removed before any VM boots; public certificates and artifacts remain for
inspection.

The 18 cases cover certificate introduction, overlap, removal, certificate
revocation and Authenticode-hash revocation, including virtual USB media.
Select `--usb-controller xhci` or `ehci` explicitly for the interface under test;
the default is xHCI and the example selects EHCI. Use a separate prepared fixture
for each controller. The result names that controller; a successful run does not
establish another controller's boot/discovery behavior. There is no automatic
controller substitution after a failure.
The independently trusted controller checks Secure Boot/User Mode, records the
firmware's exact `LoadImage` result, checks candidate execution and continues
after a refusal. The inspect phase reads back effective `PK`, `KEK`, `db` and
`dbx` from every completed variable store. Inputs and read-only images must
retain their hashes. Provisioning uses private offline variable editing; this
does not test authenticated variable-update transports, physical firmware,
encrypted owner recovery or a complete signed-image transition. Those belong
to the [release acceptance matrix](ReleaseDiagnostics.md#trust-transition-acceptance).

### Scoped allocator components

[`Tests/acceptance/allocator/`](../Tests/acceptance/allocator/) contains the
pinned hardened_malloc evaluation inputs. The source preparer uses the system
CA store, checks the exact signed upstream tag and commit against the reviewed
public SSH signer, and verifies the canonical archive hash:

```sh
mkdir -m 0700 /tmp/particleve-allocator-rpm
PYTHONPATH=Sources:. python3 -W error Tests/acceptance/allocator/prepare.py \
  --output /tmp/particleve-allocator-rpm/SOURCES
rpmbuild -ba --define '_topdir /tmp/particleve-allocator-rpm' \
  /tmp/particleve-allocator-rpm/SOURCES/rpm.spec
```

Build in a disposable Fedora environment with the recipe's declared dependencies.
Both upstream default and light variants retain C++ allocation support, strict
diagnostics and Fedora flags, with explicit x86-64-v2 targeting and native CPU
tuning disabled. The narrow ChaCha pointer-lifetime patch has a comparison
against the unmodified tagged implementation at block boundaries and counter
carry. The upstream corruption suite covers the default variant; it does not
establish equivalent coverage for light.

Set `ALLOCATOR_BINARY_RPM` and `ALLOCATOR_SOURCE_RPM` to the resulting normal
binary and source RPM paths. Inspect their exact source, recipe, patch and
installed-library bytes after normal RPM processing:

```sh
python3 -W error Tests/acceptance/allocator/inspect.py \
  --rpm "$ALLOCATOR_BINARY_RPM" --source-rpm "$ALLOCATOR_SOURCE_RPM" \
  --output /tmp/particleve-allocator-rpm/payload.json
```

This inspection checks local RPM digests, ELF hardening and the passive `/usr`
payload. It does not authenticate an OBS signature or establish verified-image
delivery. The package installs no global preload, sysctl or service policy.
Keep its public source and inspection records with the build evidence.

For component measurements, use a separately selected disposable Fedora QEMU
recovery VM with enforcing SELinux, PID 1, GCC, QEMU, swtpm and util-linux.
Install the reviewed evaluation RPM there, checking its exact hash and installed
file digests. Stage the allocator probe directory, matching inspection record
and compiled probe under `/run/particleve-allocator`, owned by root and readable
but not writable by the probe UID:

```sh
gcc -std=c23 -O2 -fno-builtin -Wall -Wextra -Werror \
  -fstack-protector-strong -fcf-protection=full -Wl,-z,relro,-z,now \
  /run/particleve-allocator/allocation-probe.c -pthread -ldl \
  -o /run/particleve-allocator/allocation-probe
python3 -W error /run/particleve-allocator/components.py \
  --expect-machine-uuid "$DISPOSABLE_VM_UUID" \
  --allocation-probe /run/particleve-allocator/allocation-probe \
  --payload-record /run/particleve-allocator/payload.json \
  --output /run/particleve-allocator/result.json
```

The probe requires the exact DMI UUID and absence of an installed-host record.
It compares glibc, default and light in three interleaved rounds, recording
actual mappings, `malloc` resolution, RSS, mapping counts and timings. QEMU
initializes virtual block/network devices while paused, copies a private disk
through QMP, and exits. swtpm initializes a new private identity and answers a
TPM capability request. Children use an unprivileged UID with empty capability
sets; QEMU's seccomp sandbox remains enabled. Their recorded SELinux domains
must not be mistaken for the production vmspawn/MCS confinement contract.

Separate memory-limited units exercise `MemoryHigh` throttling and relief with
an unchanged 128-MiB hard cap, then a deliberate contained OOM. The probe removes
only its own units and files, preserves partial results on failure, and leaves
the global allocator and map-count policy unchanged. These small component
timings do not measure guest startup, guest disk/network performance, complete
authentication or maintenance, whole-host pressure, or the selected signed
image. Apply the [allocator adoption policy](Hardening.md#advanced-userspace-and-kernel-mitigations)
and full release matrix before selecting an allocator for host use.

The separate [`fwupd.py`](../Tests/acceptance/allocator/fwupd.py) probe exercises
the packaged fwupd service and its actual SELinux domain and seccomp policy.
It requires that service to be initially inactive. In the same prepared UEFI
component VM, with fwupd and its native dependencies installed, run:

```sh
python3 -W error /run/particleve-allocator/fwupd.py \
  --expect-machine-uuid "$DISPOSABLE_VM_UUID" \
  --payload-record /run/particleve-allocator/payload.json \
  --output /run/particleve-allocator/fwupd-result.json
```

Nine interleaved cases compare glibc, default and light through native service
starts and matching CLI/D-Bus device discovery. A temporary runtime drop-in
selects only the allocator; the probe checks actual mappings, process authority
and unchanged confinement properties. It records the effective `AT_SECURE`
value rather than assuming the loader honored the environment. After stopping
the daemon, it restores the original unit, verifies the shared CA bundle and
selected firmware boot/trust-variable fingerprints, and removes its override.
The startup and resource observations describe discovery in the selected
virtual fixture. Firmware installation, transport compatibility and subsequent
recovery follow the separate [supervised procedure](Operations.md#supervised-firmware-maintenance).

### Native probes with compiled helpers

Build the test-only driver through `make test` on the supported toolchain before
staging it into a disposable fixture. Keep the source revision and binary hash
with its evidence. It exposes privileged library operations for tests and is
never installed by the host or initrd RPMs. Stage it as a root-owned executable
without other-account writes under a private `/run` directory in the selected
fixture; do not install it as a production management interface.

Run each Python harness with `PYTHONPATH=Sources:.` from the matching reviewed
checkout. These probes call the compiled Rust implementation:

| Probe | Required compiled input and fixture |
| --- | --- |
| [`management-network.py`](../Tests/acceptance/management-network.py) | `--runtime-driver /run/particleve-tests/runtime-contract-driver`; a disposable installed host, native networking and reviewed VM state. |
| [`storage-service.py`](../Tests/acceptance/storage-service.py) | The storage-watch service file as its positional argument and `--runtime-driver`; a disposable installed systemd/firmware-witness fixture. |
| [`storage-member-counters.py`](../Tests/acceptance/storage-member-counters.py) | `--runtime-driver`; a disposable root fixture with Btrfs-backed `/var/tmp` and loop/device-mapper support. |
| [`radio-policy.py`](../Tests/acceptance/radio-policy.py) | `--expect-installation`, reviewed `--source-dir` and `--runtime-binary` under `/run`; an isolated QEMU component fixture with the native RFKill units, no installed radio-policy service and no exposed radios. Use the matching RPM's compiled radio helper. |

The startup descriptor/ACL comparison runs separately as
`PYTHONPATH=Sources:. PVE_RUNTIME_DRIVER=DRIVER python3 -m Tests.runtime.startup-contract`
inside an isolated uid-0 fixture with ACL tools. Read each harness's complete
prerequisites before execution. Component observations must identify staged
helpers and remain distinct from acceptance of the final signed image and its
installed service paths.

The [Landlock handoff probe](../Tests/runtime/landlock-handoff.py) takes
`--runtime-driver` and runs the compiled sender boundary in a separate,
unprivileged process on a system with the supported Landlock ABI. It creates its
own disposable directory, verifies inherited-descriptor closure and permitted
reads, and requires filesystem mutations to fail without changing retained data.
The parent process retains its original authority.

## CI coverage and reproduction

OBS source-service definitions and package recipes define the source inputs,
dependencies, checks, and signing stages. Use the failed build's exact source
revision, package identities, configuration, and diagnostics when reproducing it:

| Build or check | Coverage and local entry points |
| --- | --- |
| [GitHub source checks](../.github/workflows/check.yml) | Digest-pinned Fedora container, pinned Rust packages and Ruff, native Fedora Python, `make check`, upstream pin/patch verification and resolved image configuration. A passing `main` push can select system changes for OBS. |
| [Host, initrd and build-tools RPMs](../.obs/particleve/rpm.spec) | Offline locked Rust build, strict formatting/Clippy, Rust and Python tests, SELinux policy compilation, and final ELF payload identity after normal RPM transformations. |
| [Pinned mkosi RPM](../.obs/mkosi/mkosi.spec) | Exact upstream, recipe, and patch identity; installed-payload records; shell syntax checks for the OBS signing continuation. |
| [fwupd EFI helper RPM](../.obs/fwupd-efi/fwupd-efi.spec) | Compiler diagnostics, retained SBAT/SBOM sections, payload identity, and separate PE signing. |
| [Kernel RPM](../.obs/kernel/kernel.spec) | Pinned Fedora/secureblue sources, selected configuration, normal Fedora transformations, module-body identity, and native OBS PE/module signing. |
| [Image build](../.obs/fedora/x86-64/mkosi.conf) | Runtime/initrd/tools dependencies, package origins, installed identities, security inventory, and required kernel, storage, and KVM support. |
| [Signing and publication](Build.md#signing-and-release-publication) | Final UKI, bootloader, verity, and firmware-helper signatures; complete release manifest and authenticated index. |
| [Publication observer](../Tools/check-publication.py) | Read-only observation of source/build/feed consistency, Fedora and secureblue upstream freshness, and stalled updates; see [publication monitoring](Build.md#publication-monitoring-and-trust-boundary). |

The [`.obs/`](../.obs/) source services follow the configured branch; Fedora and
stable systemd package changes trigger builds through OBS's dependency graph.
Pinned upstream inputs change through their reviewed source and packaging
updates. The generated dependency definition comes from all three mkosi trees.

OBS runs the checks declared in each recipe. The ParticleVE recipe runs offline
Rust formatting, Clippy, Rust tests and Python unittest; contributor Ruff checks
run through `make check` locally and in GitHub Actions. The source-selection
workflow and versioned changelogs are described in
[Build](Build.md#versions-and-source-selection). Missing, skipped, or unavailable
checks are not evidence that they passed; record required local results.

Image building and publication do not run every native acceptance case or
commission a physical host. Run the selected signed-image and hardware checks
from the release and commissioning guides, and retain their matching evidence.
Firmware installation remains a supervised hardware procedure.

## Reclaiming build space

Stop builds, tests, and diagnostic VMs using the outputs before removing them.
Check custom path overrides too. Inspect sizes without changing anything:

```sh
du -sh build mkosi.output mkosi.cache mkosi.tools
```

Some paths exist only after their first build. Inspect the directories present
in this checkout and any configured alternatives.

| Location | Cleanup consequences |
| --- | --- |
| `build/sources/` | Pinned upstream checkouts; removing them requires refetching. Preserve any separate patch-development work first. |
| `build/summary.json`, `build/obs-project/`, `build/obs-packages/` | Regenerable configuration and source archives. Save inputs needed to reproduce an unresolved build. |
| `mkosi.cache/`, `mkosi.tools/`, and configured cache paths | Build cache and tools tree. Removing them requires rebuilding the affected outputs. |
| `mkosi.output/`, `build/local-image/`, and configured output paths | Built images and artifacts. Preserve releases and matching verification evidence before removal. |
| `.venv/`, `.ruff_cache/`, Python bytecode, `dist/`, and `*.egg-info/` | Local development environments and rebuildable packaging state. |
| `target/` and configured Cargo targets | Rebuildable Rust binaries, tests and driver artifacts. Preserve copies and hashes needed by an active fixture before removal. |
| `build/acceptance/`, commissioning records, and failure reproductions | Retained test evidence and investigation material. Preserve unresolved failures, source/image identities, and useful measurements. |
| Signing keys, recovery material, and credentials | Private inputs, **not disposable cache**. Preserve them outside the checkout according to their ownership and recovery requirements. |

Avoid treating all ignored files, or all of `build/`, as cache. A blanket
`git clean -xfd` would also remove retained evidence and local investigation
artifacts. Reclaim specific outputs after reviewing their contents, then rebuild
with the normal tools. Build cleanup must not touch the
[host's persistent state or VM storage](Troubleshooting.md#data-ownership-and-preservation).
