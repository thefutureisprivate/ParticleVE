# Development

Run commands from the repository root. Read the [contributor guide](../CONTRIBUTING.md)
and use the [pinned toolchain](Toolchain.md); these workflows do not replace the
required verification for a change. Distribution builds have a separate
[release procedure](ReleaseDiagnostics.md#preparing-a-release).

## Local builds

Use a Linux development environment with Python 3.14 or newer, Ruff, Git, GNU
Make, Bash, GnuPG, OpenSSL, and the OpenSSH client tools. The source tests use
`ssh-keygen` to check actual public-key parsing. Image builds also need the native
tools and project packages described in [build and publication](Build.md) and
the [mkosi RPM recipe](../.obs/mkosi/mkosi.spec). The runtime, initrd, and image
tools use Fedora 45, Fedora's kernel packages, and the selected stable systemd
package family.

Check the source and prepare the pinned build inputs:

```sh
make check
make sources
PYTHONPATH=Sources:. python3 Tools/configure-build.py --site .obs/site.json
make summary
```

`make sources` fetches the mkosi and fwupd-efi revisions in
[`sources.lock.json`](../sources.lock.json). This checkout is the ParticleOS
fork; its recorded upstream revision is provenance, not another tree to download.
Existing source checkouts must match their pins and have clean worktrees.
`configure-build.py` validates public trust and generates repository, initrd,
and image inputs. Review those tracked changes. `make summary` resolves and
checks the configuration of all three trees before image generation.

For a local signed image, first make the matching ParticleVE integration,
build-tools, pinned mkosi, and fwupd-efi RPMs available to the selected build
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
| Source checks | `make check` | Lint, formatting, shell syntax, and unittest results. |
| Resolved image configuration | `make summary` | `build/summary.json`. |
| Local signed image | `build/sources/mkosi/bin/mkosi --force build` | `mkosi.output/ParticleVE_<version>_x86-64*`. |
| OBS dependency configuration | `PYTHONPATH=Sources:. python3 Tools/obs-project.py --site .obs/site.json --summary build/summary.json` | `build/obs-project/` and `.obs/fedora/x86-64/mkosi.conf`. |
| Image and integration package sources | `PYTHONPATH=Sources:. python3 Tools/prepare-obs.py --tree HEAD` | A fresh `build/obs-packages/`. |

`prepare-obs.py` archives the exact Git commit or tree object supplied through
`--tree`; using `HEAD` excludes uncommitted edits. Source preparation does not
upload or publish a release. The normal OBS source services also prepare the
separately pinned mkosi and fwupd-efi packages.

## Incremental work and isolated outputs

The image configuration enables mkosi's incremental cache. The project checks
source identities, recipes, patches, installed package payloads, and image
policy before accepting the build. Running the normal builder after preparing
matching packages is the ordinary incremental workflow. For a Python-only
iteration that does not need an image, run the affected source suite directly:

```sh
PYTHONPATH=Sources:. python3 -W error -m unittest Tests.test_coordinator -v
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
| `Tools/prepare-obs.py --output` | Prepared source packages; defaults to `build/obs-packages`. Its image and integration output directories must be fresh. |
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

## Tests and diagnostics

The [required-check matrix](../CONTRIBUTING.md#required-verification) is
authoritative. These are the common local entry points:

```sh
make lint
make test
make check
```

`make lint` runs Ruff checks, Ruff formatting checks, and Bash syntax checks for
the listed image, initrd, shutdown, and EFI-fixture scripts. `make test` runs
Python unittest discovery with warnings treated as errors. `make check` runs
both. These source checks do not require building an image first.

For a focused regression, select the relevant unittest modules:

```sh
PYTHONPATH=Sources:. python3 -W error -m unittest \
  Tests.test_coordinator \
  Tests.test_storage_admission \
  Tests.test_vmrun -v
```

Python is the normal language for policy tests, failure injection, and native
acceptance orchestration. Small shell fixtures exercise shell interfaces or
build native test payloads. Keep the required whole-change checks alongside
focused iterations; selecting a module does not run Ruff or the shell checks.

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
| Update interruption, guest shutdown, and restoration | [`test_coordinator.py`](../Tests/test_coordinator.py), [`test_vmrun.py`](../Tests/test_vmrun.py), and [repeated lifecycle tests](ReleaseDiagnostics.md#repeated-lifecycle-tests). |
| Disk admission, stale members, and recovery | [`test_storage_admission.py`](../Tests/test_storage_admission.py), [`test_accounts_storage.py`](../Tests/test_accounts_storage.py), and [bootloader and mirror recovery](Commissioning.md#bootloader-and-mirror-recovery). |
| Guest authority and SELinux confinement | [`test_confinement.py`](../Tests/test_confinement.py) and [QEMU containment](Hardening.md#qemu-containment). |
| Native networking, kernel interfaces, and device policy | [`Tests/acceptance/`](../Tests/acceptance/), [hardening](Hardening.md), and the selected probe's arguments and prerequisites. |
| EFI loader failure and fallback | [`build-loader-probe.sh`](../Tests/acceptance/build-loader-probe.sh). |
| Final signed-image and hardware behavior | [Release diagnostics](ReleaseDiagnostics.md) and [commissioning](Commissioning.md). |

Measurements are diagnostic. They do not replace correctness assertions or
establish VM capacity from an idle host or isolated fixture. Record the actual
source, image, fixture, configuration, results, and coverage limits.

## CI coverage and reproduction

OBS source-service definitions and package recipes define the source inputs,
dependencies, checks, and signing stages. Use the failed build's exact source
revision, package identities, configuration, and diagnostics when reproducing it:

| Build or check | Coverage and local entry points |
| --- | --- |
| [Integration RPM](../.obs/particleve/rpm.spec) | Python unittest with warnings as errors and SELinux policy compilation. Source checks use `make check`; the package build also verifies its native build requirements. |
| [Pinned mkosi RPM](../.obs/mkosi/mkosi.spec) | Exact upstream, recipe, and patch identity; installed-payload records; shell syntax checks for the OBS signing continuation. |
| [fwupd EFI helper RPM](../.obs/fwupd-efi/fwupd-efi.spec) | Compiler diagnostics, retained SBAT/SBOM sections, payload identity, and separate PE signing. |
| [Image build](../.obs/fedora/x86-64/mkosi.conf) | Runtime/initrd/tools dependencies, package origins, installed identities, security inventory, and required kernel, storage, and KVM support. |
| [Signing and publication](Build.md#signing-and-release-publication) | Final UKI, bootloader, verity, and firmware-helper signatures; complete release manifest and authenticated index. |
| [Publication observer](../Tools/check-publication.py) | Read-only observation of source/build/feed consistency and freshness; see [publication monitoring](Build.md#publication-monitoring-and-trust-boundary). |

The [`.obs/`](../.obs/) source services follow the configured branch; Fedora and
stable systemd package changes trigger builds through OBS's dependency graph.
Pinned upstream inputs change through their reviewed source and packaging
updates. The generated dependency definition comes from all three mkosi trees.

OBS runs the checks declared in each recipe. The integration RPM's unittest
stage does not run the contributor's Ruff checks, and this checkout has no
separate GitHub Actions workflow. Missing, skipped, or unavailable checks are
not evidence that they passed; record required local results.

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
| `build/acceptance/`, commissioning records, and failure reproductions | Retained test evidence and investigation material. Preserve unresolved failures, source/image identities, and useful measurements. |
| Signing keys, recovery material, and credentials | Private inputs, **not disposable cache**. Preserve them outside the checkout according to their ownership and recovery requirements. |

Avoid treating all ignored files, or all of `build/`, as cache. A blanket
`git clean -xfd` would also remove retained evidence and local investigation
artifacts. Reclaim specific outputs after reviewing their contents, then rebuild
with the normal tools. Build cleanup must not touch the
[host's persistent state or VM storage](Troubleshooting.md#data-ownership-and-preservation).