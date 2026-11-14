# Build and publication

This checkout is the ParticleOS fork. Build it directly; no overlay composition
or second ParticleOS download is required. Read the
[contributor guide](../CONTRIBUTING.md), use the [toolchain baseline](Toolchain.md),
and run commands from the repository root. Local iteration and source checks are
described in [Development.md](Development.md); release preparation and retained
evidence are described in [ReleaseDiagnostics.md](ReleaseDiagnostics.md).

## Source and payload identities

[`sources.lock.json`](../sources.lock.json) pins the upstream
base, mkosi revision and fwupd-efi. Fedora 45 and the upstream stable systemd
repository apply to runtime, initrd and build tools. Installed RPM origins and
family versions are checked during the build, rather than inferred from names.
The host, initrd and build-tools RPMs also carry an implementation-content identity
and hashes of their installed payloads. The image checkout computes the expected
identity from runtime modules, helpers, policy sources, trust and packaging inputs.
All three RPMs must match before image generation; final signing checks their payloads
again before publishing a manifest. A failed or delayed independent source webhook
therefore cannot publish new implementation inputs with an old coordinator or
signing helper. Documentation-only changes retain the same implementation identity.

The shared [RPM recipe](../.obs/particleve/particleve.spec) produces three components:

| RPM | Installed role |
| --- | --- |
| `particleve` | Native host CLI, service helpers, VM handoffs, SELinux policy and public signing trust. |
| `particleve-initrd` | Native storage admission, initrd assembly and shutdown witness helpers, used by both the host and initrd. |
| `particleve-build-tools` | Python artifact verification and metadata assembly in the image build environment. |

The host package requires its matching initrd subpackage. The initrd installs
only the early-boot component and its native dependencies. Python build tools
and test harnesses are not installed as host or initrd runtime helpers.

The `particleve:allocator` flavor builds the pinned GrapheneOS hardened_malloc
default library independently of the Rust RPM. Host and initrd both install it;
the tools tree keeps its distribution allocator. Its signed upstream tag, archive
checksum, patch and recipe are checked before compilation, and its transformed
library identity is checked again in the image and final initrd. The existing
ParticleVE package-scoped source-service token covers this flavor.

Renovate proposes allocator release tags after the dependency cooldown. Review
the selected version, then run
`PYTHONPATH=Sources:. python3 -m Tools.allocator_source --refresh` to authenticate
its upstream SSH-signed tag and refresh the commit, epoch and archive checksum.
Review the lock and recipe together. `make check-upstream` rejects stale or
mismatched signed provenance; the RPM checks its downloaded archive against
that lock too.

Runtime dependencies are vendored by the pinned native Cargo during checked
source publication from the reviewed `Cargo.lock`, with dependency updates
disabled. The source release carries the locked vendor archive. Publication
verifies its lockfile and GitHub's asset digest before advancing the OBS build
ref. Assets are attached and verified in a draft before publication locks the
release; retries resume that draft, and an existing asset must match and is
never overwritten. Publication retains the ID returned when a draft is created
and addresses uploads and publication by that ID; it does not require a newly
created draft to be visible in the release list. OBS downloads that
archive through its native `download_files` service. RPM builds and
checks run offline using the pinned Rust toolchain. Native ELF identities are
recorded after Fedora's ordinary stripping and debug-information processing;
upstream dependency license and notice texts accompany the runtime packages.
The worker reconstructs and compresses the source archive from the SCM snapshot
using buildtime `tar` and `recompress` services. The worker needs no network
access, and source preparation uses only services installed on the OBS server.
The independently built mkosi and fwupd-efi RPMs also carry their own upstream
pin, recipe and patch identities, plus installed-payload hashes. Their build
records are produced after Fedora's BRP transformations. The source service keeps
an unmodified recipe under a separate `.recipe` filename, so OBS's advancing RPM
build counter cannot rewrite that source input or duplicate the source RPM's spec
entry. Every original recipe byte, source URL/revision, patch byte and the identity
generator must match. Exact built package EVRs remain in release provenance.
Image generation checks each package against the image checkout, and final
signing checks both packages again. The signed manifest includes these source
identities. Including a recipe in the integration digest alone is insufficient.

For the EFI executable, payload verification uses the SHA256 Authenticode digest,
which excludes the checksum and certificate table changed by off-host signing.
The existing project-certificate verification independently checks its attached
signature. Other payload bytes and symlink targets must match exactly, including
mkosi's Python modules, resources and bytecode. A delayed upstream-package source
refresh therefore fails publication even when the integration packages match.
The final EROFS payload is also checked for retained boot/storage and Intel/AMD
KVM drivers, including built-in driver metadata, after mkosi's module filtering.
Module selectors use the pinned mkosi's glob syntax; directory selectors end in `/`.

## Public build configuration

[`.obs/site.json`](../.obs/site.json) contains the owned project, source branch, package repository and
single image feed. `Tools/configure-build.py` validates public trust and generates
tracked repository and image inputs. It never imports private keys. Local builds
use normal mkosi signing options with private keys outside this checkout. OBS
builds automatically select mkosi's native deferred-signing integration.

```sh
make sources
PYTHONPATH=Sources:. python3 Tools/configure-build.py --site .obs/site.json
make summary
PYTHONPATH=Sources:. python3 Tools/obs-project.py --site .obs/site.json --summary build/summary.json
```

`make summary` resolves and checks the three build trees and requires the tracked
OBS dependency recipe to match them. It does not build an image or regenerate
tracked files. If dependencies changed, use its new `build/summary.json` with
`Tools/obs-project.py` as shown above, then rerun `make summary`. Review generated
inputs before publishing the source revision that OBS will build.

Source fetching and upstream-tag checks use native Git with the distribution CA
bundle and directory. They enforce certificate verification, ignore per-user Git
configuration and disable inherited repository selection and replacement objects.
Only HTTPS source URLs without embedded credentials are accepted; URL rewrites
and redirects are refused. Install any required CA in the system store; a
tool-specific bundle does not change source trust. Immutable revision, release-tag
and patch checks remain independent of transport authentication.
Cargo vendoring selects the same system bundle for source and HTTPS-proxy
connections, overriding inherited Cargo-specific CA paths.
The GitHub release tool likewise selects the distribution trust paths for its
GitHub CLI child and fixes the publication host to `github.com`.
Workstation network policy lives in [`Tools/trust.py`](../Tools/trust.py), outside
the installed build-verification library, so changes confined to these tools
follow the ancillary-change rule below.

## OBS dependencies and package builds

The generated `.obs/fedora/x86-64/mkosi.conf` schedules dependencies from all three
resolved trees. OBS builds the checkout's root `mkosi.conf`, supplies the advancing
`CI_CNT.B_CNT` image version, and rebuilds on transitive dependency changes.
`.obs/` supplies the pinned mkosi, host/initrd/build-tools recipe and separately
PE-signed fwupd helper. The pinned mkosi RPM requires the build-tools subpackage,
so OBS installs the final-verification and native signing tools in its worker;
image `BuildPackages=` alone schedules downloads without installing those tools.
The mkosi patch repairs its native signing continuation: it regenerates stale
split partitions after verity signing, copies each artifact once, and handles
absent optional signature classes without diagnostics or empty signing rounds.
The exact upstream patch application, shell syntax, and file-backed partition
regeneration have focused checks; the full signing path is an OBS release gate.
The helper's one documented patch changes a successful
SBOM linker-selection message from warning to informational; compiler warnings
remain fatal, and SBOM/SBAT sections are checked.

The [kernel recipe](../.obs/kernel/kernel.spec) builds the selected Fedora kernel
sources and packaging with the reviewed secureblue configuration and patch set.
The [policy](../.obs/kernel/policy.json) records explicit deviations, including
retained Fedora built-in trust and off-host OBS signing. The image repository
selects the four matching runtime kernel packages from the owned OBS project;
the build rejects mixed versions and missing source/payload records.

Renovate reads Fedora's release and stable-updates source RPM repositories and
the advertised secureblue branch. A Fedora update requests the published RPM
version through the generated source manifest; a branch tip does not select the
Fedora release. The trusted-base updater resolves Koji's immutable Fedora commit,
authenticates the published SRPM with the selected Fedora release's native RPM
key, and compares every source file and lookaside archive against that commit.
It never executes an upstream recipe with repository write authority.

Only after those checks does the updater regenerate the source lock, public
recipe, configuration, source manifest, services and image source metadata, then
check the exact generated commit. Dependent images rebuild through OBS's normal graph.
Kernel updates retain Fedora's version cadence and use the ordinary signed-image
publication and guarded host activation path. Failed checks leave the last usable
release intact.

The kernel source package also builds the independent `kernel:build-policy`
flavor. Its small `particleve-kernel-build` RPM sets the worker's required PAM
resource limit and is absent from deployed images. It does not inherit the host
RPM's version or build counters. Host-only source changes therefore reuse the
kernel; changed kernel inputs or relevant build dependencies still rebuild it.

Kernel identity is recorded after Fedora's debug and strip transformations.
Image and final-signing checks compare the reviewed source manifest, resolved
configuration, kernel PE body, module bodies and signatures. The build-tools RPM
carries the expected source manifest, so a stale verification package cannot
approve a different kernel pin. From source version `45.0.3.0`, UKI inspection
also requires the embedded kernel hash and release name to match the verified
kernel package and module tree. Retained earlier images keep their existing
inspection and recovery contract.

Final signing also verifies the actual UKI initrd. The
[bounded archive reader](../Sources/particleve/kernelinitrd.py) handles the newc
and Zstandard archives emitted by the pinned mkosi configuration. It checks the
native admission/shutdown helpers against their RPM payload record and compares
early-boot units, public PCR authorization key, assembly masks and shared policy
against the source contract carried by the build-tools RPM. Parent symlinks are
resolved without unpacking them; duplicate security files, aliases and foreign
kernel trees are rejected.

Every initrd module must match verified userspace. Native kmod regenerates the
dependency indexes for that subset, and the verifier checks module signatures,
body identities and required boot drivers. The verified initrd hash and coverage
counts enter the release manifest; UKI inspection checks that hash before host
activation. These producer checks complement the signed-image boot and recovery
matrix in [release diagnostics](ReleaseDiagnostics.md).

## Signing and release publication

After the native signing stages attach verity, PCR and PE signatures, the final
hook verifies the root hash, partition payloads, UKI identity/security policy,
bootloader, fwupd helper and project certificate. It emits a versioned release
manifest alongside the six required artifacts. Signature payloads include NUL
padding to exactly 1 MiB; installed signature slots use that same fixed size.
This fully replaces stale contents on slot reuse, as required by the upstream
signature parser. The other OS partitions retain their configured growth margin.
OBS signs its native `SHA256SUMS`
index, covering the manifest and final artifact bytes. Clients authenticate that
index and the complete manifest before any disk write. There is no deployment
or promotion service. Interrupted/incomplete signing stages emit no release
manifest and therefore cannot become eligible releases.

## Public signing trust

Public signing identities:

- GPG fingerprint: `411E78DB29ECC8276328B3F526F1183EEA4C1F07`.
- EFI certificate SHA256:
  `7B:98:38:86:2B:14:3E:F0:69:E2:B2:70:0B:39:6B:9D:77:60:F0:16:F0:10:24:E3:0A:CD:8C:81:44:B0:6D:12`.
- Stable-systemd package GPG fingerprint:
  `CF496DFD918C8A3F55C56EBC713BF72732820778`.

The initial PCR authorization certificate uses RSA4096. Capability preflight
checks TPM support for that policy before disk changes; the TPM2 version alone
does not establish RSA4096 support.

These public files are in `mkosi.extra/usr/lib/particleve/trust/`. Enroll the
intended EFI certificate through owner-controlled firmware procedures. A future
rotation requires an explicitly reviewed overlap, signed releases trusted by the
installed key, both independent boot paths and TPM recovery testing; no implicit
trust migration is permitted. The rotation and image-retirement procedures keep
those authority changes explicit and preserve a usable owner recovery path.

## Versions and source selection

[`particleve.version`](../particleve.version) owns
`FEDORA_MAJOR.PVE_MAJOR.PVE_MINOR.PVE_PATCH`. A signed image appends both native
OBS counters: `FEDORA_MAJOR.PVE_MAJOR.PVE_MINOR.PVE_PATCH-OBS_CHECKIN.OBS_BUILD`,
for example `45.0.2.0-1.2`. The check-in counter starts at 1 for each new source
version; dependency rebuilds can advance the image counters without changing
the source version or Git revision. Local mkosi configuration uses the `-0.0`
suffix until the builder supplies its counters.

The default `particleve.spec` exposes the PVE source version to OBS's native
check-in tracking and builds the host, initrd and build-tools RPMs in
`Fedora_45`. The same source package builds the image in `Fedora_45_images`,
whose build type is mkosi. Only the allocator needs a separate flavor. Keep the
default RPM recipe under the source package's name so multiple recipes do not
hide its version or prevent OBS from rewriting its release metadata.

Use [`Tools/version.py`](../Tools/version.py) to advance a patch for fixes or a
minor for substantial features. PVE major changes require the owner's explicit
instruction. The tool synchronizes the image configuration, RPM and Python
metadata, Cargo manifest and lock. Cargo uses the three PVE components because
its package version has three fields. `make check` verifies these declarations
and the pinned Rust toolchain requirements together.

A Cargo dependency update, including a Renovate PR, requires a new source patch
before merging. Each immutable source release owns one exact `Cargo.lock` and
vendor archive. CI checks that identity before accepting the candidate and again
before preparing publication; it never replaces an earlier release's archive.

Reviewed development enters `main`. The
[source workflow](../.github/workflows/check.yml) runs `make check`, verifies
upstream pins and patches, and resolves the image configuration. For a passing
push to `main`, [`Tools/build_source.py`](../Tools/build_source.py) compares the
candidate tree with `build`. System-input changes advance that ref. Changes
confined to `Documentation/`, `Tests/`, `.github/` and the tool's other ancillary
paths stay on `main` and accompany the next selected system change. They do not
create a source release or request an OBS source rebuild by themselves.

The workflow publishes one GitHub Release for each full source version, tagged
`vFEDORA_MAJOR.PVE_MAJOR.PVE_MINOR.PVE_PATCH`, with commit notes since the previous
source release. [`Tools/source_releases.py`](../Tools/source_releases.py) prepares
the notes without publishing unless `--publish` is supplied together with the
latest source release's `--vendor-archive`. OBS image counters
do not create separate GitHub Releases.

Publication creates a missing source-version Git tag and verifies its exact
commit before creating the release from that existing tag. Annotated tags are
peeled and checked; an existing tag is never moved. Release creation does not
resend a historical target commit, which would invoke GitHub's separate workflow
permission check when its workflow files differ from the default branch.

## Source updates and uploads

The source repository and OBS ref are declared in [`.obs/site.json`](../.obs/site.json).
The four `.obs/*/_service` definitions follow `build`; the ParticleVE and kernel
packages' native SCM bridges also track that ref. The kernel bridge refreshes its
service definition with each checked source selection, keeping the pinned Fedora
and secureblue service revisions together with their recipe and source manifest.
Checked publication prepares and uploads
the exact locked vendor archive before advancing the ref; OBS downloads it and
creates the ParticleVE source tarball in the worker. The mkosi/fwupd services
extract their reviewed build inputs and download upstream sources at the locked immutable
commits. Package-scoped source-service credentials avoid a GitHub personal
access token. Dependency rebuilds use OBS's native repository graph.

The checked publication job requests source refreshes only for the commit
selected by `build`. It compares delivered source markers and component inputs,
so retries preserve completed deliveries and host-only changes preserve an
unchanged kernel or source-tool build. An active source service defers another
request until it completes. Direct push notifications are not used: the OBS
package-service endpoint does not filter the push branch.

[Renovate configuration](../.github/renovate.json) opens reviewed updates for the
mkosi/fwupd source pins and recipes, both kernel source pins, Cargo dependencies
and configured CI tools.
Renovate waits seven days before proposing ordinary dependency updates and
requires a release timestamp. The mkosi, fwupd-efi, Fedora kernel and secureblue
kernel source updates are excluded from this cooldown.
Automerge is disabled. Updates must retain matching locks, recipes, license
notices and required acceptance coverage; source checks alone do not qualify a
new signed image.

`Tools/obs-upload.py particleve` and `Tools/obs-upload.py kernel` configure the
Git-managed packages from the declared ref. For mkosi and fwupd-efi, the tool uploads
a reviewed source directory atomically; their service reads the current recipe
from that same checked ref before downloading upstream inputs. Its credential file is two lines (OBS username/password),
mode 0600; credentials are sent only to `api.opensuse.org`, redirects are refused,
and no credential is
written to sources. Keep this credential file and all private keys outside Git,
source archives, and image inputs.


## Publication monitoring and trust boundary

`Tools/check-publication.py` is a read-only check for an existing external
monitoring system. Run it as an ordinary dedicated observer user from a reviewed
checkout with its public trust files:

```sh
PYTHONPATH=Sources:. python3 Tools/check-publication.py --site .obs/site.json \
    --state-dir "$HOME/.local/state/particleve-publication"
```

The observer directory must be private to that user. The check reads `main`, the
selected build branch, native OBS source revisions, the ParticleVE RPM, mkosi, fwupd-efi,
kernel, its build-policy flavor when present, and image build targets, and
project/package maintainer metadata. A failed worker-policy build is reported
directly, including while the main kernel target waits on it.
Once observed, a missing flavor also fails observation.
It verifies the feed's GPG-signed
index and indexed manifest, then checks HTTPS availability and declared size for
all six artifacts. HTTP downgrade redirects are rejected. Availability checks do
not replace full payload hashing and PE/verity verification by the normal release
client. The check has no OBS/GitHub write credential and cannot promote, replace
or withdraw a release.

Host and image sources must match the selected commit exactly. Dependency
sources may retain an earlier commit when their recipes and selected inputs are
unchanged; the observer uses the same comparison as checked source refresh.
It fetches public Git history into a temporary private repository using native
Git and system CA trust. Unselected system changes on `main` remain pending
until checked source selection advances. A failed source workflow for that exact
development commit fails observation immediately; ancillary changes alone do
not require a release or rebuild.

A terminal or unknown build state fails immediately. A source/feed lag initially
reports `pending`; its default grace is two hours from the observer's first
pending observation. Preserved Git commit dates do not establish when a rewritten
head reached the source service. Private observer state also
bounds continuously pending dependency rebuilds, including transitions from
building to signing and fresh observer processes. A successful observation clears
the corresponding pending timer. Clock rollback, changed publication-policy
binding, malformed state, changed maintainer policy and unavailable metadata fail
observation. An unavailable observation preserves the preceding state. The JSON
result is bounded; `fail` and `unavailable` return a nonzero exit status. Schedule
it in the installation's existing monitor, alert on either result, and have that
receiver alert if no observation arrives within its independently selected
freshness interval. No permanent additional runner or production machine is
provisioned by this repository.
Give the observer job a two-minute runtime limit in that existing scheduler;
an unavailable or wedged HTTP peer must also become a missing observation.

The observer also reads the source lock and generated kernel manifest at the
exact selected repository commit. It compares Fedora's highest published stable
source RPM version and its Koji commit with that selection, and independently
reads secureblue's advertised branch. The Fedora observation checks bounded
primary metadata, including compressed and expanded hashes and sizes, from both
the release and stable-updates repositories. These HTTPS observations establish
availability; the updater's separate SRPM-signature and content verification
still establishes source authority before a pin changes.

An upstream mismatch uses the same grace period as other publication lag.
Further upstream updates do not restart its pending timer; matching sources
clear it. An unavailable upstream fails observation and preserves the previous
state. A stalled updater therefore remains visible even when OBS successfully
builds an unchanged pin. Observation never updates a source lock or selects a
release. The ordinary observer environment requires Python 3.14 or newer and
native Git using the system CA store.

The producer is the reviewed OBS project. Its source checkout, recipes, worker,
package repositories and signing continuation are in the trusted build boundary.
The signed index binds manifest and artifact bytes; the manifest identifies the
source revisions, implementation inputs, package recipes/payloads and resulting
OS contract. Final inspection checks those relationships against the actual
artifacts before publication. These are producer-authenticated claims, not an
independent attestation that a compromised worker behaved correctly. OBS retains
the signing private key outside the checkout and build recipes. Fedora and stable
systemd dependency refreshes continue through OBS's transitive repository graph;
pinned mkosi/fwupd recipe changes remain reviewed source changes.

Project policy grants maintenance to the declared owner alone; the observer
detects deviation from that policy. Source-service tokens are scoped to their
individual packages and require no GitHub personal access token. GitHub-hosted
CI selects checked source updates; OBS performs package/image builds and signing
without a permanently provisioned external runner. The image builder
requires repository access to resolve its declared RPMs; this configuration does
not claim an offline or independently network-isolated image worker. Restrict
operator access and protect signing/trust/recipe changes in the source and OBS
accounts. Hardware-backed Git signing has been exercised; account-wide strong
authentication and credential recovery remain owner-controlled commissioning
evidence, rather than properties inferred from public repository metadata.
