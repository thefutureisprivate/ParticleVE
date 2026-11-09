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
The integration and build-tools RPMs also carry an implementation-content identity
and hashes of their installed payloads. The image checkout computes the expected
identity from runtime modules, helpers, policy sources, trust and packaging inputs.
Both RPMs must match before image generation; final signing checks their payloads
again before publishing a manifest. A failed or delayed independent source webhook
therefore cannot publish new implementation inputs with an old coordinator or
signing helper. Documentation-only changes retain the same implementation identity.
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

`make summary` resolves and checks the three build trees; it does not build an
image. The configuration tools write public generated inputs. Review those
changes before publishing the source revision that OBS will build.

## OBS dependencies and package builds

The generated `.obs/fedora/x86-64/mkosi.conf` schedules dependencies from all three
resolved trees. OBS builds the checkout's root `mkosi.conf`, supplies the advancing
`CI_CNT.B_CNT` image version, and rebuilds on transitive dependency changes.
`.obs/` supplies the pinned mkosi, integration/build hooks and separately
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

Fedora's kernel packages are normal image dependencies. Updates imported from
the configured Fedora repositories trigger OBS image rebuilds through the same
transitive dependency graph. Fedora supplies the kernel configuration, patches,
and matching modules; ParticleVE records exact package identities and checks
the resulting UKI, initrd, module tree, and required host capabilities. Kernel
updates use the ordinary signed-image publication and guarded host activation
path. A failed build or verification leaves the last usable release intact and
is reported by publication monitoring.

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

## Source updates and uploads

The signed implementation and upstream Git history have been published.
The source repository is `https://github.com/thefutureisprivate/particleve`, branch
`main`. The three `.obs/*/_service` definitions track that branch and extract the relevant
recipes. Integration tarballs are created by native OBS source services; pinned
upstream mkosi/fwupd sources are downloaded from their immutable GitHub commit
URLs. Four package-scoped source-service webhooks avoid granting OBS a GitHub
personal access token. Dependency rebuilds use OBS's native repository graph.
No permanent external runner is required.

Historical verification: all four GitHub registrations triggered an automatic
refresh to commit `fd52ed982ddb80f8163aa70dd8f35a7ecb1fdf23`. That observation
establishes the tested source-refresh path; check current delivery, package, and
image results independently when diagnosing a later publication.

`Tools/obs-upload.py` commits reviewed source directories atomically. Its
credential file is two lines (OBS username/password), mode 0600; credentials are
sent only to `api.opensuse.org`, redirects are refused, and no credential is
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

The observer directory must be private to that user. The check reads the declared
GitHub branch, all four native OBS source-service revisions, the required package
build states and project/package maintainer metadata. It verifies the feed's GPG-signed
index and indexed manifest, then checks HTTPS availability and declared size for
all six artifacts. HTTP downgrade redirects are rejected. Availability checks do
not replace full payload hashing and PE/verity verification by the normal release
client. The check has no OBS/GitHub write credential and cannot promote, replace
or withdraw a release.

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
detects deviation from that policy. The four source-service
tokens are scoped to their individual packages and require no GitHub personal
access token. There is no external CI workflow dependency. The image builder
requires repository access to resolve its declared RPMs; this configuration does
not claim an offline or independently network-isolated image worker. Restrict
operator access and protect signing/trust/recipe changes in the source and OBS
accounts. Hardware-backed Git signing has been exercised; account-wide strong
authentication and credential recovery remain owner-controlled commissioning
evidence, rather than properties inferred from public repository metadata.
