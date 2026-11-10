# Contributing to ParticleVE

These requirements apply to all contributors, human and agent. Start with the
[README](README.md) for product scope and build instructions. Agents must also
follow [AGENTS.md](AGENTS.md).

Use the [security policy](SECURITY.md) for vulnerability reports and the
[troubleshooting guide](Documentation/Troubleshooting.md) for supported recovery
and useful bug-report details.

## Design and compatibility

ParticleVE aims to be clean, elegant, and modern, with security as a first-class
principle. Make changes carefully with security hardening in mind.

- Choose the simplest implementation that fully meets the requirements. Avoid
  unnecessary features, redundant code, stopgaps, and accumulating workarounds.
  Fix the underlying problem and make architectural decisions for the long term.
- Target the modern platform and tools pinned in the
  [toolchain baseline](Documentation/Toolchain.md). Update that baseline
  deliberately; "latest" does not mean using an unverified local toolchain.
- Do not preserve compatibility with older platforms, toolchains, or APIs.
  Remove obsolete paths instead of adding compatibility layers or fallbacks.
  Any workaround for a current upstream defect must be documented and narrowly
  scoped. Deliberate boot fallback and owner recovery are current product
  requirements, not obsolete compatibility paths.
- Consider compatibility and migrations for persisted user data case by case,
  with explicit maintainer approval. Any retained migration must be narrow,
  documented, and tested. Dropping support for an old platform does not authorize
  discarding user data or silently changing its meaning.

The [coding standards](Documentation/CodingStandards.md) define language,
concurrency, ownership, and privileged-boundary requirements. Exceptions must be
narrow, documented, and tested. The
[architecture invariants](Documentation/Architecture.md#non-negotiable-invariants)
remain non-negotiable.

## Task reading map

The [documentation index](Documentation/README.md) lists all guides by purpose.
Before working on the project, read this guide, the README, the coding standards,
the toolchain baseline, and the opening architecture overview and invariants.
Then read the documents relevant to the area you will investigate or change:

| Area | Read before working |
| --- | --- |
| Rust runtime or initrd helpers | [Coding standards](Documentation/CodingStandards.md), [Toolchain](Documentation/Toolchain.md), and the compiled-test and native-fixture procedures in [Development](Documentation/Development.md#tests-and-diagnostics), plus the affected subsystem contracts below. |
| Module ownership, storage, encryption, or mirror admission | The affected sections of [Architecture and security decisions](Documentation/Architecture.md) and the storage procedures in [Operations](Documentation/Operations.md). |
| VM lifecycle, maintenance, bootloaders, or OS fallback | [Architecture](Documentation/Architecture.md), [Operations](Documentation/Operations.md), and the relevant [release diagnostics](Documentation/ReleaseDiagnostics.md). Read the tests for interruption, shutdown refusal, stale state, and recovery before changing these boundaries. |
| Guest isolation, SELinux, service authority, or kernel interfaces | [Hardening policy](Documentation/Hardening.md), the architecture invariants, and the relevant native fixtures under [Tests/acceptance](Tests/acceptance). |
| Administration, homed, FIDO2, or recovery credentials | [Operations](Documentation/Operations.md), [Hardening](Documentation/Hardening.md), and [Commissioning](Documentation/Commissioning.md). |
| Management networking, time, DNS, or external reporting | [Operations](Documentation/Operations.md), [Hardening](Documentation/Hardening.md), and the affected configuration schemas, runtime observations, and failure tests. |
| Native dependencies, kernel builds, patches, or hardening | [Toolchain baseline](Documentation/Toolchain.md), [Build and publication](Documentation/Build.md), and the affected sections of [Hardening](Documentation/Hardening.md). |
| Local builds, OBS reproduction, or cache cleanup | [Development](Documentation/Development.md), plus the affected recipes and scripts. |
| Source refresh, signing, or release preparation | [Build and publication](Documentation/Build.md) and [Release diagnostics](Documentation/ReleaseDiagnostics.md). |
| Installation, firmware, physical devices, or hardware acceptance | [Commissioning](Documentation/Commissioning.md), [Operations](Documentation/Operations.md), and the device-policy sections of [Hardening](Documentation/Hardening.md). |
| Boot, configuration, storage, or maintenance reports | [Troubleshooting and recovery](Documentation/Troubleshooting.md), then the linked architecture contracts and affected tests. |

The reading map routes work to the relevant contracts; it does not replace
reading the affected code, tests, and local invariant comments.

## Required verification

Run checks from the repository root using the supported scripts, which retain
the pinned toolchain and hardening settings. Apply every relevant row below;
additional risk-specific checks supplement the ordinary language checks.

| Change | Required checks |
| --- | --- |
| Rust runtime or initrd helpers | Run `make check` with the pinned Rust toolchain: formatting, Clippy with warnings as errors, Rust tests and the compiled contract driver used by Python tests. Exercise the affected native entry point and apply the relevant subsystem checks below. |
| Python source, tests, or first-party tools | Run `make check` with Python 3.14+ and the configured Ruff checks. Exercise the affected command's behavior as well as its unit tests. |
| Shell hooks, units, image configuration, or build settings | Run `make check` and, when image configuration or dependencies change, `make summary` with the pinned mkosi and configured public site inputs. Inspect generated dependencies and the affected native service behavior. |
| Storage, boot, TPM, update transactions, or persistent authority | Also exercise the affected disposable native acceptance cases, including interruption and failure paths, in the [release diagnostics](Documentation/ReleaseDiagnostics.md) and [commissioning matrix](Documentation/Commissioning.md). |
| SELinux, QEMU confinement, parsers, system interfaces, or untrusted input | Also run the relevant positive and negative native probes. Verify actual process authority and effective policy; a passing parser test or policy build does not establish runtime isolation. |
| Dependency recipes, patches, kernel changes, or signing | Exercise the affected package build, source/payload verification, resolved image configuration, and signed-artifact checks described in the [build guide](Documentation/Build.md). Run the affected recovery and compatibility cases before release. |
| Source refresh, publication, or reporting | Exercise the affected entry point and failure paths. Check stale builds, incomplete or mismatched artifacts, delivery failure, and receiver-side freshness as applicable. Observation alone must not deploy or promote a release. |
| Firmware, physical-interface policy, or supported hardware | Use the relevant supervised [commissioning procedures](Documentation/Commissioning.md). Record the actual hardware, transport, image, and recovery coverage; disposable fixtures do not establish physical-device acceptance. |
| Documentation only | Check local links and section anchors, command accuracy, and `git diff --check`. A rebuild or native acceptance run is not required when source and build settings are unchanged. |

Risk-specific entry points are documented in the
[development guide](Documentation/Development.md#tests-and-diagnostics),
[release diagnostics](Documentation/ReleaseDiagnostics.md),
[hardening policy](Documentation/Hardening.md), and
[commissioning guide](Documentation/Commissioning.md). Select coverage based on
the behavior and boundary changed. A wording-only change does not by itself
require a guest boot; a change to disk authority, privileged startup, or
concurrent maintenance does require the relevant additional checks.

Review every interpreter, compiler, analyzer, test, and script warning or error.
Do not suppress diagnostics merely to obtain a passing run. Follow the coding
standards for test design, including cancellation, races, malformed input, and
partial completion where relevant.

Before handing off a change, review its diff for correctness, unnecessary
complexity, and scope. Record the checks actually run and their results,
including configurations, reviewed diagnostics, and any required verification
that remains blocked or unperformed. Historical results in documentation do
not establish that a new change passes.

## Maintaining documentation

Keep each kind of guidance in its authoritative home:

- `README.md`: product orientation, capabilities, and build/test entry points.
- `CONTRIBUTING.md`: shared contribution policy, reading routes, and verification
  requirements.
- `Documentation/README.md`: index of documentation and tool guides.
- `Documentation/Development.md`: local build workflows, OBS coverage, and safe
  cleanup of generated artifacts.
- `Documentation/Troubleshooting.md`: supported user recovery and diagnostic
  collection, aligned with current behavior.
- `Documentation/ReleaseDiagnostics.md`: release preparation and evidence,
  lifecycle and recovery diagnostics, and hardware coverage requirements.
- `Documentation/CodingStandards.md`: shared engineering requirements.
- `Documentation/Toolchain.md`: supported versions, source pins, package and
  compiler-specific settings, and necessary build workarounds.
- `Documentation/Architecture.md`: authority boundaries, ownership, security
  invariants, and the reasoning behind cross-component decisions.
- `Documentation/Build.md`: source refresh,
  package and image builds, provenance, signing, and publication procedures.
- `Documentation/Operations.md` and `Documentation/Commissioning.md`: host
  operating procedures and installation-specific acceptance requirements.
- `Documentation/Hardening.md`: effective security policy, compatibility
  decisions, selected exceptions, and scoped native evidence.
- `AGENTS.md`: project character for agents, agent-specific workflow, and
  mandatory reading instructions.
- `SECURITY.md`: vulnerability-reporting routes and disclosure policy.
- `Documentation/ThirdPartyNotices.md`: attribution and license notices for
  reused documentation.

Document decisions, constraints, failure modes, and operational steps that are
hard to recover from code alone. Keep local `SAFETY:` and `PERF:` explanations
beside the code they justify. Avoid duplicating API catalogs, obvious control
flow, or the same policy in several files; link to the authoritative section.

Update or remove obsolete guidance as part of the change. Keep the documentation
index current when adding, moving, or removing guides. Rewrite the relevant
explanation instead of appending a running history of pull requests. Keep
temporary investigation notes and agent plans out of permanent project docs.
Retain historical verification or benchmark evidence when it explains a decision,
but label its date, source revision, configuration, method, and limitations.
Separate those observations from current requirements and reproducible commands.
Write product documentation for the completed, working system. Keep task
progress and implementation status in review records and conversation, rather
than presenting features as unfinished. Explain ownership and behavior without
requiring readers to know a migration phase or former implementation. Keep
historical evidence in labeled sections. Link to authoritative version/limit
definitions when repeating their values adds no useful context, and update
documentation indexes and build-coverage
summaries when their linked workflows change.
