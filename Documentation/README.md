# Documentation

Start with the [project README](../README.md) for product scope and build
instructions. The [contributor guide](../CONTRIBUTING.md) defines required
reading, verification, and documentation responsibilities.
[AGENTS.md](../AGENTS.md) adds project character and workflow guidance for agents.

## Workflows and support

| Document | Contents |
| --- | --- |
| [Development](Development.md) | Local builds, incremental work, tests, OBS coverage and reproduction, and safe cache cleanup. |
| [Build and publication](Build.md) | Resolved image inputs, package provenance, signing, complete release publication, and build observation. |
| [Host operations](Operations.md) | Installation, administration, storage, VM integration, OS maintenance, firmware, networking, Prometheus metrics, and health reporting. |
| [Commissioning](Commissioning.md) | Installation-specific acceptance, recovery evidence, resource budgets, and enabling automatic OS maintenance. |
| [Troubleshooting and recovery](Troubleshooting.md) | Boot, storage, administration, and maintenance recovery; data preservation and useful bug reports. |
| [Release diagnostics](ReleaseDiagnostics.md) | Release preparation, signing evidence, lifecycle and failure checks, kernel acceptance, and hardware coverage. |
| [Security policy](../SECURITY.md) | Vulnerability reporting and disclosure policy. |

## Foundations

| Document | Contents |
| --- | --- |
| [Architecture and security decisions](Architecture.md) | Process authority, module ownership, storage and network contracts, and security invariants. |
| [Coding standards](CodingStandards.md) | Rust, Python, shell, concurrency, ownership, native system interfaces, and privileged-boundary requirements. |
| [Toolchain baseline](Toolchain.md) | Pinned tools and platform, package selection, kernel policy, and build-specific constraints. |
| [Hardening policy](Hardening.md) | Boot and runtime protections, guest containment, privileged execution, network/time/DNS policy, physical interfaces, and measured mitigation decisions. |

## Subsystem contracts

| Document | Contents |
| --- | --- |
| [Storage and boot architecture](Architecture.md) | Independent boot paths, encrypted mirrors, witness authority, verified releases, and data-preserving recovery. |
| [VM and maintenance integration](Operations.md) | External unit ownership, persistent guest state, resource policy, graceful shutdown, and conditional update activation. |

## Guides alongside tools and sources

- [Build and diagnostic tools](../Tools): use the entry points documented in
  [Development](Development.md) and [Build](Build.md).
- [Rust host and initrd implementation](../Sources/runtime): the installed CLI,
  service helpers and privileged boundaries; use the [toolchain baseline](Toolchain.md).
- [Compiled contract tests](../Tests/runtime) and Python test harnesses:
  follow [tests and diagnostics](Development.md#tests-and-diagnostics), including
  the required fixture inputs for staged native helpers.
- [Native acceptance fixtures](../Tests/acceptance): use the matching procedures
  in [Hardening](Hardening.md), [Release diagnostics](ReleaseDiagnostics.md), and
  [Commissioning](Commissioning.md).
- [Package recipes and policies](../.obs): source/payload identities,
  narrow dependency patches, and SELinux policy sources.
- [Public configuration examples](../Tools/Examples): intentionally unusable device
  identities and addresses that must be replaced for a real installation.

## Upstream and attribution

- [Project license](../LICENSE): the existing LGPL-2.1-or-later license.
