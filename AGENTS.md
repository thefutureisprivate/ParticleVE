# Agent instructions

Shared contributor requirements apply to agents in full. This file describes
the project's character, agent workflow, and required reading; detailed
engineering policy lives in the shared documentation.

## Project character and taste

ParticleVE is a focused virtualization host built on ParticleOS and Fedora.
It should feel small, predictable, and native to systemd. Installing a host,
inspecting its state, and recovering a failed update should be straightforward,
even when the underlying boot, storage, and virtualization work is complicated.
Security is a first-class part of that product quality.

Use these preferences when making decisions:

- Make the host feel at home on Linux. Prefer upstream systemd services and
  familiar administration interfaces. Accurate status, bounded maintenance,
  independent recovery, and preservation of user data deserve the same care
  as the feature itself.
- Keep the product focused. Features should serve concrete workflows; settings,
  dependencies, and abstractions should justify their ongoing complexity.
  Workload deployment, VM provisioning, and backups remain externally owned.
- Use the current platform and toolchain capabilities to make code smaller
  and safer. Treat strict diagnostics as design feedback.
- Choose the simplest complete solution, with clear ownership and lifecycle.
  Solve problems at the responsible boundary, choose fixes that hold up over
  time, and remove obsolete paths as part of the work.
- Keep security architectural. Disk and maintenance authority stays explicit
  and narrow; untrusted guest work stays contained. Preserve user data when an
  outcome is uncertain and make that uncertainty visible.
- Base performance policies on measurements and safety claims on focused
  verification. Make tradeoffs and remaining uncertainty explicit.

## Required reading before starting work

Before investigating, reviewing, or changing the project, read:

1. [README.md](README.md) for product scope, architecture, and build entry points.
2. [CONTRIBUTING.md](CONTRIBUTING.md) for design policy, the task reading map,
   required verification, and documentation responsibilities.
3. [Coding standards](Documentation/CodingStandards.md) for Python, shell,
   system interfaces, ownership, and privileged-boundary requirements.
4. [Toolchain baseline](Documentation/Toolchain.md) for the supported platform,
   source pins, package selection, and build-specific hardening details.
5. The opening overview and
   [non-negotiable invariants](Documentation/Architecture.md#non-negotiable-invariants)
   in the architecture document.

Then read the documents for the affected area in the
[task reading map](CONTRIBUTING.md#task-reading-map), along with relevant code,
tests, and local invariant comments. Read these before working in that area,
not only when preparing the final verification.

## Agent workflow

- When asked to review, never make changes without explicit approval.
- Preserve unrelated work and keep changes within the authorized scope.
- Run the [required verification](CONTRIBUTING.md#required-verification) for
  the change. Report the checks actually run, their results, and any required
  checks that remain unperformed or blocked.
- Update shared policies in their authoritative documentation. Keep this file
  focused on project character, agent workflow, and reading instructions;
  link to detailed engineering requirements in the shared documents.
