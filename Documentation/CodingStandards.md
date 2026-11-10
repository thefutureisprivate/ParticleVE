# Coding standards

These requirements apply to all contributors, human and agent. Each language
section defines its scope. Exceptions must be narrow, documented, and tested.

Read the [contributor guide](../CONTRIBUTING.md) for design and compatibility
policy, required verification, and documentation responsibilities. The
[toolchain baseline](Toolchain.md) records supported versions and
build-specific hardening details; this document defines coding requirements.

## Rust runtime and host integration

The installed host and initrd helpers use Rust. Python remains the language for
build tools, tests, and acceptance probes. Third-party source is out of scope,
but repository-owned adapters, patches, and dependency policy remain in scope.

### Baseline and module boundaries

- Target the Rust, Python, Fedora, systemd, and mkosi baseline recorded in
  [Toolchain.md](Toolchain.md). Do not add backward-compatibility branches,
  permissive fallbacks, or retain obsolete implementations unless a current
  upstream defect requires a documented workaround.
- Use Python 3.14 or newer and the Ruff configuration in
  [`pyproject.toml`](../pyproject.toml). Run the supported test entry point with
  warnings as errors for build tools, tests and acceptance harnesses.
- Keep reusable runtime policy in `Sources/runtime/`, command dispatch in
  `Sources/runtime/cli.rs`, native entry points in `Sources/runtime/bin/`, and
  Python build/publication entry points in `Tools/`. Python modules in
  `Sources/particleve/` serve those build tools. Never execute a Python runtime
  implementation from a Rust helper.
- Keep the joint kernel, TPM and SELinux baseline in
  [`runtime-policy.json`](../Sources/particleve/runtime-policy.json). Rust embeds
  this reviewed input; Python build checks read the same data. Change the
  authoritative policy and its validation rather than duplicating constants.
- Use maintained, established dependencies only when they justify their
  complexity. Pin their exact versions and checksums in `Cargo.toml` and
  `Cargo.lock`; build offline from the lock in OBS. Review maintenance status,
  advisories, licenses and transitive changes when updating dependencies.
- Run Rust formatting, Clippy and tests through `make check`. Treat warnings
  as errors. Keep `unsafe` at narrow Linux ABI boundaries, with local ownership,
  lifetime, layout and bounds explanations. Prefer owned descriptors and RAII
  cleanup; a cleanup guard must never force off an externally owned guest.
- Do not weaken checks or add broad suppressions to obtain a passing run.
  Fix the ownership, validation, or API boundary instead.

### Architecture and ownership

- Choose the simplest complete solution, with clear ownership and lifecycle.
  Reuse the native systemd, storage, and virtualization interfaces rather than
  introducing a second management framework.
- Represent meaningful states and contracts explicitly. Validate external JSON
  at its boundary; do not let unchecked dictionaries, magic strings, or Boolean
  combinations stand in for a validated installation or release.
- Keep observation separate from mutation where this reduces authority. A
  status command must not silently repair storage, approve a release, enroll
  trust, or change a VM's startup policy.
- Inject mutable services and clocks where this makes policy testable. A
  process-wide coordinator is acceptable only when its authority is explicit
  and its state is protected by the shared lock and durable transaction record.
- Use RAII, context managers and `try`/`finally` for deterministic cleanup. Cleanup
  must preserve the original failure and must not discard state needed for
  recovery.

### Diagnostics

Project code must be usable without warnings and pass the configured lint.
Warnings are errors. Do not disable diagnostics globally or use broad
suppressions. A local suppression must cover the smallest possible region,
explain why the operation is correct, and receive verification appropriate to
its risk.

Report actionable failures and distinguish invalid configuration, unavailable
observation, deferred maintenance, and a completed operation. Do not translate
uncertain results into success. Logs and status output must be bounded and must
not expose credentials, recovery material, private keys, or unnecessary guest
data.

### Transactions and concurrency

- Treat the maintenance lock as ownership of the update/install/repair
  transaction. Preserve one lock inode and the durable state needed to reconcile
  an interrupted attempt.
- Validate before mutation. Stage complete authenticated releases and verify
  both selected boot paths before making a release eligible for activation.
- Persist authority changes before allowing their dependent writes. In
  particular, a returning storage member cannot authorize itself from its own
  contents, and uncertain NOCOW mirror authority requires owner recovery.
- Use atomic replacement, file synchronization, and parent-directory
  synchronization where the persistent contract requires them. An atomic rename
  alone does not establish durability after power loss.
- Give subprocesses and operational waits a deadline. Use monotonic time for
  elapsed deadlines and the explicit authenticated wall-clock policy for the
  maintenance window.
- Track resources and VMs owned by an attempt. Abort/recovery may restore only
  the VMs stopped by that attempt; it must not force a guest off or permanently
  change external startup policy.
- Preserve late completion, interruption, cancellation, and restart semantics.
  Do not hide a partially completed operation behind a generic retry.

### Command-line and subprocess interfaces

- Pass subprocess argument arrays. Do not interpolate configuration, device
  identities, paths, or network input into a shell command.
- Use the common subprocess helpers where their timeout and output contract
  fits. For untrusted or potentially large diagnostic output, use a bounded
  capture path and validate its encoding and structure.
- Validate stable identifiers and option values before invoking tools. Resolve
  the exact selected device; never infer a destructive target from enumeration
  order or a convenient default.
- Keep destructive operations explicit, with the required identity and
  ownership checks immediately before the mutation. A previously successful
  preflight does not authorize a different device instance.
- Preserve useful machine-readable output and failure status. Do not add an
  interactive prompt to an unattended path or silently substitute a weaker
  authentication mode.

### Privileged and unsafe boundaries

- Confine direct syscalls, `ctypes`, capability changes, descriptor passing,
  namespace transitions, and privilege drops to narrow helpers. Expose validated
  values and explicit failures to the rest of the project.
- State ownership, size, lifetime, ABI, and cleanup requirements at the actual
  boundary. Check syscall results and prevent descriptor leaks across exec or
  privilege transitions.
- Apply hard limits before allocating or interpreting untrusted data. Validate
  versions, identifiers, enums, offsets, lengths, conversions, and size
  arithmetic. Reject duplicate or unknown fields where the format requires it.
- Invalid input fails closed: do not introduce permissive coercion, fallback
  parsers, or partial mutation.
- Keep executables, libraries, Python modules, and security policy in verified
  `/usr`. Treat writable configuration and VM storage according to their
  distinct authority contracts; `noexec` is not a substitute for controlling
  interpreter and loader inputs.
- Keep SELinux, systemd restrictions, QEMU seccomp, and post-handoff confinement
  aligned with actual runtime authority. A high inspection score or a present
  unit directive does not replace positive and negative behavioral checks.
- Explain non-obvious safety invariants beside the code. Discuss lifetime,
  ownership, bounds, synchronization, and cleanup only where relevant; avoid
  file-wide or formulaic safety claims.

### Performance and testing

- Base performance policy on measurements. Do not add caching, parallelism,
  weaker validation, or resource limits merely because they appear faster.
  Explain the measured tradeoff and preserve the security contract.
- Use Rust tests for runtime contracts and Python unittest for build tooling,
  cross-language persisted formats and acceptance probes. Prefer focused
  behavioral tests over tests that merely reproduce the implementation.
- Use the compiled test driver for runtime contract checks from Python harnesses.
  Keep expected persisted formats and failure outcomes explicit; do not retain a
  second runtime implementation as a test oracle. Native harnesses must exercise
  the selected compiled helper and record its source and binary identity.
- Test interruption, teardown, stale results, duplicate completion, late guest
  exits, and races directly. Prefer fake clocks, controlled fixtures, and
  injected observations over arbitrary sleeps.
- Treat network, filesystem, firmware, IPC, and dependency output as hostile.
  Test empty, malformed, oversized, boundary-sized, concurrent, cancelled, and
  partially completed cases where they affect the boundary.
- Use disposable fixtures for destructive tests. Do not promote evidence from
  mocks or component probes into claims about the final signed image or every
  physical platform.
- Record image/source identities, relevant configuration, method, results, and
  limitations for acceptance and measurements. Historical results do not prove
  that a changed implementation passes.

## Shell, native probes, and packaging

These rules apply to first-party shell helpers, native acceptance probes, RPM
recipes, mkosi hooks, and downstream patches. Keep native code small and
single-purpose; ordinary host orchestration belongs in the validated Rust
and systemd interfaces.

### Language and toolchain

Use the interpreters, compiler, headers, and RPM tooling declared by the selected
build environment. Do not add compatibility paths for older platforms,
architectures, or language modes. Platform-specific syscalls and EFI interfaces
must state and validate their supported ABI.

### Ownership and untrusted input

Every resource must have explicit ownership and deterministic cleanup. Quote
shell expansions, use arrays for argument lists where supported, and avoid
`eval`. Check commands whose failure would invalidate a subsequent destructive
or privileged operation; shell strict mode does not replace that review.

Native probes and patches must validate buffer lengths and arithmetic before
access, keep borrowed storage within its lifetime, and report failures without
corrupting the acceptance fixture. Do not generalize test-only fault injection
into a production interface.

### Build hardening and provenance

Do not weaken configured compiler diagnostics, SELinux enforcement, module and
PE signature checks, artifact verification, or dependency identity checks.
Any necessary change requires an explicit rationale and targeted verification.

Keep recipes, patches, source locks, installed-payload records, and final
release provenance consistent. Preserve normal RPM build transformations and
record final installed bytes at the appropriate stage. A signing continuation
must verify the bytes it publishes, not merely an earlier build directory.

Treat private signing and service credentials as external inputs. Never place
them in source archives, image overlays, example configuration, logs, or a URL.
Keep generated public configuration reviewable and reject accidental private
key material.

### Scope and clarity

Prefer functions and explicit configuration over duplicated command fragments
and implicit environment state. Comments should document invariants, ownership,
fault containment, durability, and ordering rather than restate the code.

Use the [build guide](Build.md), [hardening contracts](Hardening.md), and
[architecture invariants](Architecture.md#non-negotiable-invariants) for the
cross-component policy that these implementation rules preserve.
