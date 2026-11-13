# Native OBS rpm flavor; the default build consumes these RPMs for the image.
%global _buildshell /bin/bash
Name:           particleve
Version:        45.0.3.5
Release:        1%{?dist}
Summary:        ParticleVE host installation and maintenance coordinator
# Project sources are LGPL; statically linked crates select MIT where dual
# licensed. LICENSE.dependencies records the native resolved dependency graph.
License:        LGPL-2.1-or-later AND MIT AND Apache-2.0 AND ISC AND BSD-3-Clause AND Unicode-3.0
Source0:        particleve-%{version}.tar.xz
Source1:        https://github.com/thefutureisprivate/ParticleVE/releases/download/v%{version}/vendor.tar.zst
ExclusiveArch:  x86_64
BuildRequires:  cargo-rpm-macros
BuildRequires:  cargo = 1.99.1
BuildRequires:  rust = 1.99.1
BuildRequires:  rustfmt = 1.99.1
BuildRequires:  clippy = 1.99.1
BuildRequires:  gcc
# Rust embeds Python debugger scripts; gdb-minimal cannot inspect them during BRP.
BuildRequires:  gdb
BuildRequires:  bash
BuildRequires:  libselinux-devel
BuildRequires:  python3 >= 3.14
BuildRequires:  gnupg2
BuildRequires:  coreutils
BuildRequires:  tar
BuildRequires:  zstd
BuildRequires:  git-core
BuildRequires:  openssh-clients
BuildRequires:  openssl
# TLS source checks exercise Fedora's real system trust store.
BuildRequires:  ca-certificates
BuildRequires:  p11-kit-trust
BuildRequires:  cpio
BuildRequires:  selinux-policy-devel
BuildRequires:  make
Requires:       bubblewrap
Requires:       util-linux
Requires:       keyutils
Requires:       particleve-initrd = %{version}-%{release}
Requires:       systemd-udev
Requires:       openssh-clients
Requires:       systemd-container
Requires:       mdadm
Requires:       cryptsetup
Requires:       btrfs-progs
Requires:       smartmontools
Requires:       gnupg2
Requires:       sbsigntools
Requires:       systemd-ukify
Requires:       ca-certificates
Requires:       p11-kit-trust

# BRP strips ELF binaries and generates debuginfo before these final identities.
%global __os_install_post %{expand:%{__os_install_post}}\
    PYTHONPATH=Sources python3 Tools/package-identity.py --root %{buildroot} --component integration --obs-sources %{_sourcedir}\
    PYTHONPATH=Sources python3 Tools/package-identity.py --root %{buildroot} --component initrd --obs-sources %{_sourcedir}\
    PYTHONPATH=Sources python3 Tools/package-identity.py --root %{buildroot} --component build-tools --obs-sources %{_sourcedir}\
%{nil}

%package initrd
Summary:        ParticleVE early-boot storage admission and shutdown witness
Requires:       systemd-udev
Requires:       util-linux
Requires:       cryptsetup
Requires:       mdadm
Requires:       btrfs-progs

%description initrd
Native storage admission before decryption or filesystem assembly, startup
validation, and clean-shutdown mirror authority. The initrd and installed host
use identical compiled helpers.

%package -n particleve-build-tools
License:        LGPL-2.1-or-later
Summary:        ParticleVE verification hooks for native OBS image signing
Requires:       python3 >= 3.14
Requires:       rpm
Requires:       sbsigntools
Requires:       openssl
Requires:       erofs-utils
Requires:       dosfstools
Requires:       mtools
Requires:       veritysetup
Requires:       systemd-repart
Requires:       systemd-ukify
Requires:       pesign
Requires:       nss-tools
Requires:       cpio
Requires:       binutils
Requires:       kmod
Requires:       jq
Requires:       efitools
Requires:       tar
Requires:       zstd
Requires:       findutils
Requires:       coreutils

%description -n particleve-build-tools
Final artifact verification and metadata assembly within mkosi's native OBS
signing stages. Private signing material stays in OBS.

%description
Explicit-target installation, two-disk OS update transactions and supervised
firmware-maintenance inhibition for the ParticleVE ParticleOS profile.

%prep
%autosetup
cp Cargo.lock Cargo.lock.source
tar -xf %{SOURCE1}
cmp Cargo.lock.source Cargo.lock
rm Cargo.lock.source
# The locked vendor archive supplies .cargo/config. Consume its contents
# through the filename required by the pinned Cargo, before any Cargo command.
test ! -e .cargo/config.toml
mv .cargo/config .cargo/config.toml

%build
%set_build_flags
export CARGO_NET_OFFLINE=true
# Fedora caps lints globally; retain its build flags while making diagnostics fatal.
export RUSTFLAGS="${RUSTFLAGS//--cap-lints=warn/} -Dwarnings -Ctarget-cpu=x86-64-v2 -Cforce-frame-pointers=yes -Clink-arg=-Wl,-z,relro,-z,now"
cargo build --release --offline --locked --bins
%cargo_license_summary
%{cargo_license} > LICENSE.dependencies
%cargo_vendor_manifest
# Retain upstream license and notice text for every vendored crate, including
# additional third-party notices nested beneath a crate's root.
mkdir dependency-licenses
find vendor -type f \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' -o -iname 'COPYRIGHT*' \) \
    -exec cp --parents -t dependency-licenses {} +
make -C .obs/particleve/selinux -f /usr/share/selinux/devel/Makefile particleve_vmspawn.pp particleve_witness.pp

%check
%set_build_flags
export CARGO_NET_OFFLINE=true
# Fedora caps lints globally; retain its build flags while making diagnostics fatal.
export RUSTFLAGS="${RUSTFLAGS//--cap-lints=warn/} -Dwarnings -Ctarget-cpu=x86-64-v2 -Cforce-frame-pointers=yes -Clink-arg=-Wl,-z,relro,-z,now"
cargo fmt --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked
cargo build --offline --locked --example runtime-contract-driver
PVE_RUNTIME_DRIVER=$PWD/target/debug/examples/runtime-contract-driver PYTHONPATH=Sources python3 -W error -m unittest discover -v

%install
# Fedora's index wrapper prefers gdb.minimal even when full GDB is present.
# Select its Python-aware parser for standard Rust .debug_gdb_scripts metadata.
export GDB=/usr/bin/gdb
install -d %{buildroot}%{_prefix}/lib/particleve/trust
install -m0644 mkosi.extra/usr/lib/particleve/trust/* %{buildroot}%{_prefix}/lib/particleve/trust/
install -D -m0755 target/release/particleve %{buildroot}%{_bindir}/particleve
for helper in health-sender radio-policy storage-admission initrd-storage witness-write homed-account vm-stop vm-start-guard vm-run system-trust nts-trust; do
    install -D -m0755 target/release/particleve-$helper %{buildroot}%{_libexecdir}/particleve-$helper
done
install -D -m0755 target/release/particleve-qemu %{buildroot}%{_libexecdir}/particleve-qemu/qemu
install -D -m0755 target/release/particleve-swtpm %{buildroot}%{_libexecdir}/particleve-swtpm/swtpm
install -D -m0755 target/release/particleve-storage-shutdown %{buildroot}%{_prefix}/lib/systemd/system-shutdown/particleve-storage
install -m0644 .obs/particleve/selinux/particleve_vmspawn.pp .obs/particleve/selinux/particleve_witness.pp %{buildroot}%{_prefix}/lib/particleve/
install -m0644 .obs/particleve/security-policy.json %{buildroot}%{_prefix}/lib/particleve/
install -d %{buildroot}%{_prefix}/lib/particleve-build/particleve
install -m0644 Sources/particleve/__init__.py Sources/particleve/common.py Sources/particleve/config.py Sources/particleve/release.py \
    Sources/particleve/kernels.py Sources/particleve/buildartifacts.py Sources/particleve/contracts.py Sources/particleve/provenance.py \
    Sources/particleve/package_sources.py Sources/particleve/security.py Sources/particleve/kernelruntime.py \
    Sources/particleve/consoles.py Sources/particleve/versioning.py Sources/particleve/layout.py Sources/particleve/systemtrust.py \
    Sources/particleve/kernelpayload.py Sources/particleve/initrdpolicy.py Sources/particleve/kernelinitrd.py \
    %{buildroot}%{_prefix}/lib/particleve-build/particleve/
install -m0644 .obs/kernel/kernel.inputs.json %{buildroot}%{_prefix}/lib/particleve-build/
install -D -m0755 Tools/obs-postoutput %{buildroot}%{_libexecdir}/particleve-obs-postoutput
install -m0644 Sources/particleve/runtime-policy.json %{buildroot}%{_prefix}/lib/particleve-build/particleve/

%files
%dir %{_prefix}/lib/particleve
%license LICENSE LICENSE.dependencies cargo-vendor.txt dependency-licenses
%{_bindir}/particleve
%{_libexecdir}/particleve-health-sender
%{_libexecdir}/particleve-radio-policy
%{_libexecdir}/particleve-system-trust
%{_libexecdir}/particleve-nts-trust
%{_libexecdir}/particleve-homed-account
%{_libexecdir}/particleve-witness-write
%{_libexecdir}/particleve-vm-stop
%{_libexecdir}/particleve-vm-start-guard
%{_libexecdir}/particleve-vm-run
%{_libexecdir}/particleve-qemu
%{_libexecdir}/particleve-swtpm
%{_prefix}/lib/particleve/particleve_vmspawn.pp
%{_prefix}/lib/particleve/particleve_witness.pp
%{_prefix}/lib/particleve/trust
%{_prefix}/lib/particleve/package-identity.json
%{_prefix}/lib/particleve/security-policy.json

%files initrd
%dir %{_prefix}/lib/particleve
%license LICENSE LICENSE.dependencies cargo-vendor.txt dependency-licenses
%{_libexecdir}/particleve-storage-admission
%{_libexecdir}/particleve-initrd-storage
%{_prefix}/lib/systemd/system-shutdown/particleve-storage
%{_prefix}/lib/particleve/initrd-package-identity.json

%files -n particleve-build-tools
%license LICENSE
%{_prefix}/lib/particleve-build
%{_libexecdir}/particleve-obs-postoutput

%changelog
* Tue Nov 10 2026 ParticleVE maintainers <thefutureisprivate@users.noreply.github.com> - 45.0.2.2-1
- Merge local and homed NSS group members for native polkit administrator selection.
- Reject image NSS configurations that hide homed wheel membership.

* Tue Nov 10 2026 ParticleVE maintainers <thefutureisprivate@users.noreply.github.com> - 45.0.2.1-1
- Rebuild shared Fedora CA views from the active image and reviewed local trust.
- Refresh native TLS clients and invalidate NTS sessions when system trust changes.

* Tue Nov 10 2026 ParticleVE maintainers <thefutureisprivate@users.noreply.github.com> - 45.0.2.0-1
- Rewrite installed host and initrd helpers in Rust while retaining storage and recovery contracts.
- Build from the locked offline Cargo vendor archive with strict native Fedora hardening.
- Use Fedora system CA trust and record final RPM-transformed runtime payloads.

* Fri Nov 06 2026 ParticleVE maintainers <thefutureisprivate@users.noreply.github.com> - 0.1.0-1
- Add homed SSH policy, native Btrfs installation and coordinated vmspawn maintenance.
- Verify final artifacts in the native OBS signing pipeline.
