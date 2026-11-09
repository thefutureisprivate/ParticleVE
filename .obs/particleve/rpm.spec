# Native OBS rpm flavor; the default build consumes these RPMs for the image.
Name:           particleve
Version:        45.0.1.11
Release:        1%{?dist}
Summary:        ParticleVE host installation and maintenance coordinator
License:        LGPL-2.1-or-later
Source0:        particleve-%{version}.tar.xz
BuildArch:      noarch
BuildRequires:  python3 >= 3.14
BuildRequires:  gnupg2
BuildRequires:  coreutils
BuildRequires:  git-core
BuildRequires:  openssh-clients
BuildRequires:  selinux-policy-devel
BuildRequires:  make
Requires:       bubblewrap
Requires:       util-linux
Requires:       keyutils
Requires:       python3 >= 3.14
Requires:       python3-libselinux
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

%package -n particleve-build-tools
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

%build
make -C .obs/particleve/selinux -f /usr/share/selinux/devel/Makefile particleve_vmspawn.pp particleve_witness.pp

%check
PYTHONPATH=Sources python3 -W error -m unittest discover -v

%install
install -d %{buildroot}%{_prefix}/lib/particleve/particleve
install -m0644 Sources/particleve/*.py %{buildroot}%{_prefix}/lib/particleve/particleve/
install -d %{buildroot}%{_prefix}/lib/particleve/trust
install -m0644 mkosi.extra/usr/lib/particleve/trust/* %{buildroot}%{_prefix}/lib/particleve/trust/
install -D -m0755 Sources/bin/particleve %{buildroot}%{_bindir}/particleve
install -D -m0755 Sources/bin/particleve-health-sender %{buildroot}%{_libexecdir}/particleve-health-sender
install -D -m0755 Sources/bin/particleve-radio-policy %{buildroot}%{_libexecdir}/particleve-radio-policy
install -D -m0755 Sources/bin/particleve-storage-admission %{buildroot}%{_libexecdir}/particleve-storage-admission
install -D -m0755 Sources/bin/particleve-witness-write %{buildroot}%{_libexecdir}/particleve-witness-write
install -D -m0755 Sources/bin/particleve-homed-account %{buildroot}%{_libexecdir}/particleve-homed-account
install -D -m0755 Sources/bin/particleve-vm-stop %{buildroot}%{_libexecdir}/particleve-vm-stop
install -D -m0755 Sources/bin/particleve-vm-start-guard %{buildroot}%{_libexecdir}/particleve-vm-start-guard
install -D -m0755 Sources/bin/particleve-vm-run %{buildroot}%{_libexecdir}/particleve-vm-run
install -D -m0755 Sources/bin/particleve-qemu %{buildroot}%{_libexecdir}/particleve-qemu/qemu
install -D -m0755 Sources/bin/particleve-swtpm %{buildroot}%{_libexecdir}/particleve-swtpm/swtpm
install -m0644 .obs/particleve/selinux/particleve_vmspawn.pp .obs/particleve/selinux/particleve_witness.pp %{buildroot}%{_prefix}/lib/particleve/
install -m0644 .obs/particleve/security-policy.json %{buildroot}%{_prefix}/lib/particleve/
install -d %{buildroot}%{_prefix}/lib/particleve-build/particleve
install -m0644 Sources/particleve/__init__.py Sources/particleve/common.py Sources/particleve/config.py Sources/particleve/release.py \
    Sources/particleve/kernels.py Sources/particleve/buildartifacts.py Sources/particleve/contracts.py Sources/particleve/provenance.py \
    Sources/particleve/package_sources.py Sources/particleve/security.py Sources/particleve/landlock.py Sources/particleve/kernelruntime.py \
    Sources/particleve/consoles.py Sources/particleve/versioning.py Sources/particleve/processes.py Sources/particleve/layout.py \
    %{buildroot}%{_prefix}/lib/particleve-build/particleve/
install -D -m0755 Tools/obs-postoutput %{buildroot}%{_libexecdir}/particleve-obs-postoutput
PYTHONPATH=Sources python3 Tools/package-identity.py --root %{buildroot} \
    --component integration --obs-sources %{_sourcedir}
PYTHONPATH=Sources python3 Tools/package-identity.py --root %{buildroot} \
    --component build-tools --obs-sources %{_sourcedir}

%files
%license LICENSE
%{_bindir}/particleve
%{_libexecdir}/particleve-health-sender
%{_libexecdir}/particleve-radio-policy
%{_libexecdir}/particleve-homed-account
%{_libexecdir}/particleve-storage-admission
%{_libexecdir}/particleve-witness-write
%{_libexecdir}/particleve-vm-stop
%{_libexecdir}/particleve-vm-start-guard
%{_libexecdir}/particleve-vm-run
%{_libexecdir}/particleve-qemu
%{_libexecdir}/particleve-swtpm
%{_prefix}/lib/particleve/particleve_vmspawn.pp
%{_prefix}/lib/particleve/particleve_witness.pp
%{_prefix}/lib/particleve/particleve
%{_prefix}/lib/particleve/trust
%{_prefix}/lib/particleve/package-identity.json
%{_prefix}/lib/particleve/security-policy.json

%files -n particleve-build-tools
%license LICENSE
%{_prefix}/lib/particleve-build
%{_libexecdir}/particleve-obs-postoutput

%changelog
* Fri Nov 06 2026 ParticleVE maintainers <thefutureisprivate@users.noreply.github.com> - 0.1.0-1
- Add homed SSH policy, native Btrfs installation and coordinated vmspawn maintenance.
- Verify final artifacts in the native OBS signing pipeline.
