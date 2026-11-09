# renovate: depName=systemd/mkosi
%global upstream_commit a6753e508681aa162cef4e5183f1a728c11c4d78
Name:           mkosi
Version:        28~devel
Release:        1%{?dist}
Summary:        Pinned mkosi for the ParticleVE ParticleOS revision
License:        LGPL-2.1-or-later
Source0:        https://github.com/systemd/mkosi/archive/%{upstream_commit}.tar.gz
Source1:        sources.lock.json
Source2:        package_sources.py
Source3:        mkosi.recipe
Source4:        mkosi-entrypoint.py
Patch0:         mkosi-obs-continuation.patch
Patch1:         mkosi-initrd-module-indexes.patch
Patch2:         mkosi-build-metadata.patch
BuildArch:      noarch
BuildRequires:  gcc
BuildRequires:  kmod
BuildRequires:  cpio
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-setuptools-scm
BuildRequires:  python3-build
BuildRequires:  python3-installer
Requires:       python3
Requires:       python3-pefile
Requires:       systemd-container
Requires:       systemd-ukify
Requires:       systemd-boot
Requires:       systemd-repart
Requires:       dnf5
Requires:       distribution-gpg-keys
Requires:       perl-Config-IniFiles
Requires:       bubblewrap
Requires:       erofs-utils
Requires:       cryptsetup
Requires:       kmod
Requires:       particleve-build-tools

# Record installed bytes after Fedora's BRP transformations, including bytecode.
%global __os_install_post %{expand:%{__os_install_post}}\
    python3 %{SOURCE2} --root %{buildroot} --rpm-sources %{_sourcedir} --component mkosi --revision %{upstream_commit}\
%{nil}

%description
Upstream mkosi at the exact revision recorded in sources.lock.json, with the
ParticleVE native OBS verification toolchain, signing-continuation fixes, and
module indexes regenerated for the selected initrd contents.

%prep
%autosetup -p1 -n mkosi-%{upstream_commit}

%build
PYTHONWARNINGS=error python3 -W error -m build --wheel --no-isolation

%check
bash -n mkosi/resources/mkosi-obs/mkosi.build
PYTHONPATH=. python3 -W error tests/test_initrd_module_indexes.py

%install
python3 -m installer --destdir=%{buildroot} dist/*.whl
install -m0755 %{SOURCE4} %{buildroot}%{_bindir}/mkosi

%files
%license LICENSES/LGPL-2.1-or-later.txt
%{_bindir}/mkosi*
%{python3_sitelib}/mkosi*
%dir %{_prefix}/lib/particleve
%dir %{_prefix}/lib/particleve/source-identities
%{_prefix}/lib/particleve/source-identities/mkosi.json

%changelog
* Fri Nov 06 2026 ParticleVE maintainers <thefutureisprivate@users.noreply.github.com> - 28~0.git.a6753e508681-1
- Build the pinned upstream revision with the native OBS continuation fix.
