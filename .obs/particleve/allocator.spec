# needssslcertforbuild
# renovate: depName=GrapheneOS/hardened_malloc
%global upstream_commit c5b1ae0bacd896bff7c4d3bf4794adf7950ca4ab
Name:           hardened_malloc
Version:        2026110800
Release:        1%{?dist}
Summary:        GrapheneOS hardened allocator for ParticleVE
License:        MIT AND ISC AND BSL-1.0 AND (Apache-2.0 WITH LLVM-exception)
URL:            https://github.com/GrapheneOS/hardened_malloc
Source0:        https://github.com/GrapheneOS/hardened_malloc/archive/%{upstream_commit}.tar.gz
Source1:        sources.lock.json
Source2:        package_sources.py
Source3:        hardened_malloc.recipe
Source4:        chacha-boundaries.c
Source5:        hardened_malloc.allowed_signers
Patch0:         hardened_malloc-chacha-output-pointer.patch
ExclusiveArch:  x86_64
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  python3 >= 3.14
BuildRequires:  redhat-rpm-config
BuildRequires:  binutils
Provides:       bundled(libdivide) = 5.4.0

%global __os_install_post %{expand:%{__os_install_post}}\
    python3 %{SOURCE2} --root %{buildroot} --rpm-sources %{_sourcedir} --component hardened_malloc --revision %{upstream_commit}\
%{nil}

%description
The upstream default hardened_malloc variant, including C++ sized-allocation
checks, built for x86-64-v2 without native CPU tuning. ParticleVE's verified
host and initrd images select this library through their global loader policy.

%prep
python3 - <<'PY'
import hashlib, json
from pathlib import Path
pin = json.loads(Path('%{SOURCE1}').read_text())['sources']['hardened_malloc']
if pin['version'] != '%{version}' or pin['revision'] != '%{upstream_commit}':
    raise RuntimeError('allocator source identity differs from its lock')
if hashlib.sha256(Path('%{SOURCE0}').read_bytes()).hexdigest() != pin['archive_sha256']:
    raise RuntimeError('allocator archive checksum differs from its lock')
PY
%setup -q -n hardened_malloc-%{upstream_commit}
cp chacha.c chacha.upstream.c
%patch -P 0 -p1

%build
%set_build_flags
export CFLAGS="$CFLAGS -march=x86-64-v2"
export CXXFLAGS="$CXXFLAGS -march=x86-64-v2"
%make_build CC=gcc CXX=g++ CONFIG_NATIVE=false CONFIG_WERROR=true VARIANT=default

%check
ulimit -c 0
gcc -std=c23 -O0 -Wall -Wextra -Werror -I. \
    -Dchacha_keysetup=reference_chacha_keysetup \
    -Dchacha_ivsetup=reference_chacha_ivsetup \
    -Dchacha_keystream_bytes=reference_chacha_keystream_bytes \
    -c chacha.upstream.c -o chacha.reference.o
gcc -std=c23 -O3 -Wall -Wextra -Werror -I. -c chacha.c -o chacha.checked.o
gcc -std=c23 -O2 -Wall -Wextra -Werror -I. %{SOURCE4} \
    chacha.reference.o chacha.checked.o -o chacha-boundaries
./chacha-boundaries
%{__make} test CC=gcc CXX=g++ CONFIG_NATIVE=false CONFIG_WERROR=true

%install
install -Dpm0755 out/libhardened_malloc.so %{buildroot}%{_libdir}/libhardened_malloc.so
install -Dpm0644 config/default.mk %{buildroot}%{_datadir}/hardened_malloc/default.mk

%files
%license LICENSE CREDITS
%doc README.md
%{_libdir}/libhardened_malloc.so
%{_datadir}/hardened_malloc/default.mk
%dir %{_prefix}/lib/particleve
%dir %{_prefix}/lib/particleve/source-identities
%{_prefix}/lib/particleve/source-identities/hardened_malloc.json

%changelog
* Sat Nov 14 2026 ParticleVE maintainers - 2026110800-1
- Build and authenticate the default allocator for global host and initrd use.
