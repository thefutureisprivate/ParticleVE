# Evaluation package; no preload, sysctl or service activation is installed.
Name:           hardened_malloc
Version:        2026110800
Release:        1%{?dist}
Summary:        GrapheneOS allocator variants for scoped ParticleVE evaluation
License:        MIT AND ISC AND BSL-1.0 AND (Apache-2.0 WITH LLVM-exception)
URL:            https://github.com/GrapheneOS/hardened_malloc
Source0:        hardened_malloc-%{version}.tar.xz
Source1:        source.json
Source2:        chacha-boundaries.c
Patch0:         chacha-output-pointer.patch
ExclusiveArch:  x86_64
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  python3 >= 3.14
BuildRequires:  redhat-rpm-config
BuildRequires:  binutils
BuildRequires:  xz
Provides:       bundled(libdivide) = 5.4.0

%description
The upstream default and light hardened_malloc variants, built without native
CPU tuning and with C++ sized-allocation checks. Libraries and reviewed source
metadata live under /usr. Selection and compatibility evaluation are explicit;
installing this package does not enable a host-wide allocator or change policy.

%prep
python3 - <<'PY'
import hashlib, json
from pathlib import Path
pin = json.loads(Path('%{SOURCE1}').read_text())
def require(condition, message):
    if not condition:
        raise RuntimeError(message)
require(pin['schema'] == 1 and pin['version'] == '%{version}', 'source version mismatch')
require(pin['revision'] == 'c5b1ae0bacd896bff7c4d3bf4794adf7950ca4ab', 'source commit mismatch')
require(pin['variants'] == ['default', 'light'] and pin['native_tuning'] is False, 'allocator build policy mismatch')
require(pin['cpu_baseline'] == 'x86-64-v2' and pin['cxx_allocator'] is True, 'allocator CPU/C++ policy mismatch')
require(hashlib.sha256(Path('%{SOURCE0}').read_bytes()).hexdigest() == pin['archive_sha256'], 'source archive digest mismatch')
require(hashlib.sha256(Path('%{PATCH0}').read_bytes()).hexdigest() == pin['patches']['chacha-output-pointer.patch'], 'patch digest mismatch')
PY
%setup -q -n hardened_malloc-%{version}
cp chacha.c chacha.upstream.c
%patch -P 0 -p1

%build
%set_build_flags
# Fedora retains its flags; the final explicit target replaces host tuning.
export CFLAGS="$CFLAGS -march=x86-64-v2"
export CXXFLAGS="$CXXFLAGS -march=x86-64-v2"
%make_build CC=gcc CONFIG_NATIVE=false CONFIG_WERROR=true VARIANT=default
%make_build CC=gcc CONFIG_NATIVE=false CONFIG_WERROR=true VARIANT=light

%install
install -Dpm0755 out/libhardened_malloc.so %{buildroot}%{_libdir}/libhardened_malloc.so
install -Dpm0755 out-light/libhardened_malloc-light.so %{buildroot}%{_libdir}/libhardened_malloc-light.so
install -Dpm0644 %{SOURCE1} %{buildroot}%{_datadir}/hardened_malloc/source.json
install -Dpm0644 config/default.mk %{buildroot}%{_datadir}/hardened_malloc/default.mk
install -Dpm0644 config/light.mk %{buildroot}%{_datadir}/hardened_malloc/light.mk

%check
ulimit -c 0
gcc -std=c23 -O0 -Wall -Wextra -Werror -I. \
    -Dchacha_keysetup=reference_chacha_keysetup \
    -Dchacha_ivsetup=reference_chacha_ivsetup \
    -Dchacha_keystream_bytes=reference_chacha_keystream_bytes \
    -c chacha.upstream.c -o chacha.reference.o
gcc -std=c23 -O3 -Wall -Wextra -Werror -I. -c chacha.c -o chacha.checked.o
gcc -std=c23 -O2 -Wall -Wextra -Werror -I. %{SOURCE2} \
    chacha.reference.o chacha.checked.o -o chacha-boundaries
./chacha-boundaries
# Upstream's corruption tests deliberately fault in bounded child processes.
# Its test Makefile supports only the default variant; do not relabel those
# tests as evidence for light. Native per-process probes cover both variants.
%{__make} test CC=gcc CONFIG_NATIVE=false CONFIG_WERROR=true

%files
%license LICENSE CREDITS
%doc README.md
%{_libdir}/libhardened_malloc.so
%{_libdir}/libhardened_malloc-light.so
%{_datadir}/hardened_malloc/

%changelog
* Tue Nov 10 2026 ParticleVE maintainers - 2026110800-1
- Package pinned signed-source variants for isolated evaluation.
