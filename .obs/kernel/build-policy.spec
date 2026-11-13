Name:           particleve-kernel-build
# Supersede the former subpackage's ParticleVE release version. This package
# owns only the worker policy and advances independently of host releases.
Epoch:          1
Version:        1
Release:        1%{?dist}
Summary:        ParticleVE kernel build-worker resource policy
License:        LGPL-2.1-or-later
URL:            https://github.com/thefutureisprivate/ParticleVE
Source0:        90-particleve-kernel-build.conf
Source1:        particleve.LICENSE
BuildArch:      noarch
Requires:       pam

%description
PAM file-descriptor limits for OBS's abuild account. This build-only package
keeps Fedora's kernel debug processing and duplicate-file processing within
the worker's resource contract. It is not installed in the host or initrd.

%install
install -D -m0644 %{SOURCE0} \
    %{buildroot}%{_sysconfdir}/security/limits.d/90-particleve-kernel-build.conf
install -D -m0644 %{SOURCE1} %{buildroot}%{_licensedir}/%{name}/LICENSE

%files
%license %{_licensedir}/%{name}/LICENSE
%{_sysconfdir}/security/limits.d/90-particleve-kernel-build.conf

%changelog
* Fri Nov 13 2026 ParticleVE maintainers <thefutureisprivate@users.noreply.github.com> - 1:1-1
- Build the worker resource policy independently of ParticleVE host releases.
