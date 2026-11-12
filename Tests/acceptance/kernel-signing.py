"""Exercise OBS's native RPM module/PE signing continuation on inert payloads.

Run in a disposable Fedora build environment with native signing tools. The
private key is an external, disposable acceptance input; no module is loaded
and no kernel image is executed. This proves packaging, not boot acceptance.
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def run(arguments, *, cwd=None, data=None):
    result = subprocess.run(arguments, cwd=cwd, input=data, capture_output=True, timeout=180, check=True)
    return result.stdout


def copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o644)


def rpm_arguments(top):
    return [
        "rpmbuild",
        "--define",
        "_topdir " + str(top),
        "--define",
        "fedora 45",
        "--define",
        "dist .fc45",
        "--define",
        "_smp_mflags -j2",
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    args = parser.parse_args()
    # New owned output only. Neither external key nor source PE may be changed.
    root = args.workspace.resolve()
    root.mkdir(mode=0o700)
    key = args.key.resolve(strict=True)
    certificate = args.certificate.resolve(strict=True)
    before = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (certificate, args.kernel, args.helper)
    }
    sys.path.insert(0, str(args.helper.parent))
    from kernelpayload import MAGIC, module_parts, verify

    first = second = root / "rpmbuild"
    if run(["rpm", "--eval", "%{_topdir}"]).decode().strip() != str(second):
        raise ValueError("configure the disposable RPM macro path's _topdir as WORKSPACE/rpmbuild")
    for name in ("SOURCES", "SPECS", "BUILD", "BUILDROOT", "RPMS", "SRPMS", "OTHER"):
        (first / name).mkdir(parents=True)
    sources = first / "SOURCES"
    copy(args.helper, sources / "kernelpayload.py")
    copy(args.kernel, sources / "vmlinuz")
    copy(certificate, sources / "_projectcert.crt")
    source = {"schema": 1, "configuration": {"CONFIG_PROBE": "y"}, "scope": "inert signing probe"}
    (sources / "kernel.inputs.json").write_text(json.dumps(source) + "\n")
    spec = r"""# needssslcertforbuild
Name: kernel-signing-probe
Version: 1
Release: 1%{?dist}
Summary: Disposable native signing probe
License: MIT
BuildRequires: gcc, pesign-obs-integration, pesign
Source0: kernelpayload.py
Source1: vmlinuz
Source2: kernel.inputs.json
%global __os_install_post %{expand:%{__os_install_post}}\
 modules=%{buildroot}/lib/modules\
 cert=%{_sourcedir}/_projectcert.crt\
 python3 %{SOURCE0} --modules "$modules" --source-manifest %{SOURCE2} --certificate "$cert"\
 export BRP_PESIGN_COMPRESS_MODULE=xz\
 /usr/lib/rpm/brp-suse.d/brp-99-pesign --files '/lib/modules/*/*.ko /lib/modules/*/vmlinuz'\
 python3 %{SOURCE0} --prepare-signing-continuation %{_topdir}/OTHER/pesign-repackage.spec\
%{nil}
%description
An inert ELF and read-only PE fixture; never loaded or executed.
%prep
%build
cat > probe.c <<'EOF'
const char license[] __attribute__((section(".modinfo"))) = "license=MIT";
int init_module(void) { return 0; }
void cleanup_module(void) {}
EOF
gcc -g -c -Wall -Wextra -Werror -o probe.ko probe.c
%install
install -d %{buildroot}/usr
install -Dm0644 probe.ko %{buildroot}/lib/modules/1.0-probe/kernel/probe.ko
install -m0644 %{SOURCE1} %{buildroot}/lib/modules/1.0-probe/vmlinuz
printf 'CONFIG_PROBE=y\n' > %{buildroot}/lib/modules/1.0-probe/config
for name in System.map modules.builtin modules.builtin.modinfo modules.order; do
 printf 'inert probe metadata\n' > %{buildroot}/lib/modules/1.0-probe/$name
done
%files
/lib/modules/1.0-probe
%changelog
* Wed Nov 11 2026 ParticleVE acceptance - 1-1
- Exercise the native signing continuation with inert payloads.
"""
    path = first / "SPECS/probe.spec"
    path.write_text(spec)
    copy(path, sources / "probe.spec")
    initial = subprocess.run([*rpm_arguments(first), "-bb", str(path)], capture_output=True, timeout=180)
    (root / "initial-build.log").write_bytes(initial.stdout + initial.stderr)
    initial.check_returncode()
    archive = first / "OTHER/kernel-signing-probe.cpio.rsasign"
    paths = run(["cpio", "-it", "--quiet"], data=archive.read_bytes()).decode().splitlines()
    expected = {"lib/modules/1.0-probe/kernel/probe.ko", "lib/modules/1.0-probe/vmlinuz"}
    if set(name.removeprefix("./") for name in paths) != expected or len(paths) != 2:
        raise ValueError("native signing request does not cover exactly the module and kernel")
    signing = root / "signing"
    signing.mkdir()
    run(["cpio", "-id", "--quiet", "--no-absolute-filenames"], cwd=signing, data=archive.read_bytes())
    signatures = []
    for name in sorted(expected):
        signature = Path(name + ".sig")
        run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(key),
                "-out",
                str(signing / signature),
                str(signing / name),
            ]
        )
        signatures.append(signature.as_posix())
    signed = run(
        ["cpio", "-o", "--quiet", "-H", "newc"], cwd=signing, data=("\n".join(signatures) + "\n").encode()
    )
    destination = second / "SOURCES"
    (destination / (archive.name + ".sig")).write_bytes(signed)
    for item in (archive, first / "OTHER/pesign-repackage.spec", *first.glob("RPMS/*/*.rpm")):
        copy(item, destination / item.name)
        if item.suffix == ".rpm":
            copy(item, root / "unsigned-rpms" / item.name)
            item.unlink()
    copy(certificate, destination / "_projectcert.crt")
    # The nested rpmbuild uses RPM's default topdir, as it does in an OBS
    # worker. Give it the same isolated tree rather than the user's ~/rpmbuild.
    command = [*rpm_arguments(second), "-bb", str(destination / "pesign-repackage.spec")]
    continuation = subprocess.run(command, capture_output=True, timeout=180)
    (root / "continuation-build.log").write_bytes(continuation.stdout + continuation.stderr)
    continuation.check_returncode()
    packages = list(second.glob("RPMS/*/kernel-signing-probe-1-*.rpm"))
    if len(packages) != 1:
        raise ValueError("native signing continuation did not emit one probe RPM")
    payload = root / "payload"
    payload.mkdir()
    contents = run(["rpm2cpio", str(packages[0])])
    run(["cpio", "-id", "--quiet", "--no-absolute-filenames"], cwd=payload, data=contents)
    modules = payload / "lib/modules"
    value = verify(modules, source, certificate)
    module = modules / "1.0-probe/kernel/probe.ko.xz"
    original = module.read_bytes()
    body, signature = module_parts(module)
    checks = [
        "native RPM continuation",
        "module body preserved",
        "module and PE signatures",
        "XZ compression",
    ]

    def rejected(label, action):
        try:
            action()
        except ValueError, subprocess.CalledProcessError:
            checks.append(label)
        else:
            raise ValueError("probe unexpectedly accepted: " + label)

    import lzma

    try:
        module.write_bytes(lzma.compress(body, check=lzma.CHECK_CRC32))
        rejected("unsigned module rejected", lambda: verify(modules, source, certificate))
        tampered = bytearray(body)
        tampered[-1] ^= 1
        header = struct.pack(">5B3sI", 0, 0, 2, 0, 0, b"\0\0\0", len(signature))
        module.write_bytes(lzma.compress(tampered + signature + header + MAGIC, check=lzma.CHECK_CRC32))
        rejected("changed module body rejected", lambda: verify(modules, source, certificate))
        module.write_bytes(original)
        rejected(
            "different source identity rejected",
            lambda: verify(modules, {**source, "scope": "different"}, certificate),
        )
        with tempfile.TemporaryDirectory(prefix="particleve-module-probe-key-") as temporary:
            private = Path(temporary)
            run(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-noenc",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=Unrelated disposable module probe/",
                    "-keyout",
                    str(private / "key"),
                    "-out",
                    str(private / "cert"),
                ]
            )
            (private / "body").write_bytes(body)
            run(
                [
                    "openssl",
                    "cms",
                    "-sign",
                    "-binary",
                    "-noattr",
                    "-nocerts",
                    "-md",
                    "sha256",
                    "-signer",
                    str(private / "cert"),
                    "-inkey",
                    str(private / "key"),
                    "-in",
                    str(private / "body"),
                    "-outform",
                    "DER",
                    "-out",
                    str(private / "signature"),
                ]
            )
            wrong = (private / "signature").read_bytes()
            module.write_bytes(
                lzma.compress(
                    body + wrong + struct.pack(">5B3sI", 0, 0, 2, 0, 0, b"\0\0\0", len(wrong)) + MAGIC,
                    check=lzma.CHECK_CRC32,
                )
            )
            rejected("unrelated module signer rejected", lambda: verify(modules, source, certificate))
    finally:
        module.write_bytes(original)
    verify(modules, source, certificate)
    for name, wanted in before.items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != wanted:
            raise ValueError("probe changed an external input")
    result = {
        "result": "pass",
        "scope": "inert native RPM signing continuation; no boot or module load",
        "checks": checks,
        "inputs": before,
        "kernel_record": value,
        "packages": run(["rpm", "-q", "pesign-obs-integration", "rpm", "openssl"]).decode().splitlines(),
    }
    (root / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"result": "pass", "checks": checks}))


if __name__ == "__main__":
    os.umask(0o077)
    main()
