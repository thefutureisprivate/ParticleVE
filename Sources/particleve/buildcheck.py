#!/usr/bin/python3
"""Fail a build on inherited desktop/security defaults, wrong origins, or missing host capabilities."""

import re
import shutil
import tempfile
from pathlib import Path

from .common import hash_file, read_json, require, run, write_json
from .config import kernel_parameter_key, version_key
from .consoles import uki_profiles
from .contracts import PERSISTENT_STATE
from .kernels import verify_kernel, verify_kernel_packages
from .provenance import implementation_digest, upstream_inputs, verify_package, verify_upstream_package
from .security import TPM_PROFILE, check_privileges, kernel_baseline
from .systemtrust import check_layout


def check_factory_links(root):
    """Exercise fresh-root materialization, where packaged /etc files are absent."""
    names = (
        "swtpm_setup.conf",
        "swtpm-localca.conf",
        "swtpm-localca.options",
        "udisks2/udisks2.conf",
    )
    require(
        read_json(root / "usr/lib/particleve/tpm-profile.json") == TPM_PROFILE,
        "fresh virtual TPM provisioning profile changed",
    )
    template = root / "usr/lib/systemd/system/systemd-vmspawn@.service.d/50-particleve.conf"
    require(
        "--tpm=no" in template.read_text(), "unconfigured VMs must not manufacture transient TPM identities"
    )
    with tempfile.TemporaryDirectory(prefix="particleve-factory-check-") as directory:
        probe = Path(directory)
        (probe / "etc").mkdir()
        config = probe / "usr/lib/tmpfiles.d/particleve-etc.conf"
        config.parent.mkdir(parents=True)
        shutil.copyfile(root / "usr/lib/tmpfiles.d/particleve-etc.conf", config)
        factory = probe / "usr/share/factory/etc"
        factory.mkdir(parents=True)
        for name in names:
            (factory / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / "usr/share/factory/etc" / name, factory / name)
        run(
            [
                "systemd-tmpfiles",
                f"--root={probe}",
                "--create",
                *(f"--prefix=/etc/{name}" for name in names),
                "particleve-etc.conf",
            ]
        )
        for name in names:
            link = probe / "etc" / name
            require(link.is_symlink(), f"fresh root is missing factory link: /etc/{name}")
            target = link.readlink()
            target = probe / str(target).lstrip("/") if target.is_absolute() else link.parent / target
            require(target.resolve().is_relative_to(probe), "factory configuration link escapes its root")
            require(target.read_bytes() == (factory / name).read_bytes(), "wrong factory configuration")


def check_resolver_defaults(root):
    """The unprivileged resolver must traverse and read its public defaults."""
    relative = Path("usr/lib/systemd/resolved.conf.d/50-particleve.conf")
    for parent in reversed(relative.parents[:-1]):
        directory = root / parent
        require(
            directory.is_dir() and directory.stat().st_mode & 0o005 == 0o005,
            "resolver defaults directory is not publicly readable/searchable: " + str(parent),
        )
    require((root / relative).stat().st_mode & 0o004, "resolver defaults are not publicly readable")


def check_homed_nss(root):
    """Polkit must enumerate homed members of the native local wheel group."""
    factory = Path(root) / "usr/share/factory/etc"
    authority = factory / "nsswitch.conf"
    directory = factory / "authselect"
    source = directory / "nsswitch.conf"
    require(
        authority.is_symlink() and authority.readlink() == Path("/etc/authselect/nsswitch.conf"),
        "factory NSS must use the selected authselect configuration",
    )
    require(
        not directory.is_symlink() and directory.is_dir() and not source.is_symlink() and source.is_file(),
        "factory authselect NSS must be an image-owned regular file",
    )
    rows = [line.split("#", 1)[0].split() for line in source.read_text().splitlines()]
    groups = [row for row in rows if row[:1] == ["group:"]]
    require(
        groups == [["group:", "files", "[SUCCESS=merge]", "systemd"]],
        "NSS must merge local and homed group members for native polkit administration",
    )


def check_radio_rules(root):
    for path in (root / "usr/lib/udev/rules.d").glob("*.rules"):
        require(
            all(
                "systemd-rfkill.socket" not in line.split("#", 1)[0] for line in path.read_text().splitlines()
            ),
            "udev requests the masked native radio-state owner: " + str(path),
        )
    run(
        [
            "udevadm",
            "verify",
            "--no-summary",
            root / "usr/lib/udev/rules.d/71-particleve-radio.rules",
            root / "usr/lib/udev/rules.d/99-systemd.rules",
        ]
    )


def source_revision(directory):
    for file in Path("/usr/src/packages/SOURCES").glob("*.obsinfo"):
        values = dict(line.split(": ", 1) for line in file.read_text().splitlines() if ": " in line)
        if values.get("name") == "particleve":
            if "tree" in values:
                require(re.fullmatch(r"[0-9a-f]{40}", values["tree"]), "invalid staged source tree")
                return "particleve_tree", values["tree"]
            require(re.fullmatch(r"[0-9a-f]{40}", values.get("commit", "")), "invalid OBS source revision")
            return "particleve", values["commit"]
    result = run(["git", "-C", directory, "rev-parse", "HEAD"])
    require(re.fullmatch(r"[0-9a-f]{40}\n", result.stdout), "unresolved fork revision")
    return "particleve", result.stdout.strip()


def check_build_sources(build, lock):
    require(
        build.get("schema") == 1
        and build.get("fedora") == lock["fedora"] == "45"
        and isinstance(build.get("sources"), dict)
        and all(build["sources"].get(name) == pin["revision"] for name, pin in lock["sources"].items()),
        "image source metadata differs from the reviewed source lock",
    )


FORBIDDEN = {
    "cockpit",
    "cockpit-machines",
    "libvirt-daemon",
    "NetworkManager",
    "PackageKit",
    "zram-generator-defaults",
    "gcc",
    "nodejs",
    "gdb",
    "gnome-shell",
    "plasma-workspace",
    "incus",
    "incus-client",
    "incus-agent",
}


def summary_check(summary):
    main = next(i for i in summary["Images"] if i["Image"] == "main")
    initrd = next(i for i in summary["Images"] if i["Image"] == "default-initrd")
    for image in (main, initrd, summary["Tools"]):
        require(
            image["Distribution"] == "fedora" and image["Release"] == "45",
            "Fedora 45 must be explicit in all trees",
        )
        require(
            any("systemd" in t["Source"] and t["Target"].endswith(".repo") for t in image["SandboxTrees"]),
            f"stable systemd repository missing from {image['Image']}",
        )
    require(main["Profiles"] == ["particleve"], "build only the ParticleVE profile")
    require("chrony" in main["Packages"], "the authenticated clock owner is missing")
    require("node-exporter" in main["Packages"], "the management metrics exporter is missing")
    require(not (FORBIDDEN & set(main["Packages"])), "inherited desktop/build/zram package")
    require(
        not main["Credentials"] and main["UnifiedKernelImageProfiles"] == uki_profiles(),
        "unexpected credentials or signed UKI profiles",
    )
    require(main["ImageId"] == "ParticleVE", "incorrect image identity")
    require(
        version_key(main["ImageVersion"])[0] == int(main["Release"]), "image version and Fedora base differ"
    )
    cmdline = main["KernelCommandLine"]
    require(
        [word for word in cmdline if word.startswith("console=")] == ["console=tty0"],
        "base UKI console must be the display console",
    )
    require(
        "audit=1" in cmdline and "audit=0" not in cmdline and "zswap.enabled=1" in cmdline,
        "incorrect audit or zswap command line",
    )
    require(not any("ParticleOS_" in word for word in cmdline), "upstream OS discovery still inherited")
    require(
        {"kvm_intel.nested=0", "kvm_amd.nested=0"} <= set(cmdline),
        "production kernel must disable nested virtualization",
    )
    require("systemd.ssh_auto=no" in cmdline, "automatic SSH socket generation must be disabled")
    require("rfkill.default_state=0" in cmdline, "early radio defaults must be blocked")
    for expected in (
        "module.sig_enforce=1",
        "sysctl.kernel.unprivileged_bpf_disabled=1",
        "sysctl.net.core.bpf_jit_harden=2",
    ):
        key = kernel_parameter_key(expected)
        require(
            [word for word in cmdline if kernel_parameter_key(word) == key] == [expected],
            "signed early kernel policy differs: " + key,
        )
    require(
        main["MicrocodeHost"] is False
        and main["KernelModulesIncludeHost"] is False
        and main["KernelModulesInitrdIncludeHost"] is False,
        "build-host hardware pruning is enabled",
    )
    require(
        main["KernelModules"] == ["*"]
        and {
            "default",
            "/drivers/scsi/",
            "/drivers/nvme/",
            "/drivers/md/",
            "/drivers/char/tpm/",
            "/drivers/net/ethernet/",
            "/net/rfkill/",
        }
        <= set(main["KernelInitrdModules"]),
        "retain generic kernel and initrd module coverage",
    )
    require(
        {
            "systemd-container",
            "systemd-udev",
            "systemd-pam",
            "fwupd",
            "fwupd-efi",
            "udisks2",
            "mdadm",
            "btrfs-progs",
            "systemd",
            "qemu-kvm-core",
            "qemu-img",
            "edk2-ovmf",
        }
        <= set(main["Packages"]),
        "missing host runtime package",
    )


def root_check(root, *, tree="usr", output=None, source_dir=None):
    implementation = None
    upstream = {}
    security = None
    kernel_verification = None
    if tree in ("usr", "tools", "initrd"):
        require(source_dir is not None, "package identity needs the expected image source checkout")
        implementation = implementation_digest(source_dir)
        component = {"usr": "integration", "tools": "build-tools", "initrd": "initrd"}[tree]
        verify_package(root, component, implementation, source=source_dir)
        if tree == "usr":
            verify_package(root, "initrd", implementation, source=source_dir)
        if tree != "initrd":
            upstream = upstream_inputs(source_dir)
            component = "fwupd-efi" if tree == "usr" else "mkosi"
            verify_upstream_package(root, component, upstream[component])
    query = "%{NAME}|%{EVR}|%{VENDOR}|%{DISTURL}\n"
    rows = [
        line.split("|", 3) for line in run(["rpm", "--root", root, "-qa", "--qf", query]).stdout.splitlines()
    ]
    names = {r[0] for r in rows}
    family = [r for r in rows if r[0].startswith("systemd") or r[0] in ("udev", "libudev")]
    require(family, "RPM metadata unavailable; provenance must be checked before package metadata cleanup")
    wrong_origin = [row for row in family if "system:systemd:stable" not in row[3]]
    require(
        not wrong_origin,
        "systemd family contains packages outside upstream OBS stable: " + repr(wrong_origin),
    )
    require(len({row[1] for row in family}) == 1, "mixed systemd family versions")
    if tree != "tools":
        require(not (FORBIDDEN & names), "runtime contains a forbidden package")
        require(
            (root / "usr/lib/systemd/systemd-coredump").is_file(),
            "the selected metadata-only core handler is missing",
        )
        require(source_dir is not None, "boot-disk policy checks need the expected image source checkout")
        rule = Path("usr/lib/udev/rules.d/61-particleve-boot-disk.rules")
        require(
            (root / rule).read_bytes() == (Path(source_dir) / "mkosi.extra" / rule).read_bytes(),
            "boot-disk UUID selection policy differs from the reviewed source",
        )
        for name in (
            "systemd/coredump.conf.d/60-particleve.conf",
            "systemd/system.conf.d/60-particleve-memory.conf",
            "systemd/user.conf.d/60-particleve-memory.conf",
            "sysctl.d/60-particleve-memory.conf",
        ):
            path = Path("usr/lib") / name
            require(
                (root / path).is_file()
                and hash_file(root / path) == hash_file(Path(source_dir) / "mkosi.extra" / path),
                "memory privacy configuration differs from the reviewed source",
            )
        for name in ("modules-load.d/60-particleve-radio.conf", "udev/rules.d/71-particleve-radio.rules"):
            path = Path("usr/lib") / name
            require(
                (root / path).is_file()
                and hash_file(root / path) == hash_file(Path(source_dir) / "mkosi.extra" / path),
                "RFKill device policy differs from the reviewed source",
            )
        for name in ("sysctl.d/60-particleve-kernel.conf", "udev/rules.d/71-particleve-kernel.rules"):
            path = Path("usr/lib") / name
            require(
                (root / path).is_file()
                and hash_file(root / path) == hash_file(Path(source_dir) / "mkosi.extra" / path),
                "kernel interface policy differs from the reviewed source",
            )
    if tree == "usr":
        check_build_sources(
            read_json(root / "usr/lib/particleve/build.json"),
            read_json(Path(source_dir) / "sources.lock.json"),
        )
        kernel_verification = verify_kernel(
            root,
            read_json(Path(source_dir) / ".obs/kernel/kernel.inputs.json"),
            root / "usr/lib/particleve/trust/secure-boot.crt",
        )
        kernel_verification["packages"] = verify_kernel_packages(rows, kernel_verification["kernel"])
        security = {"kernel": kernel_baseline(root), "privileged_files": check_privileges(root)}
        for path in (
            "usr/bin/particleve",
            "usr/bin/chronyc",
            "usr/sbin/chronyd",
            "usr/lib/systemd/system/chronyd-restricted.service",
            "usr/bin/prometheus-node-exporter",
            "usr/lib/systemd/system/prometheus-node-exporter.service",
            "usr/bin/busctl",
            "usr/libexec/particleve-health-sender",
            "usr/libexec/particleve-radio-policy",
            "usr/lib/systemd/system/particleve-radio-policy.service",
            "usr/bin/setpriv",
            "usr/bin/keyctl",
            "usr/bin/machinectl",
            "usr/bin/homectl",
            "usr/bin/userdbctl",
            "usr/bin/systemd-vmspawn",
            "usr/lib/systemd/systemd-nsresourced",
            "usr/lib/systemd/system/systemd-nsresourced.socket",
            "usr/bin/swtpm_setup",
            "usr/bin/smartctl",
            "usr/bin/swtpm_localca",
            "usr/lib/systemd/systemd-sysupdate",
            "usr/lib/systemd/system/systemd-vmspawn@.service",
            "usr/lib/systemd/system/particleve-report.service",
            "usr/lib/systemd/system/particleve-report.timer",
            "usr/share/zoneinfo/Europe/Berlin",
            "usr/libexec/particleve-homed-account",
            "usr/libexec/particleve-vm-stop",
            "usr/libexec/particleve-vm-start-guard",
            "usr/libexec/particleve-vm-run",
            "usr/libexec/particleve-qemu/qemu",
            "usr/libexec/particleve-swtpm/swtpm",
            "usr/lib/particleve/particleve_vmspawn.pp",
        ):
            require((root / path).exists(), f"missing runtime artifact: {path}")
        check_factory_links(root)
        check_layout(root)
        check_resolver_defaults(root)
        check_radio_rules(root)
        require(
            "/run/particleve-dns-policy(/.*)? system_u:object_r:systemd_conf_t:s0"
            in (root / "usr/share/factory/etc/selinux/targeted/contexts/files/file_contexts.local")
            .read_text()
            .splitlines(),
            "DNS policy views lack the native systemd configuration label",
        )
        for name in (
            "systemd/system/chronyd-restricted.service.d/50-particleve.conf",
            "systemd/system/prometheus-node-exporter.service.d/50-particleve.conf",
            "systemd/system/particleve-ca-trust.service",
            "systemd/system/particleve-dns-policy.service",
            "systemd/system/systemd-resolved.service.d/70-private-dns.conf",
            "systemd/system/systemd-resolved.service.d/60-system-trust.conf",
            "systemd/system/fwupd.service.d/60-system-trust.conf",
            "systemd/ntp-units.d/50-chronyd.list",
            "systemd/resolved.conf.d/50-particleve.conf",
            "systemd/system/particleve-radio-policy.service",
            "systemd/system/systemd-networkd.service.d/60-particleve-radio.conf",
        ):
            path = Path("usr/lib") / name
            require(
                (root / path).is_file()
                and hash_file(root / path) == hash_file(Path(source_dir) / "mkosi.extra" / path),
                "runtime daemon contract differs from the reviewed source",
            )
        require(
            (root / "usr/share/factory/etc/chrony.conf").read_bytes()
            == (Path(source_dir) / "mkosi.extra/etc/chrony.conf").read_bytes(),
            "unconfigured factory image has an unreviewed time source",
        )
        require(
            (root / "usr/share/factory/etc/particleve/radio-policy.json").read_bytes()
            == (Path(source_dir) / "mkosi.extra/etc/particleve/radio-policy.json").read_bytes(),
            "unconfigured factory image has an unreviewed radio policy",
        )
        for name in ("particleve_boot.cil", "particleve_runtime.cil"):
            path = Path("usr/lib/particleve") / name
            require(
                (root / path).is_file()
                and hash_file(root / path) == hash_file(Path(source_dir) / "mkosi.extra" / path),
                "SELinux policy source differs from the reviewed image source: " + name,
            )
        for unit in (
            "systemd-sysext.service",
            "systemd-sysext.socket",
            "systemd-confext.service",
            "systemd-confext.socket",
            "systemd-portabled.service",
            "systemd-timesyncd.service",
            "chronyd.service",
            "chrony-wait.service",
            "ksm.service",
            "ksmtuned.service",
            "systemd-rfkill.service",
            "systemd-rfkill.socket",
        ):
            path = root / "usr/lib/systemd/system" / unit
            require(
                path.is_symlink() and path.readlink() == Path("/dev/null"),
                "mutable host extension path is not masked: " + unit,
            )
        for parent in ("etc", "usr/share/factory/etc", "usr/lib"):
            report_timer = root / parent / "systemd/system/timers.target.wants/particleve-report.timer"
            require(
                not report_timer.exists() and not report_timer.is_symlink(),
                "external reporting must remain disabled until an owner selects and tests its receiver",
            )
        require(
            "pam_systemd_home.so" in (root / "usr/lib/pam.d/system-auth").read_text(),
            "upstream PAM homed integration missing",
        )
        check_homed_nss(root)
        require(
            "particleve-homed-account" in (root / "usr/lib/pam.d/system-auth").read_text(),
            "homed account policy missing",
        )
        require(
            "particleve-homed-account" in (root / "usr/lib/pam.d/sshd").read_text(),
            "SSH must enforce the homed account policy independently of authselect's includes",
        )
        require(
            not (root / "usr/share/factory/etc/pam.d").exists(),
            "generic factory PAM examples would shadow the configured /usr PAM stack",
        )
        ssh = (root / "usr/share/factory/etc/ssh/sshd_config.d/05-particleve.conf").read_text()
        require(
            "UsePAM yes" in ssh and "userdbctl ssh-authorized-keys %u" in ssh,
            "generic SSH defaults must activate homed and retrieve keys through upstream userdb",
        )
        require(
            "AuthenticationMethods publickey,password" in ssh,
            "cold-home SSH requires a key and native PAM authentication",
        )
        require(
            "PubkeyAuthOptions touch-required verify-required" in ssh,
            "FIDO2 SSH must require user presence and verification",
        )
        userdb_rule = root / "usr/lib/tmpfiles.d/20-systemd-userdb.conf"
        require(
            not userdb_rule.exists() and not userdb_rule.is_symlink(),
            "the optional userdb link rule cannot mutate read-only factory SSH defaults",
        )
        for file in (root / "usr/lib/tmpfiles.d").glob("*.conf"):
            require(
                not re.search(r"^h\S*\s+/var/lib/machines\s+.*\+C", file.read_text(), re.M),
                "NOCOW must be selected only on individual raw images, not the machines directory",
            )
        certificate = root / "usr/lib/particleve/trust/secure-boot.crt"
        helpers = list((root / "usr/libexec/fwupd/efi").glob("fwupdx64.efi*"))
        require(helpers, "fwupd EFI helper missing")
        signed = [p for p in helpers if p.name.endswith(".signed")]
        require(signed, "supply an OBS-built fwupd-efi package with the separately signed helper")
        for helper in signed:
            run(["sbverify", "--cert", certificate, helper])
        for path in ("etc/selinux/config", "usr/share/factory/etc/selinux/config"):
            require(
                "SELINUX=enforcing" in (root / path).read_text(),
                "SELinux factory configuration is not enforcing",
            )
        policy = root / "etc/selinux/targeted/policy"
        factory = root / "usr/share/factory/etc/selinux/targeted/policy"
        binaries = list(policy.glob("policy.*"))
        require(binaries, "compiled SELinux policy is missing")
        for binary in binaries:
            require(
                binary.read_bytes() == (factory / binary.name).read_bytes(),
                "factory SELinux policy differs from the configured image policy",
            )
        for path in (root / "etc/systemd/system").glob("*.wants/systemd-sysupdate*.timer"):
            require(not path.is_symlink(), f"uncommissioned timer enabled: {path}")
        require(not list((root / "usr/lib/sysupdate.d").glob("*.transfer")), "unguarded OS feed inherited")
        units = [p.name for p in (root / "usr/lib/systemd/system").glob("particleve-*") if p.is_file()]
        run(
            [
                "systemd-analyze",
                f"--root={root}",
                "--man=no",
                "verify",
                *units,
                "systemd-vmspawn@particleve-verify.service",
                "sshd.socket",
                "prometheus-node-exporter.service",
                "multi-user.target",
            ],
            timeout=120,
        )
    elif tree == "initrd":
        require(not (root / "usr/lib/particleve/particleve").exists(), "obsolete Python initrd runtime")
        for executable in (
            "usr/sbin/ldconfig",
            "usr/libexec/particleve-storage-admission",
            "usr/libexec/particleve-initrd-storage",
        ):
            require((root / executable).is_file(), f"initrd admission tool is missing: {executable}")
        run(
            [
                "systemd-analyze",
                f"--root={root}",
                "--man=no",
                "verify",
                "particleve-initrd-storage.service",
                "particleve-initrd-watchdog.timer",
                "particleve-initrd-reboot.service",
            ],
            timeout=120,
        )
    record = {
        "schema": 1,
        "tree": tree,
        "systemd": family,
        "implementation_sha256": implementation,
        "upstream_inputs": upstream,
        "persistent_state": PERSISTENT_STATE.copy(),
        "security_baseline": security,
        "kernel_verification": kernel_verification,
        "packages": [
            {"name": n, "evr": v, "vendor": vendor, "origin": origin} for n, v, vendor, origin in rows
        ],
        "hardware_validation": "not performed by build checks",
    }
    if output:
        write_json(output, record)
    return record
