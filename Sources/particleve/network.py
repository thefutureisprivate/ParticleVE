"""Render networkd and nftables from validated host topology."""

from pathlib import Path

from .common import atomic_write, require
from .dns import link_settings
from .dns import render as render_dns
from .radio import render as render_radio
from .timesync import render as render_time


def render(config):
    network = config["network"]
    files = {}
    devices = network["links"] + network.get("bridges", []) + network.get("vlans", [])
    for link in network["links"]:
        files[f"etc/systemd/network/10-particleve-{link['name']}.link"] = (
            f"[Match]\nPermanentMACAddress={link['mac']}\n\n[Link]\nName={link['name']}\n"
        )
    for bridge in network.get("bridges", []):
        files[f"etc/systemd/network/20-particleve-{bridge['name']}.netdev"] = (
            f"[NetDev]\nName={bridge['name']}\nKind=bridge\n"
        )
    for vlan in network.get("vlans", []):
        files[f"etc/systemd/network/20-particleve-{vlan['name']}.netdev"] = (
            f"[NetDev]\nName={vlan['name']}\nKind=vlan\n\n[VLAN]\nId={vlan['id']}\n"
        )
    for device in devices:
        lines = [
            "[Match]",
            f"Name={device['name']}",
            "",
            "[Network]",
            "DHCP=no",
            "IPv6AcceptRA=no",
            "LinkLocalAddressing=no",
            *link_settings(network["dns"], device["name"]),
        ]
        if device.get("bridge"):
            lines.append(f"Bridge={device['bridge']}")
        for vlan in network.get("vlans", []):
            if vlan["parent"] == device["name"]:
                lines.append(f"VLAN={vlan['name']}")
        if device["name"] == network["management"]:
            lines += [f"Address={value}" for value in network["addresses"]]
            lines += [f"Gateway={value}" for value in network["gateways"]]
            lines += ["", "[Link]", "RequiredForOnline=routable"]
        else:
            lines += ["", "[Link]", "RequiredForOnline=no"]
        files[f"etc/systemd/network/30-particleve-{device['name']}.network"] = "\n".join(lines) + "\n"
    files.update(render_time(config["time"]))
    files.update(render_dns(network["dns"]))
    files.update(render_radio(config["physical"]["radios"]))
    files["etc/hostname"] = config["hostname"] + "\n"
    console = config.get("console", "console=tty0").removeprefix("console=")
    if console != "tty0":
        port, _, setting = console.partition(",")
        baud = setting.removesuffix("n8") if setting else "115200"
        files["etc/systemd/system/getty.target.d/50-particleve-console.conf"] = (
            f"[Unit]\nWants=serial-getty@{port}.service\n"
        )
        files[f"etc/systemd/system/serial-getty@{port}.service.d/50-particleve.conf"] = (
            "[Service]\nExecStart=\n"
            f"ExecStart=-/sbin/agetty --noclear --noreset -o '-p -- \\u' - {baud} vt220\n"
        )
    return files


def firewall(config):
    """Combine image-owned policy with installation-owned management settings."""
    network = config["network"]
    # Only our host-input table is replaced; guest forwarding remains independent.
    rules = [
        "destroy table inet particleve_host",
        "table inet particleve_host {",
        "  chain input {",
        "    type filter hook input priority 0; policy drop;",
        '    iifname "lo" accept',
        "    ct state invalid drop",
        "    ct state established,related accept",
        "    meta l4proto { icmp, ipv6-icmp } accept",
        '    iifname "vt-*" meta nfproto ipv4 udp sport 68 udp dport 67 accept',
        '    iifname "ns-*" meta nfproto ipv4 udp sport 68 udp dport 67 accept',
    ]
    for source in network["allowed_sources"]:
        family = "ip6" if ":" in source else "ip"
        rules.append(f'    iifname "{network["management"]}" {family} saddr {source} tcp dport 22 accept')
    rules += ["  }", "}"]
    return "\n".join(rules) + "\n"


def write(config, root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, content in render(config).items():
        # These are public daemon configuration directories, including when
        # the owner recovery environment uses umask 077. JSON state stays private.
        parent = root
        for part in Path(name).parts[:-1]:
            parent /= part
            require(not parent.is_symlink(), f"configuration directory is a symlink: {parent}")
            parent.mkdir(exist_ok=True)
            parent.chmod(0o755)
        atomic_write(root / name, content.encode(), mode=0o644)
