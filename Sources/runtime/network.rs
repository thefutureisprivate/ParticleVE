//! Render native networkd, resolved, chrony and nftables configuration.
use crate::common::{Result, atomic_write, field, list, require, text};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::Path,
};
pub fn render(config: &Value) -> Result<BTreeMap<String, String>> {
    let network = field(config, "network")?;
    let mut files = BTreeMap::new();
    let mut devices = Vec::new();
    for kind in ["links", "bridges", "vlans"] {
        if let Some(v) = network.get(kind) {
            devices.extend(list(v)?);
        }
    }
    for link in list(field(network, "links")?)? {
        let name = text(field(link, "name")?)?;
        let mac = text(field(link, "mac")?)?;
        files.insert(
            format!("etc/systemd/network/10-particleve-{name}.link"),
            format!("[Match]\nPermanentMACAddress={mac}\n\n[Link]\nName={name}\n"),
        );
    }
    if let Some(bridges) = network.get("bridges") {
        for bridge in list(bridges)? {
            let name = text(field(bridge, "name")?)?;
            files.insert(
                format!("etc/systemd/network/20-particleve-{name}.netdev"),
                format!("[NetDev]\nName={name}\nKind=bridge\n"),
            );
        }
    }
    if let Some(vlans) = network.get("vlans") {
        for vlan in list(vlans)? {
            let name = text(field(vlan, "name")?)?;
            files.insert(
                format!("etc/systemd/network/20-particleve-{name}.netdev"),
                format!(
                    "[NetDev]\nName={name}\nKind=vlan\n\n[VLAN]\nId={}\n",
                    vlan["id"]
                ),
            );
        }
    }
    for device in devices {
        let name = text(field(device, "name")?)?;
        let mut lines = vec![
            "[Match]".into(),
            format!("Name={name}"),
            "".into(),
            "[Network]".into(),
            "DHCP=no".into(),
            "IPv6AcceptRA=no".into(),
            "LinkLocalAddressing=no".into(),
        ];
        lines.extend(crate::dns::link_settings(field(network, "dns")?, name)?);
        if let Some(bridge) = device.get("bridge")
            && !text(bridge)?.is_empty()
        {
            lines.push(format!("Bridge={}", text(bridge)?));
        }
        if let Some(vlans) = network.get("vlans") {
            for vlan in list(vlans)? {
                if vlan["parent"] == name {
                    lines.push(format!("VLAN={}", text(field(vlan, "name")?)?));
                }
            }
        }
        if network["management"] == name {
            for value in list(field(network, "addresses")?)? {
                lines.push(format!("Address={}", text(value)?));
            }
            for value in list(field(network, "gateways")?)? {
                lines.push(format!("Gateway={}", text(value)?));
            }
            lines.extend([
                "".into(),
                "[Link]".into(),
                "RequiredForOnline=routable".into(),
            ]);
        } else {
            lines.extend(["".into(), "[Link]".into(), "RequiredForOnline=no".into()]);
        }
        files.insert(
            format!("etc/systemd/network/30-particleve-{name}.network"),
            lines.join("\n") + "\n",
        );
    }
    files.extend(crate::timesync::render(field(config, "time")?)?);
    files.extend(crate::dns::render(field(network, "dns")?)?);
    files.extend(crate::radio::render(&config["physical"]["radios"])?);
    files.insert(
        "etc/hostname".into(),
        format!("{}\n", text(field(config, "hostname")?)?),
    );
    let console = config
        .get("console")
        .map(text)
        .transpose()?
        .unwrap_or("console=tty0")
        .trim_start_matches("console=");
    if console != "tty0" {
        let (port, baud) = console
            .split_once(',')
            .map_or((console, "115200"), |(p, b)| (p, b.trim_end_matches("n8")));
        files.insert(
            "etc/systemd/system/getty.target.d/50-particleve-console.conf".into(),
            format!("[Unit]\nWants=serial-getty@{port}.service\n"),
        );
        files.insert(format!("etc/systemd/system/serial-getty@{port}.service.d/50-particleve.conf"),format!("[Service]\nExecStart=\nExecStart=-/sbin/agetty --noclear --noreset -o '-p -- \\\\u' - {baud} vt220\n"));
    }
    Ok(files)
}
pub fn firewall(config: &Value) -> Result<String> {
    let network = field(config, "network")?;
    let mut rules = [
        "destroy table inet particleve_host",
        "table inet particleve_host {",
        "  chain input {",
        "    type filter hook input priority 0; policy drop;",
        "    ct state invalid drop",
        // Enforce the metrics boundary even for loopback or an established flow
        // arriving on another interface after a routing/policy change.
        "    tcp dport 9100 jump metrics",
        "    iifname \"lo\" accept",
        "    ct state established,related accept",
        "    meta l4proto { icmp, ipv6-icmp } accept",
        "    iifname \"vt-*\" meta nfproto ipv4 udp sport 68 udp dport 67 accept",
        "    iifname \"ns-*\" meta nfproto ipv4 udp sport 68 udp dport 67 accept",
    ]
    .map(String::from)
    .to_vec();
    for source in list(field(network, "allowed_sources")?)? {
        let source = text(source)?;
        let family = if source.contains(':') { "ip6" } else { "ip" };
        rules.push(format!(
            "    iifname \"{}\" {family} saddr {source} tcp dport 22 accept",
            text(field(network, "management")?)?
        ));
    }
    rules.extend(["  }".into(), "  chain metrics {".into()]);
    for address in list(field(network, "addresses")?)? {
        let address = text(address)?;
        let address = address
            .split_once('/')
            .ok_or_else(|| crate::common::Error::new("management address needs a prefix"))?
            .0;
        for source in list(field(network, "allowed_sources")?)? {
            let source = text(source)?;
            if source.contains(':') == address.contains(':') {
                let family = if source.contains(':') { "ip6" } else { "ip" };
                rules.push(format!(
                    "    iifname \"{}\" {family} daddr {address} {family} saddr {source} accept",
                    text(field(network, "management")?)?
                ));
            }
        }
    }
    rules.extend(["    drop".into(), "  }".into(), "}".into()]);
    Ok(rules.join("\n") + "\n")
}
pub fn write(config: &Value, root: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)?;
    for (name, content) in render(config)? {
        let relative = Path::new(&name);
        let mut parent = root.to_path_buf();
        if let Some(parts) = relative.parent() {
            for part in parts {
                parent.push(part);
                require(
                    !parent.is_symlink(),
                    format!("configuration directory is a symlink: {}", parent.display()),
                )?;
                std::fs::create_dir_all(&parent)?;
                std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))?;
            }
        }
        atomic_write(root.join(relative), content.as_bytes(), 0o644)?;
    }
    Ok(())
}
