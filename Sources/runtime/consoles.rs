//! Signed early-console selections, shared by verification and runtime health.
use crate::common::{Error, Result, require, text};
use serde_json::{Value, json};
use std::path::Path;
pub const BAUD_RATES: [u32; 5] = [9600, 19200, 38400, 57600, 115200];
pub fn serial_consoles() -> Vec<(String, String)> {
    (0..4)
        .flat_map(|port| {
            BAUD_RATES.map(move |baud| {
                (
                    format!("serial{port}-{baud}"),
                    format!("console=ttyS{port},{baud}n8"),
                )
            })
        })
        .collect()
}
pub fn profile(config: &Value) -> Result<Option<String>> {
    let mut selected = config
        .get("console")
        .map(text)
        .transpose()?
        .unwrap_or("console=tty0")
        .to_owned();
    if selected == "console=tty0" {
        return Ok(None);
    }
    for port in 0..4 {
        if selected == format!("console=ttyS{port}") {
            selected.push_str(",115200n8")
        }
    }
    serial_consoles()
        .into_iter()
        .find_map(|(name, arg)| (arg == selected).then_some(name))
        .map(Some)
        .ok_or_else(|| Error::new("unsupported signed recovery console"))
}
pub fn uki_profiles() -> Vec<Value> {
    serial_consoles().into_iter().map(|(name,arg)|json!({"Profile":{"ID":name,"TITLE":arg.trim_start_matches("console=")},"Cmdline":[arg],"SignExpectedPcr":true})).collect()
}
pub fn baseline(config: &Value, proc: &Path, sys: &Path) -> Result<Value> {
    let selected = profile(config)?;
    let mut expected = vec!["console=tty0".to_owned()];
    if let Some(ref name) = selected {
        expected.push(
            serial_consoles()
                .into_iter()
                .find(|(id, _)| id == name)
                .ok_or_else(|| Error::new("unsupported signed recovery console"))?
                .1,
        )
    }
    let cmdline = std::fs::read_to_string(proc.join("cmdline"))?;
    let actual: Vec<_> = cmdline
        .split_whitespace()
        .filter(|s| s.starts_with("console="))
        .collect();
    require(
        actual == expected,
        "signed early recovery console differs from installation configuration",
    )?;
    let active_text = std::fs::read_to_string(sys.join("class/tty/console/active"))?;
    let active: Vec<_> = active_text.split_whitespace().collect();
    let device = expected
        .last()
        .ok_or_else(|| Error::new("missing recovery console"))?
        .trim_start_matches("console=")
        .split(',')
        .next()
        .ok_or_else(|| Error::new("invalid recovery console"))?;
    require(
        active.contains(&device),
        "selected early recovery console is unavailable",
    )?;
    require(
        active.iter().all(|s| *s == "tty0" || *s == device),
        "unexpected active recovery console",
    )?;
    Ok(
        json!({"profile":selected.unwrap_or_else(||"main".into()),"command_line":actual,"active":active}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_supported_serial_choice_is_signed_and_has_runtime_identity() {
        assert_eq!(uki_profiles().len(), 20);
        for (name, argument) in serial_consoles() {
            let config = json!({"console":argument});
            assert_eq!(profile(&config).expect("profile"), Some(name));
            let temporary = tempfile::tempdir().expect("fixture");
            let proc = temporary.path().join("proc");
            let sys = temporary.path().join("sys");
            std::fs::create_dir_all(&proc).expect("proc");
            std::fs::create_dir_all(sys.join("class/tty/console")).expect("sys");
            std::fs::write(
                proc.join("cmdline"),
                format!("console=tty0 {argument} audit=1"),
            )
            .expect("cmdline");
            let device = argument
                .trim_start_matches("console=")
                .split(',')
                .next()
                .expect("device");
            std::fs::write(
                sys.join("class/tty/console/active"),
                format!("tty0 {device}"),
            )
            .expect("console");
            assert!(baseline(&config, &proc, &sys).is_ok());
            std::fs::write(proc.join("cmdline"), "console=tty0 console=ttyS0,4800n8")
                .expect("wrong profile");
            assert!(baseline(&config, &proc, &sys).is_err());
        }
        assert!(profile(&json!({"console":"console=ttyS4"})).is_err());
        assert_eq!(
            profile(&json!({"console":"console=ttyS1"})).expect("default baud"),
            Some("serial1-115200".into())
        );
    }
}
