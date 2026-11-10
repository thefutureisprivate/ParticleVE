//! Bounded read-only pressure and cgroup observations.
use crate::common::{Error, Result, command as execute, hex, parse_json, read_bounded, require};
use crate::confinement::matches;
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;
pub const MAX_VMS: usize = 128;
pub const CONTROLLERS: &[&str] = &["cpu", "io", "memory", "pids"];
pub const OOM_PATTERN: &str = "oom-kill:|Memory cgroup out of memory:|Out of memory: Killed process|A process of this unit has been killed by the OOM killer|Failed with result 'oom-kill'";
pub fn text(path: &Path) -> Result<String> {
    let bytes = read_bounded(path, 65536)?;
    require(
        bytes.is_ascii(),
        "resource observation exceeds its bound or is not ASCII",
    )?;
    Ok(String::from_utf8(bytes)?)
}
fn number(value: &str) -> Result<u64> {
    require(
        matches(r"\A[0-9]{1,20}\z", value)?,
        "invalid unsigned cgroup value",
    )?;
    value
        .parse()
        .map_err(|_| Error::new("unsigned cgroup value exceeds supported range"))
}
pub fn numbers(value: &str) -> Result<Value> {
    let mut result = Map::new();
    let re = Regex::new(r"\A([a-z][a-z0-9_.]{0,63}) ([0-9]{1,20})\z")
        .map_err(|e| Error::new(e.to_string()))?;
    for line in value.lines() {
        let row = re
            .captures(line)
            .ok_or_else(|| Error::new("invalid/duplicate cgroup counter"))?;
        require(
            !result.contains_key(&row[1]),
            "invalid/duplicate cgroup counter",
        )?;
        result.insert(row[1].to_owned(), json!(number(&row[2])?));
    }
    require(!result.is_empty(), "empty cgroup counters")?;
    Ok(Value::Object(result))
}
pub fn unsigned(path: &Path) -> Result<u64> {
    number(text(path)?.trim())
}
pub fn pressure(path: &Path) -> Result<Value> {
    parse_pressure(&text(path)?)
}
pub fn parse_pressure(value: &str) -> Result<Value> {
    let mut result = Map::new();
    let re=Regex::new(r"\A(some|full) avg10=([0-9]+\.[0-9]{2}) avg60=([0-9]+\.[0-9]{2}) avg300=([0-9]+\.[0-9]{2}) total=([0-9]{1,20})\z").map_err(|e|Error::new(e.to_string()))?;
    for line in value.lines() {
        let row = re
            .captures(line)
            .ok_or_else(|| Error::new("invalid/duplicate pressure observation"))?;
        require(
            !result.contains_key(&row[1]),
            "invalid/duplicate pressure observation",
        )?;
        let mut values = Map::new();
        for (index, name) in [(2, "avg10"), (3, "avg60"), (4, "avg300")] {
            let amount: f64 = row[index]
                .parse()
                .map_err(|_| Error::new("invalid pressure percentage"))?;
            require(
                (0.0..=100.0).contains(&amount),
                "invalid pressure percentage",
            )?;
            values.insert(name.to_owned(), json!(amount));
        }
        values.insert("total_usec".into(), json!(number(&row[5])?));
        result.insert(row[1].to_owned(), Value::Object(values));
    }
    require(
        result.len() == 2 && result.contains_key("some") && result.contains_key("full"),
        "incomplete pressure observation",
    )?;
    Ok(Value::Object(result))
}
pub fn devices(value: &str) -> Result<Value> {
    let mut observed = Map::new();
    for line in value.lines() {
        let mut fields = line.split_whitespace();
        let device = fields
            .next()
            .ok_or_else(|| Error::new("invalid I/O device observation"))?;
        require(
            matches(r"\A[0-9]{1,10}:[0-9]{1,10}\z", device)? && !observed.contains_key(device),
            "invalid I/O device observation",
        )?;
        let mut values = Map::new();
        for field in fields {
            let (name, value) = field
                .split_once('=')
                .ok_or_else(|| Error::new("invalid I/O resource counter/limit"))?;
            require(
                matches(r"\A[a-z_]{1,32}\z", name)? && !values.contains_key(name),
                "invalid I/O resource counter/limit",
            )?;
            values.insert(
                name.into(),
                if value == "max" {
                    Value::Null
                } else {
                    json!(number(value)?)
                },
            );
        }
        require(!values.is_empty(), "empty I/O device observation")?;
        observed.insert(device.into(), Value::Object(values));
    }
    Ok(Value::Object(observed))
}
pub fn controllers(root: &Path) -> Result<Vec<String>> {
    let available: BTreeSet<_> = text(&root.join("cgroup.controllers"))?
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    require(
        CONTROLLERS.iter().all(|s| available.contains(*s)),
        "required cgroup v2 resource controllers are unavailable",
    )?;
    Ok(available.into_iter().collect())
}
fn command(args: &[String]) -> Result<String> {
    let result = execute(args, None, Some(Duration::from_secs(10)), 512 * 1024, false)?;
    require(
        result.code == 0 && result.stderr.is_empty(),
        "native resource inspection failed",
    )?;
    Ok(result.stdout)
}
pub fn virtual_machines(root: &Path) -> Result<Vec<Value>> {
    let rows = parse_json(
        command(
            &[
                "systemctl",
                "list-units",
                "--all",
                "--type=service",
                "--output=json",
                "systemd-vmspawn@*.service",
            ]
            .map(str::to_owned),
        )?
        .as_bytes(),
    )?;
    let rows = rows
        .as_array()
        .ok_or_else(|| Error::new("invalid VM resource inventory"))?;
    require(
        rows.len() <= MAX_VMS,
        "VM resource inventory exceeds its bound",
    )?;
    let mut units = BTreeSet::new();
    for row in rows {
        let unit = row
            .get("unit")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new("invalid VM resource inventory"))?;
        require(
            unit.len() <= 256 && crate::vms::valid_unit(unit)? && units.insert(unit.to_owned()),
            "invalid VM resource inventory",
        )?;
    }
    if units.is_empty() {
        return Ok(Vec::new());
    }
    let fields = [
        "Id",
        "ActiveState",
        "Result",
        "ControlGroup",
        "MemoryHigh",
        "MemoryMax",
        "MemorySwapMax",
        "TasksMax",
        "IOAccounting",
        "MemoryAccounting",
        "TasksAccounting",
        "OOMPolicy",
    ];
    let mut args = vec!["systemctl".to_owned(), "show".to_owned()];
    args.extend(units.iter().cloned());
    args.extend(fields.iter().map(|s| format!("--property={s}")));
    let native = command(&args)?;
    let mut observed = BTreeMap::new();
    for block in native.trim().split("\n\n") {
        let props: BTreeMap<_, _> = block
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        let name = props
            .get("Id")
            .copied()
            .ok_or_else(|| Error::new("incomplete VM resource properties"))?;
        require(
            units.contains(name)
                && !observed.contains_key(name)
                && fields.iter().all(|f| props.contains_key(f)),
            "incomplete VM resource properties",
        )?;
        let mut limits = Map::new();
        for field in ["MemoryHigh", "MemoryMax", "MemorySwapMax", "TasksMax"] {
            limits.insert(
                field.into(),
                if props[field] == "infinity" {
                    Value::Null
                } else {
                    json!(number(props[field])?)
                },
            );
        }
        let mut accounting = Map::new();
        for field in ["IOAccounting", "MemoryAccounting", "TasksAccounting"] {
            require(
                ["yes", "no"].contains(&props[field]),
                "invalid accounting observation",
            )?;
            accounting.insert(field.into(), json!(props[field] == "yes"));
        }
        let mut item = json!({"unit":name,"state":props["ActiveState"],"result":props["Result"],"oom_policy":props["OOMPolicy"],"limits":limits,"accounting":accounting});
        let cgroup = props["ControlGroup"];
        if !cgroup.is_empty()
            && ["active", "activating", "deactivating"].contains(&props["ActiveState"])
        {
            require(
                cgroup.starts_with('/')
                    && !cgroup.split('/').any(|s| s == ".." || s == ".")
                    && !cgroup.contains("//")
                    && !cgroup.ends_with('/')
                    && Path::new(cgroup).file_name().and_then(|s| s.to_str()) == Some(name),
                "invalid VM resource cgroup",
            )?;
            let directory = root.join(cgroup.trim_start_matches('/'));
            for (key, path) in [
                ("memory_current_bytes", "memory.current"),
                ("memory_peak_bytes", "memory.peak"),
                ("tasks_current", "pids.current"),
                ("oom_group", "memory.oom.group"),
            ] {
                item[key] = json!(unsigned(&directory.join(path))?);
            }
            for (key, path) in [
                ("memory_stat", "memory.stat"),
                ("memory_events", "memory.events"),
                ("task_events", "pids.events"),
                ("cpu_stat", "cpu.stat"),
            ] {
                item[key] = numbers(&text(&directory.join(path))?)?;
            }
            let mut pressures = Map::new();
            for kind in ["cpu", "memory", "io"] {
                pressures.insert(
                    kind.into(),
                    pressure(&directory.join(format!("{kind}.pressure")))?,
                );
            }
            item["pressure"] = Value::Object(pressures);
            for field in ["io.stat", "io.max"] {
                let path = directory.join(field);
                item[field.replace('.', "_")] = if path.try_exists()? {
                    devices(&text(&path)?)?
                } else {
                    Value::Null
                };
            }
            let path = directory.join("cpu.max");
            if path.try_exists()? {
                let raw = text(&path)?;
                let limit: Vec<_> = raw.split_whitespace().collect();
                require(limit.len() == 2, "invalid CPU bandwidth limit")?;
                let quota = if limit[0] == "max" {
                    Value::Null
                } else {
                    json!(number(limit[0])?)
                };
                let period = number(limit[1])?;
                require(period > 0, "invalid CPU bandwidth limit")?;
                item["cpu_max"] = json!({"quota_usec":quota,"period_usec":period});
            }
        }
        observed.insert(name.to_owned(), item);
    }
    require(
        observed.keys().collect::<BTreeSet<_>>() == units.iter().collect(),
        "VM resource observation is incomplete",
    )?;
    Ok(observed.into_values().collect())
}
pub fn oom_events() -> Result<Value> {
    let args = vec![
        "journalctl".into(),
        "--quiet".into(),
        "--since=-10min".into(),
        "--lines=65".into(),
        "--output=json".into(),
        "--output-fields=__CURSOR,MESSAGE,_TRANSPORT".into(),
        format!("--grep={OOM_PATTERN}"),
        "_TRANSPORT=kernel".into(),
        "+".into(),
        "_PID=1".into(),
    ];
    let result = execute(
        &args,
        None,
        Some(Duration::from_secs(10)),
        256 * 1024,
        false,
    )?;
    require(
        result.code == 0 || (result.code == 1 && result.stdout.is_empty()),
        "OOM journal inspection failed",
    )?;
    require(
        result.stderr.is_empty(),
        "OOM journal inspection produced diagnostics",
    )?;
    let rows = result
        .stdout
        .lines()
        .map(|line| parse_json(line.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    let mut events = Vec::new();
    let re = Regex::new(r"systemd-vmspawn@[A-Za-z0-9_.:\\-]+\.service")
        .map_err(|e| Error::new(e.to_string()))?;
    for row in rows.iter().take(64) {
        let message = row["MESSAGE"]
            .as_str()
            .ok_or_else(|| Error::new("invalid OOM event message"))?;
        let cursor = row["__CURSOR"]
            .as_str()
            .ok_or_else(|| Error::new("invalid OOM event cursor"))?;
        let unit = re
            .find(message)
            .map(|m| m.as_str())
            .filter(|s| s.len() <= 256);
        events.push(json!({"id":hex(&Sha256::digest(cursor.as_bytes())),"source":if row["_TRANSPORT"]=="kernel"{"kernel"}else{"service-manager"},"unit":unit}));
    }
    Ok(json!({"window_seconds":600,"limited":rows.len()>64,"events":events}))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pressure_requires_complete_bounded_percentages() {
        assert!(parse_pressure("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").is_err());
        assert!(parse_pressure("some avg10=101.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").is_err());
        assert!(parse_pressure("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").is_ok());
        assert!(numbers("oom 0\noom 1\n").is_err());
    }
}
