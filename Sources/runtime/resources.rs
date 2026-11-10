//! Physical RAM reserves and identity-bound read-only boot-disk health.
use crate::common::{
    Error, Result, command, field, list, object, parse_json, read_bounded, require, text, uint,
};
use crate::resourceusage::{controllers, oom_events, pressure, virtual_machines};
use serde_json::{Map, Value, json};
use std::path::Path;
use std::time::Duration;
pub fn parse_memory(input: &str) -> Result<Value> {
    let mut values = Map::new();
    for line in input.lines() {
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| Error::new("malformed kernel memory observation"))?;
        if ["MemTotal", "MemAvailable"].contains(&key) {
            let fields: Vec<_> = value.split_whitespace().collect();
            require(
                fields.len() == 2 && fields[1] == "kB",
                "unexpected kernel memory units",
            )?;
            let amount = fields[0]
                .parse::<u64>()
                .ok()
                .and_then(|n| n.checked_mul(1024))
                .ok_or_else(|| Error::new("invalid kernel memory size"))?;
            values.insert(key.into(), json!(amount));
        }
    }
    require(
        values.len() == 2 && values["MemAvailable"].as_u64() <= values["MemTotal"].as_u64(),
        "physical memory availability cannot be established",
    )?;
    Ok(json!({"total_bytes":values["MemTotal"],"available_bytes":values["MemAvailable"]}))
}
pub fn memory() -> Result<Value> {
    parse_memory(&String::from_utf8(read_bounded(
        "/proc/meminfo",
        1024 * 1024,
    )?)?)
}
pub fn disk_health(selected: &Value) -> Result<Value> {
    crate::inventory::observe_disk(selected, false)?;
    let path = text(field(selected, "path")?)?;
    let response = command(
        &["smartctl", "--json", "--health", "--attributes", path].map(str::to_owned),
        None,
        Some(Duration::from_secs(20)),
        8 * 1024 * 1024,
        false,
    )?;
    let report = parse_json(response.stdout.as_bytes())?;
    require(report.is_object(), "invalid smartctl report")?;
    let status = smart_status(&report, response.code);
    Ok(
        json!({"role":field(selected,"role")?,"path":path,"status":status,"exit_status":response.code,"report":report}),
    )
}
fn smart_status(report: &Value, code: i32) -> &'static str {
    let passed = report
        .get("smart_status")
        .and_then(|s| s.get("passed"))
        .and_then(Value::as_bool);
    if passed == Some(false) || code & 0xf8 != 0 {
        "attention"
    } else if code == 0 && passed == Some(true) {
        "passed"
    } else {
        "unavailable"
    }
}
fn memory_policy(config: &Value, ram: &mut Value) -> Result<Vec<String>> {
    let reserve = uint(field(
        field(config, "maintenance")?,
        "minimum_available_ram_mib",
    )?)?
    .checked_mul(1024 * 1024)
    .ok_or_else(|| Error::new("maintenance RAM reserve exceeds supported range"))?;
    let normal = uint(field(
        field(config, "resources")?,
        "minimum_available_ram_mib",
    )?)?
    .checked_mul(1024 * 1024)
    .ok_or_else(|| Error::new("normal RAM reserve exceeds supported range"))?;
    ram["reserve_bytes"] = json!(reserve);
    ram["normal_reserve_bytes"] = json!(normal);
    let available = uint(&ram["available_bytes"])?;
    let mut alerts = Vec::new();
    if available < normal {
        alerts.push("physical memory headroom is below the normal-operation reserve".to_owned());
    } else if available < reserve {
        alerts.push("physical memory headroom is below the maintenance reserve".to_owned());
    }
    Ok(alerts)
}
fn usage_policy(
    config: &Value,
    ram: &mut Value,
    pressures: &Map<String, Value>,
    machines: &[Value],
    events: &Value,
    alerts: &mut Vec<String>,
) -> Result<()> {
    let normal = uint(field(ram, "normal_reserve_bytes")?)?;
    let thresholds = object(field(
        field(config, "resources")?,
        "pressure_avg60_percent",
    )?)?;
    let mut observations = vec![("host", Value::Object(pressures.clone()))];
    for vm in machines {
        if let Some(value) = vm.get("pressure") {
            observations.push((text(field(vm, "unit")?)?, value.clone()));
        }
    }
    for (owner, observed) in observations {
        for (kind, threshold) in thresholds {
            let threshold = threshold
                .as_f64()
                .ok_or_else(|| Error::new("invalid pressure threshold"))?;
            let value = observed
                .get(kind)
                .and_then(|v| v.get("some"))
                .and_then(|v| v.get("avg60"))
                .and_then(Value::as_f64)
                .ok_or_else(|| Error::new("incomplete resource pressure observation"))?;
            if value >= threshold {
                alerts.push(format!("sustained {kind} pressure exceeds policy: {owner}"));
            }
        }
    }
    let mut maxima = 0u64;
    for vm in machines {
        let unit = text(field(vm, "unit")?)?;
        if vm["state"] == "failed" || vm["result"] == "oom-kill" {
            alerts.push(format!("VM unit failed: {unit}"));
        }
        if vm
            .get("memory_events")
            .and_then(|v| v.get("oom_kill"))
            .and_then(Value::as_u64)
            .is_some_and(|n| n > 0)
        {
            alerts.push(format!("VM cgroup has OOM kills: {unit}"));
        }
        let running = vm["state"] == "active" || vm["state"] == "activating";
        if running {
            if !object(field(vm, "accounting")?)?
                .values()
                .all(|v| v == true)
            {
                alerts.push(format!("VM resource accounting is disabled: {unit}"));
            }
            if vm["oom_policy"] != "kill" || vm.get("oom_group").and_then(Value::as_u64) != Some(1)
            {
                alerts.push(format!("VM kernel group OOM policy changed: {unit}"));
            }
            let limits = field(vm, "limits")?;
            if ["MemoryHigh", "MemoryMax", "TasksMax"].iter().any(|k| {
                limits
                    .get(*k)
                    .and_then(Value::as_u64)
                    .is_none_or(|n| n == 0)
            }) || limits["MemoryHigh"]
                .as_u64()
                .zip(limits["MemoryMax"].as_u64())
                .is_some_and(|(h, m)| h >= m)
            {
                alerts.push(format!(
                    "VM resource limits violate the launch contract: {unit}"
                ));
            }
            if let Some(max) = limits["MemoryMax"].as_u64() {
                maxima = maxima.checked_add(max).ok_or_else(|| {
                    Error::new("aggregate VM resource maxima exceed supported range")
                })?;
            }
        }
    }
    ram["running_vm_memory_max_bytes"] = json!(maxima);
    if maxima
        .checked_add(normal)
        .is_none_or(|n| n >= ram["total_bytes"].as_u64().unwrap_or(0))
    {
        alerts.push(
            "configured running VM memory maxima leave no normal host reserve before host overhead"
                .to_owned(),
        );
    }
    if !list(field(events, "events")?)?.is_empty() || events["limited"] == true {
        alerts.push("recent out-of-memory events require inspection".to_owned());
    }
    Ok(())
}
pub fn status(config: &Value, selected: &[Value], healthy: bool) -> Result<Value> {
    let mut ram = memory()?;
    let mut alerts = memory_policy(config, &mut ram)?;
    let available_controllers = controllers(Path::new("/sys/fs/cgroup"))?;
    let mut pressures = Map::new();
    for kind in ["cpu", "memory", "io"] {
        pressures.insert(
            kind.into(),
            pressure(&Path::new("/proc/pressure").join(kind))?,
        );
    }
    let machines = virtual_machines(Path::new("/sys/fs/cgroup"))?;
    let events = oom_events()?;
    usage_policy(
        config,
        &mut ram,
        &pressures,
        &machines,
        &events,
        &mut alerts,
    )?;
    if healthy && !alerts.is_empty() {
        return Err(Error::deferred(&alerts[0]));
    }
    let mut disks = Vec::new();
    for disk in selected {
        match disk_health(disk){Ok(value)=>disks.push(value),Err(error)=>disks.push(json!({"role":field(disk,"role")?,"path":field(disk,"path")?,"status":"unavailable","reason":error.to_string()}))}
    }
    if healthy && disks.iter().any(|d| d["status"] == "attention") {
        return Err(Error::deferred(
            "a selected disk reports a SMART health fault; inspect physical disk health",
        ));
    }
    Ok(
        json!({"memory":ram,"physical_disks":disks,"controllers":available_controllers,"pressure":pressures,"virtual_machines":machines,"oom_events":events,"alerts":alerts.iter().take(32).collect::<Vec<_>>(),"alerts_limited":alerts.len()>32}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn physical_memory_excludes_swap_and_rejects_bad_units() {
        assert_eq!(
            parse_memory("MemTotal: 1024 kB\nMemAvailable: 512 kB\nSwapFree: 99999 kB\n").unwrap(),
            json!({"total_bytes":1048576,"available_bytes":524288})
        );
        assert!(parse_memory("MemTotal: 1 MB\nMemAvailable: 0 kB\n").is_err());
        assert!(parse_memory("MemTotal: 1 kB\nMemAvailable: 2 kB\n").is_err());
    }
    fn policy() -> Value {
        json!({"maintenance":{"minimum_available_ram_mib":1024},"resources":{"minimum_available_ram_mib":512,"pressure_avg60_percent":{"cpu":50,"memory":10,"io":20}}})
    }
    fn psi() -> Map<String, Value> {
        ["cpu", "memory", "io"]
            .into_iter()
            .map(|kind| (kind.into(), json!({"some":{"avg60":0}})))
            .collect()
    }
    #[test]
    fn normal_and_maintenance_reserves_have_distinct_failure_boundaries() {
        for (available, expected) in [
            (400u64, Some("normal-operation")),
            (800, Some("maintenance")),
            (2048, None),
        ] {
            let mut memory =
                json!({"total_bytes":4u64*1024*1024*1024,"available_bytes":available*1024*1024});
            let alerts = memory_policy(&policy(), &mut memory).expect("memory policy");
            assert_eq!(memory["reserve_bytes"], 1024u64 * 1024 * 1024);
            assert_eq!(memory["normal_reserve_bytes"], 512u64 * 1024 * 1024);
            if let Some(expected) = expected {
                assert!(alerts[0].contains(expected));
            } else {
                assert!(alerts.is_empty());
            }
        }
        assert!(parse_memory("MemTotal: 4096 kB\n").is_err());
    }
    #[test]
    fn smartctl_fault_bits_and_missing_evidence_never_become_passed() {
        for (code, report, expected) in [
            (0, json!({"smart_status":{"passed":true}}), "passed"),
            (8, json!({"smart_status":{"passed":false}}), "attention"),
            (16, json!({"smart_status":{"passed":true}}), "attention"),
            (1, json!({"smartctl":{"messages":[]}}), "unavailable"),
            (4, json!({"smart_status":{"passed":true}}), "unavailable"),
            (0, json!({}), "unavailable"),
        ] {
            assert_eq!(smart_status(&report, code), expected);
        }
    }
    #[test]
    fn pressure_oom_and_aggregate_limits_remain_visible_in_resource_policy() {
        let mut memory =
            json!({"total_bytes":4u64*1024*1024*1024,"available_bytes":2u64*1024*1024*1024});
        let mut alerts = memory_policy(&policy(), &mut memory).expect("memory");
        let mut pressure = psi();
        pressure.insert("memory".into(), json!({"some":{"avg60":60}}));
        let vm = json!({"unit":"systemd-vmspawn@test.service","state":"active","result":"success","accounting":{"IOAccounting":true,"MemoryAccounting":true,"TasksAccounting":true},"oom_policy":"kill","oom_group":1,"limits":{"MemoryHigh":1610612736u64,"MemoryMax":2147483648u64,"TasksMax":256},"pressure":psi(),"memory_events":{"oom_kill":1}});
        usage_policy(
            &policy(),
            &mut memory,
            &pressure,
            &[vm.clone(), vm],
            &json!({"events":[{"id":"opaque"}],"limited":false}),
            &mut alerts,
        )
        .expect("observations");
        for expected in [
            "pressure",
            "OOM kills",
            "no normal host reserve",
            "recent out-of-memory",
        ] {
            assert!(
                alerts.iter().any(|message| message.contains(expected)),
                "{expected}"
            );
        }
        let mut bad = json!({"unit":"systemd-vmspawn@test.service","state":"active","result":"success","accounting":{"MemoryAccounting":false},"oom_policy":"continue","oom_group":0,"limits":{"MemoryHigh":0,"MemoryMax":null,"TasksMax":0}});
        let mut alerts = Vec::new();
        usage_policy(
            &policy(),
            &mut memory,
            &psi(),
            std::slice::from_ref(&bad),
            &json!({"events":[],"limited":false}),
            &mut alerts,
        )
        .expect("drift");
        for expected in [
            "accounting is disabled",
            "OOM policy changed",
            "limits violate",
        ] {
            assert!(
                alerts.iter().any(|message| message.contains(expected)),
                "{expected}"
            );
        }
        bad["state"] = "failed".into();
        bad["result"] = "oom-kill".into();
        let mut alerts = Vec::new();
        usage_policy(
            &policy(),
            &mut memory,
            &psi(),
            &[bad],
            &json!({"events":[],"limited":false}),
            &mut alerts,
        )
        .expect("failed VM");
        assert!(
            alerts
                .iter()
                .any(|message| message.contains("VM unit failed"))
        );
    }
}
