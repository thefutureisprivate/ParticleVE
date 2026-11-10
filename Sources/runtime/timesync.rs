//! Authenticated chrony observations and a clock-step barrier for activation.
use crate::common::{Error, Result, command, field, list, object, require, text};
use regex::Regex;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
pub const MAX_SOURCES: usize = 8;
const MAX_ERROR: f64 = 0.5;
const MAX_STEP: f64 = 1.0;
fn exact(value: &Value, keys: &[&str]) -> Result<()> {
    let map = object(value)?;
    require(
        map.len() == keys.len() && keys.iter().all(|k| map.contains_key(*k)),
        "unknown time policy",
    )
}
pub fn address(value: &str) -> Result<String> {
    crate::dns::remote_address(value)
}
pub fn validate(policy: &Value) -> Result<()> {
    exact(policy, &["sources", "certificates"])?;
    let sources = list(field(policy, "sources")?)?;
    require(
        (2..=MAX_SOURCES).contains(&sources.len()),
        "configure 2..8 NTS sources",
    )?;
    let mut endpoints = BTreeSet::new();
    let mut operators = BTreeSet::new();
    let operator = Regex::new(r"^[a-z][a-z0-9_-]{0,31}$").map_err(|e| Error::new(e.to_string()))?;
    for source in sources {
        exact(source, &["server", "operator", "trust"])?;
        let server = text(field(source, "server")?)?;
        require(
            !server.contains('%'),
            "use an unscoped literal time-source address",
        )?;
        match server.parse::<std::net::IpAddr>() {
            Ok(_) => require(
                address(server)? == server,
                "use a canonical NTS source address",
            )?,
            Err(_) => {
                crate::config::dns_name(server)?;
            }
        }
        require(endpoints.insert(server), "duplicate NTS endpoint")?;
        let name = text(field(source, "operator")?)?;
        require(
            operator.is_match(name),
            "record the independently reviewed source operator",
        )?;
        operators.insert(name);
        require(
            text(field(source, "trust")?)? == "system",
            "NTS uses the system trust store; remove installation certificate overrides",
        )?;
    }
    require(operators.len() >= 2, "require independent NTS operators")?;
    require(
        text(field(policy, "certificates")?)?.is_empty(),
        "NTS uses the system trust store; install public anchors through the system trust configuration",
    )?;
    Ok(())
}
pub fn render(policy: &Value) -> Result<BTreeMap<String, String>> {
    validate(policy)?;
    let mut lines = [
        "# Generated ParticleVE NTS client; no unauthenticated sources or dynamic includes.",
        "authselectmode require",
        "minsources 2",
        "maxdistance 0.5",
        "maxupdateskew 100",
        "driftfile /var/lib/chrony/drift",
        "ntsdumpdir /var/lib/chrony",
        "dumpdir /var/lib/chrony",
        "makestep 1.0 3",
        "rtcsync",
        "port 0",
        "cmdport 0",
    ]
    .map(String::from)
    .to_vec();
    for source in list(field(policy, "sources")?)? {
        lines.push(format!(
            "server {} nts certset 0 iburst minpoll 6 maxpoll 7",
            text(field(source, "server")?)?
        ));
    }
    let mut files = BTreeMap::new();
    files.insert("etc/chrony.conf".into(), lines.join("\n") + "\n");
    Ok(files)
}
pub fn check_configuration(policy: &Value, root: &Path) -> Result<()> {
    for (name, expected) in render(policy)? {
        let path = root.join(name);
        require(
            path.is_file() && std::fs::read_to_string(path)? == expected,
            "authenticated time configuration drift",
        )?;
    }
    for unit in [
        "systemd-timesyncd.service",
        "chronyd.service",
        "chrony-wait.service",
    ] {
        let mask = root.join("usr/lib/systemd/system").join(unit);
        require(
            mask.is_symlink() && std::fs::read_link(mask)? == Path::new("/dev/null"),
            "an alternate clock owner or synchronization waiter is not masked",
        )?;
    }
    Ok(())
}
pub fn rows(data: &str, width: usize, maximum: usize) -> Result<Vec<Vec<String>>> {
    require(data.len() <= 65536, "oversized time observation")?;
    let mut parsed = Vec::new();
    for line in data.lines() {
        let mut fields = Vec::new();
        let mut field = String::new();
        let mut quoted = false;
        let mut closed = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if quoted {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"')
                    } else {
                        quoted = false;
                        closed = true;
                    }
                } else {
                    field.push(c)
                }
            } else if c == ',' {
                fields.push(std::mem::take(&mut field));
                closed = false;
            } else if c == '"' && field.is_empty() && !closed {
                quoted = true;
            } else {
                require(!closed, "malformed time observation")?;
                field.push(c)
            }
        }
        require(!quoted, "malformed time observation")?;
        fields.push(field);
        require(
            fields.len() == width,
            "unknown chrony machine-report format",
        )?;
        parsed.push(fields);
    }
    require(
        parsed.len() <= maximum,
        "unknown chrony machine-report format",
    )?;
    Ok(parsed)
}
fn number(value: &str, minimum: Option<f64>, maximum: Option<f64>) -> Result<f64> {
    require(value.len() <= 64, "invalid time measurement")?;
    let number = value
        .parse::<f64>()
        .map_err(|_| Error::new("invalid time measurement"))?;
    require(
        number.is_finite()
            && minimum.is_none_or(|m| number >= m)
            && maximum.is_none_or(|m| number <= m),
        "time measurement is non-finite or outside policy",
    )?;
    Ok(number)
}
fn leap(value: &str) -> bool {
    matches!(value, "Normal" | "Insert second" | "Delete second")
}
pub fn assess(policy: &Value, reports: &Value, wall: f64) -> Result<Value> {
    validate(policy)?;
    let tracking = rows(text(field(reports, "tracking")?)?, 14, 1)?;
    require(tracking.len() == 1, "missing clock tracking observation")?;
    let track = &tracking[0];
    require(leap(&track[13]), "clock is not synchronised")?;
    number(&track[2], Some(1.), Some(15.))?;
    let age = wall - number(&track[3], Some(0.), None)?;
    require(
        (-MAX_STEP..=300.).contains(&age),
        "clock update is stale or in the future",
    )?;
    let error = number(&track[4], None, None)?.abs()
        + number(&track[10], Some(0.), None)? / 2.
        + number(&track[11], Some(0.), None)?
        + number(&track[9], Some(0.), None)? * age.max(0.) / 1_000_000.;
    require(
        error <= MAX_ERROR,
        "clock error bound exceeds activation policy",
    )?;
    let sources = rows(text(field(reports, "sources")?)?, 10, MAX_SOURCES)?;
    let mut source_ips = BTreeSet::new();
    let mut auth = BTreeMap::new();
    let mut packets = BTreeMap::new();
    for row in rows(text(field(reports, "authdata")?)?, 10, MAX_SOURCES)? {
        require(
            auth.insert(address(&row[0])?, row).is_none(),
            "ambiguous time observations",
        )?;
    }
    for row in rows(text(field(reports, "ntpdata")?)?, 38, MAX_SOURCES)? {
        require(
            packets.insert(address(&row[0])?, row).is_none(),
            "ambiguous time observations",
        )?;
    }
    let configured = list(field(policy, "sources")?)?;
    let mut operators = BTreeSet::new();
    let mut selected = Vec::new();
    let reach = Regex::new(r"^[0-7]{1,3}$").map_err(|e| Error::new(e.to_string()))?;
    for row in sources {
        let ip = address(&row[2])?;
        require(source_ips.insert(ip.clone()), "ambiguous source addresses")?;
        let name = text(field(field(reports, "names")?, &ip)?)?;
        let config = configured
            .iter()
            .find(|s| s["server"] == name)
            .ok_or_else(|| Error::new("unreviewed time source was added"))?;
        require(
            row[0] == "^",
            "only configured NTS servers may discipline this clock",
        )?;
        if !matches!(row[1].as_str(), "*" | "+" | "-") {
            continue;
        }
        let a = auth
            .get(&ip)
            .ok_or_else(|| Error::new("selected source lacks authentication/packet evidence"))?;
        let p = packets
            .get(&ip)
            .ok_or_else(|| Error::new("selected source lacks authentication/packet evidence"))?;
        require(
            a[1] == "NTS",
            "selected time source is not authenticated with NTS",
        )?;
        number(&a[4], Some(128.), None)?;
        number(&a[5], Some(0.), Some(86400.))?;
        number(&a[8], Some(1.), None)?;
        require(
            leap(&p[5]) && p[6] == "4" && p[7] == "Server" && p[27] == "Yes",
            "unauthenticated NTP sample",
        )?;
        require(
            p[23..26] == ["111", "111", "1111"],
            "NTP response failed measurement tests",
        )?;
        number(&p[2], Some(1.), Some(65535.))?;
        number(&p[33], Some(1.), None)?;
        number(&row[6], Some(0.), Some(300.))?;
        require(
            number(&row[7], None, None)?
                .abs()
                .max(number(&row[8], None, None)?.abs())
                + number(&row[9], Some(0.), None)?
                <= MAX_ERROR,
            "authenticated source error bound exceeds activation policy",
        )?;
        require(
            reach.is_match(&row[5]) && u32::from_str_radix(&row[5], 8).is_ok_and(|v| v > 0),
            "source has no valid replies",
        )?;
        if row[1] == "*" {
            selected.push(ip)
        }
        operators.insert(text(field(config, "operator")?)?.to_owned());
    }
    require(
        selected.len() == 1 && address(&track[1])? == selected[0],
        "selected clock source identity differs",
    )?;
    require(
        operators.len() >= 2,
        "fewer than two independent authenticated sources agree",
    )?;
    Ok(json!({"operators":operators,"maximum_error_seconds":error,"update_age_seconds":age}))
}
fn clocks() -> Result<(f64, f64)> {
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::new(e.to_string()))?
        .as_secs_f64();
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }; // SAFETY: kernel writes one live, correctly aligned timespec; CLOCK_BOOTTIME has no pointer lifetime beyond this call.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut time) };
    require(result == 0, "cannot observe activation boottime")?;
    Ok((wall, time.tv_sec as f64 + time.tv_nsec as f64 / 1e9))
}
pub fn probe(policy: &Value, anchor: Option<&Value>) -> Result<Value> {
    let (start_wall, start_mono) = clocks()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let query = |args: &[&str]| -> Result<String> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                Error::new("authenticated time observation exceeded its total deadline")
            })?;
        let mut command_args = [
            "/usr/bin/setpriv",
            "--reuid=chrony",
            "--regid=chrony",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            "/usr/bin/chronyc",
            "-h",
            "/run/chrony/chronyd.sock",
            "-c",
            "-n",
        ]
        .map(String::from)
        .to_vec();
        command_args.extend(args.iter().map(|s| (*s).to_owned()));
        let observed = command(
            &command_args,
            None,
            Some(remaining.min(Duration::from_secs(2))),
            65536,
            false,
        )?;
        require(
            observed.code == 0 && observed.stderr.is_empty(),
            "authenticated time observation unavailable",
        )?;
        Ok(observed.stdout)
    };
    let mut reports = json!({"names":{}});
    for name in ["tracking", "sources", "authdata", "ntpdata"] {
        reports[name] = Value::from(query(&[name])?);
    }
    for row in rows(text(field(&reports, "sources")?)?, 10, MAX_SOURCES)? {
        let ip = address(&row[2])?;
        reports["names"][&ip] = Value::from(query(&["sourcename", &ip])?.trim());
    }
    let (wall, mono) = clocks()?;
    require(
        ((wall - start_wall) - (mono - start_mono)).abs() <= MAX_STEP,
        "clock stepped during observation",
    )?;
    if let Some(anchor) = anchor {
        let a_wall = anchor["wall"]
            .as_f64()
            .ok_or_else(|| Error::new("invalid clock anchor"))?;
        let a_mono = anchor["boottime"]
            .as_f64()
            .ok_or_else(|| Error::new("invalid clock anchor"))?;
        require(
            mono >= a_mono && ((wall - a_wall) - (mono - a_mono)).abs() <= MAX_STEP,
            "clock stepped during activation; preserve the current OS and restore VMs",
        )?;
    }
    let mut result = assess(policy, &reports, wall)?;
    result["wall"] = Value::from(wall);
    result["boottime"] = Value::from(mono);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: f64 = 1794182000.;
    fn policy() -> Value {
        json!({"sources":[{"server":"time-a.example.org","operator":"operator_a","trust":"system"},{"server":"time-b.example.org","operator":"operator_b","trust":"system"}],"certificates":""})
    }
    fn encode(rows: &[Vec<String>]) -> String {
        rows.iter().map(|row| row.join(",") + "\n").collect()
    }
    fn reports() -> Value {
        let addresses = ["203.0.113.10", "203.0.113.20"];
        let tracking = vec![vec![
            "CB00710A".into(),
            addresses[0].into(),
            "2".into(),
            (NOW - 2.).to_string(),
            "0.001".into(),
            "0.001".into(),
            "0.001".into(),
            "9.0".into(),
            "0.01".into(),
            "1.0".into(),
            "0.02".into(),
            "0.001".into(),
            "64.0".into(),
            "Normal".into(),
        ]];
        let sources = addresses
            .iter()
            .zip(["*", "+"])
            .map(|(ip, state)| {
                [
                    "^", state, ip, "1", "6", "377", "2", "0.001", "0.001", "0.01",
                ]
                .map(String::from)
                .to_vec()
            })
            .collect::<Vec<_>>();
        let auth = addresses
            .iter()
            .map(|ip| {
                [*ip, "NTS", "1", "15", "256", "30", "0", "0", "8", "100"]
                    .map(String::from)
                    .to_vec()
            })
            .collect::<Vec<_>>();
        let packets = addresses
            .iter()
            .map(|ip| {
                let mut row = vec!["0".into(); 38];
                for (index, value) in [
                    *ip,
                    "CB00710A",
                    "123",
                    "203.0.113.1",
                    "CB007101",
                    "Normal",
                    "4",
                    "Server",
                    "1",
                ]
                .iter()
                .enumerate()
                {
                    row[index] = (*value).into();
                }
                for (index, value) in [
                    (23, "111"),
                    (24, "111"),
                    (25, "1111"),
                    (27, "Yes"),
                    (33, "10"),
                ] {
                    row[index] = value.into();
                }
                row
            })
            .collect::<Vec<_>>();
        json!({"tracking":encode(&tracking),"sources":encode(&sources),"authdata":encode(&auth),"ntpdata":encode(&packets),"names":{"203.0.113.10":"time-a.example.org","203.0.113.20":"time-b.example.org"}})
    }
    fn change(reports: &mut Value, report: &str, row: usize, index: usize, value: &str) {
        let width = match report {
            "tracking" => 14,
            "ntpdata" => 38,
            _ => 10,
        };
        let mut values =
            rows(reports[report].as_str().expect("text"), width, MAX_SOURCES).expect("CSV");
        values[row][index] = value.into();
        reports[report] = encode(&values).into();
    }
    #[test]
    fn only_fresh_authenticated_independent_agreement_can_authorize_activation() {
        let valid = reports();
        assert_eq!(
            assess(&policy(), &valid, NOW).expect("valid")["operators"],
            json!(["operator_a", "operator_b"])
        );
        for (report, row, index, value) in [
            ("authdata", 0, 1, "-"),
            ("authdata", 1, 4, "0"),
            ("authdata", 1, 5, "86401"),
            ("authdata", 1, 8, "0"),
            ("ntpdata", 1, 27, "No"),
            ("ntpdata", 1, 23, "110"),
            ("sources", 1, 1, "x"),
            ("sources", 1, 6, "301"),
            ("sources", 1, 5, "000"),
            ("sources", 1, 7, "0.6"),
            ("tracking", 0, 13, "Not synchronised"),
            ("tracking", 0, 4, "1.0"),
            ("tracking", 0, 3, "1794181699"),
            ("tracking", 0, 11, "nan"),
            ("tracking", 0, 9, "inf"),
            ("tracking", 0, 1, "203.0.113.20"),
        ] {
            let mut observed = valid.clone();
            change(&mut observed, report, row, index, value);
            assert!(
                assess(&policy(), &observed, NOW).is_err(),
                "{report} {index} {value}"
            );
        }
        let mut selectable = valid;
        change(&mut selectable, "sources", 1, 1, "-");
        assert!(assess(&policy(), &selectable, NOW).is_ok());
    }
    #[test]
    fn duplicates_scope_injection_and_unbounded_csv_fail_closed() {
        for server in [
            "127.0.0.1",
            "::1",
            "::ffff:101:101",
            "2001:db8::53%eth0",
            "time.example.org\nlocal stratum 1",
        ] {
            let mut selected = policy();
            selected["sources"][0]["server"] = server.into();
            assert!(validate(&selected).is_err(), "{server}");
        }
        let mut observed = reports();
        observed["names"]["203.0.113.10"] = "unknown.example.org".into();
        assert!(assess(&policy(), &observed, NOW).is_err());
        assert!(rows(&"x".repeat(65537), 10, 8).is_err());
        assert!(rows("\"unfinished", 1, 8).is_err());
        assert_eq!(
            rows("\"a,b\",c\n", 2, 8).expect("quoted CSV"),
            vec![vec!["a,b", "c"]]
        );
    }
    #[test]
    fn installation_trust_cannot_bypass_the_system_store() {
        let mut selected = policy();
        selected["sources"][0]["trust"] = "installation".into();
        assert!(
            validate(&selected)
                .expect_err("private trust")
                .message
                .contains("system trust store")
        );
        selected["sources"][0]["trust"] = "system".into();
        selected["certificates"] =
            "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".into();
        assert!(
            validate(&selected)
                .expect_err("custom certificates")
                .message
                .contains("system trust store")
        );
    }
}
