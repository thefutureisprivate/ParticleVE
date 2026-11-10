//! Test-only JSON interface; this executable is never installed in an image.
use particleve::common::{self, Error, Result, field, list, text};
use particleve::vms::VmPlatform;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::Path;

mod host;
mod orchestration;
mod storage;
mod vm;

fn evaluate(request: &Value) -> Result<Value> {
    match text(field(request, "operation")?)? {
        "canonical" => {
            let value = field(request, "value")?;
            Ok(
                json!({"canonical":String::from_utf8(common::canonical(value)?)?,"digest":common::digest(value)?}),
            )
        }
        "parse" => {
            let data = text(field(request, "data")?)?;
            Ok(json!({"value":common::parse_json(data.as_bytes())?}))
        }
        "admission-choose" => {
            let present = list(field(request, "present")?)?
                .iter()
                .map(|r| text(r).map(str::to_owned))
                .collect::<Result<Vec<_>>>()?;
            particleve::admission::choose(field(request, "record")?, &present)
        }
        "admission-validate" => particleve::admission::validate(field(request, "record")?),
        "admission-load" => particleve::admission::load(),
        "admission-watch" => particleve::admission::watch(),
        "admission-member-errors" => Ok(json!(particleve::admission::member_errors(
            field(request, "record")?,
            Path::new(text(field(request, "target")?)?),
            Path::new(text(field(request, "mapper")?)?)
        )?)),
        "witness-save" => {
            particleve::witness::save(field(request, "record")?)?;
            Ok(Value::Null)
        }
        "session-refresh" => {
            let session = Path::new(particleve::admission::SESSION);
            let before = std::os::unix::fs::MetadataExt::ino(&session.metadata()?);
            let data = common::read_json(session)?;
            common::write_json(session, &data)?;
            common::require(
                common::read_json(session)? == data
                    && std::os::unix::fs::MetadataExt::ino(&session.metadata()?) != before,
                "session refresh failed",
            )?;
            Ok(Value::Null)
        }
        "layout-calculate" => particleve::layout::calculate(
            field(request, "config")?,
            list(field(request, "devices")?)?,
            field(request, "release")?,
        ),
        "startup-check" => particleve::startup::check(Path::new(text(field(request, "root")?)?)),
        "startup-inventory" => {
            particleve::startup::inventory(Path::new(text(field(request, "root")?)?))
        }
        "storage-profiles" => Ok(json!(particleve::storage::profiles(text(field(
            request, "text"
        )?)?)?)),
        "storage-members" => Ok(json!(particleve::storage::members(text(field(
            request, "text"
        )?)?)?)),
        "persistent-contracts" => Ok(particleve::contracts::persistent_state()),
        "commission-requirements" => Ok(json!(particleve::commission::requirements_digest()?)),
        "config-validate" => particleve::config::validate(
            field(request, "config")?.clone(),
            request
                .get("publication")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
        "version-key" => Ok(json!(particleve::config::version_key(text(field(
            request, "version"
        )?)?)?)),
        "consoles-profile" => Ok(json!(particleve::consoles::profile(field(
            request, "config"
        )?)?)),
        "network-render" => Ok(json!(particleve::network::render(field(
            request, "config"
        )?)?)),
        "network-firewall" => Ok(json!(particleve::network::firewall(field(
            request, "config"
        )?)?)),
        "dns-assess" => {
            let links = list(field(request, "links")?)?
                .iter()
                .map(|value| text(value).map(str::to_owned))
                .collect::<Result<Vec<_>>>()?;
            particleve::dns::assess(
                field(request, "policy")?,
                field(request, "observed")?,
                &links,
            )
        }
        "timesync-assess" => particleve::timesync::assess(
            field(request, "policy")?,
            field(request, "reports")?,
            field(request, "wall")?
                .as_f64()
                .ok_or_else(|| Error::new("invalid test wall clock"))?,
        ),
        "release-validate" => particleve::release::validate(field(request, "manifest")?),
        "system-tls-download" => {
            let destination = Path::new(text(field(request, "destination")?)?);
            particleve::release::download(text(field(request, "url")?)?, destination, 65536)?;
            Ok(json!({"sha256":common::hash_file(destination, None)?}))
        }
        "system-tls-report" => particleve::reporting::deliver(
            &json!({"schema":1,"result":"healthy"}),
            text(field(request, "url")?)?,
            b"ParticleVE-disposable-trust-check00",
        ),
        "release-transfers" => Ok(json!(particleve::release::transfers(
            field(request, "manifest")?,
            text(field(request, "disk")?)?,
            Path::new(text(field(request, "source")?)?),
            text(field(request, "current")?)?
        )?)),
        "verify-uki-sections" => {
            particleve::release::verify_uki_sections(
                field(request, "sections")?,
                field(request, "manifest")?,
            )?;
            Ok(Value::Null)
        }
        "reconfigure-preview" => particleve::reconfigure::reconfigure(
            Path::new(text(field(request, "directory")?)?),
            Path::new(text(field(request, "destination")?)?),
            request.get("previous").filter(|v| !v.is_null()).cloned(),
            request.get("proposed").filter(|v| !v.is_null()).cloned(),
            None,
            request
                .get("resume")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
        "maintenance-input" => particleve::reconfigure::maintenance_input(
            field(request, "config")?.clone(),
            Path::new(text(field(request, "directory")?)?),
        ),
        "reconfigure-fixed" => particleve::reconfigure::fixed_settings(field(request, "config")?),
        "vm-inventory" => Ok(json!(particleve::vms::LinuxVMs.inventory(false)?)),
        _ => storage::evaluate(request)
            .or_else(|| orchestration::evaluate(request["operation"].as_str()?, request))
            .or_else(|| vm::evaluate(request["operation"].as_str()?, request))
            .or_else(|| host::evaluate(request))
            .unwrap_or_else(|| Err(Error::new("unknown test operation"))),
    }
}

fn main() -> Result<()> {
    let mut output = std::io::stdout().lock();
    let mut input = std::io::stdin().lock();
    loop {
        let mut line = Vec::new();
        let count = std::io::Read::take(std::io::Read::by_ref(&mut input), 8 * 1024 * 1024 + 1)
            .read_until(b'\n', &mut line)?;
        if count == 0 {
            break;
        }
        common::require(
            line.len() <= 8 * 1024 * 1024,
            "test request exceeds its size limit",
        )?;
        let response = common::parse_json(&line).and_then(|value| evaluate(&value));
        let value = match response {
            Ok(value) => json!({"ok":value}),
            Err(error) => json!({"error":error.to_string()}),
        };
        serde_json::to_writer(&mut output, &value)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}
