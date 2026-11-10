//! Test-only entry points for compiled host policies and disposable observations.
use particleve::common::{Error, Result, field, list, text};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
fn path<'a>(request: &'a Value, name: &str) -> Result<&'a Path> {
    Ok(Path::new(text(field(request, name)?)?))
}
fn links(request: &Value) -> Result<Vec<String>> {
    list(field(request, "links")?)?
        .iter()
        .map(|value| text(value).map(str::to_owned))
        .collect()
}
fn backend(request: &Value) -> Result<particleve::linux::Linux> {
    let directory = path(request, "directory")?.to_path_buf();
    Ok(particleve::linux::Linux {
        config: field(request, "config")?.clone(),
        manifest: request
            .get("manifest")
            .cloned()
            .unwrap_or_else(|| json!({})),
        cache: directory.join("releases"),
        directory,
        keyring: PathBuf::from("public-keyring"),
        certificate: PathBuf::from("public-certificate"),
    })
}
pub fn evaluate(operation: &str, request: &Value) -> Option<Result<Value>> {
    if !matches!(
        operation,
        "physical-collect"
            | "radio-validate"
            | "radio-render"
            | "resource-pressure"
            | "resource-counters"
            | "resource-devices"
            | "resource-controllers"
            | "resource-memory"
            | "resource-virtual-machines"
            | "resource-oom-events"
            | "timesync-render"
            | "timesync-check"
            | "dns-validate"
            | "dns-endpoint"
            | "reconfigure-status"
            | "reconfigure-apply"
            | "disable-automation"
            | "check-commissioned"
            | "linux-release"
            | "reporting-journal"
            | "reporting-sender"
            | "reporting-deliver"
    ) {
        return None;
    }
    Some((|| match operation {
        "physical-collect" => particleve::physical::collect(path(request, "sysfs")?),
        "radio-validate" => {
            particleve::radio::validate(field(request, "policy")?)?;
            Ok(field(request, "policy")?.clone())
        }
        "radio-render" => Ok(json!(particleve::radio::render(field(request, "policy")?)?)),
        "resource-pressure" => particleve::resourceusage::pressure(path(request, "path")?),
        "resource-counters" => particleve::resourceusage::numbers(text(field(request, "text")?)?),
        "resource-devices" => particleve::resourceusage::devices(text(field(request, "text")?)?),
        "resource-controllers" => Ok(json!(particleve::resourceusage::controllers(path(
            request, "root"
        )?)?)),
        "resource-memory" => particleve::resources::parse_memory(text(field(request, "text")?)?),
        "resource-virtual-machines" => Ok(json!(particleve::resourceusage::virtual_machines(
            path(request, "root")?
        )?)),
        "resource-oom-events" => particleve::resourceusage::oom_events(),
        "timesync-render" => Ok(json!(particleve::timesync::render(field(
            request, "policy"
        )?)?)),
        "timesync-check" => {
            particleve::timesync::check_configuration(
                field(request, "policy")?,
                path(request, "root")?,
            )?;
            Ok(Value::Null)
        }
        "dns-validate" => {
            particleve::dns::validate(field(request, "policy")?, &links(request)?)?;
            Ok(Value::Null)
        }
        "dns-endpoint" => Ok(json!(particleve::dns::endpoint(field(request, "server")?)?)),
        "reconfigure-status" => particleve::reconfigure::binding_status(
            path(request, "config_path")?,
            path(request, "directory")?,
        ),
        "reconfigure-apply" => particleve::reconfigure::reconfigure(
            path(request, "directory")?,
            path(request, "destination")?,
            request.get("previous").filter(|v| !v.is_null()).cloned(),
            request.get("proposed").filter(|v| !v.is_null()).cloned(),
            request.get("confirm").map(text).transpose()?,
            request
                .get("resume")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
        "disable-automation" => {
            particleve::reconfigure::disable_automation(path(request, "directory")?)
        }
        "check-commissioned" => {
            backend(request)?.check_commissioned()?;
            Ok(Value::Null)
        }
        "linux-release" => backend(request)?.release(request.get("version").map(text).transpose()?),
        "reporting-journal" => particleve::reporting::journal(),
        "reporting-sender" => particleve::reporting::sender_main(),
        "reporting-deliver" => particleve::reporting::deliver(
            field(request, "report")?,
            text(field(request, "endpoint")?)?,
            text(field(request, "token")?)?.as_bytes(),
        ),
        _ => Err(Error::new("unknown orchestration test operation")),
    })())
}
