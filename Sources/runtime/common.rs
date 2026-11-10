//! Durable JSON and owned, bounded command execution.
use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Error {
    pub message: String,
    pub deferred: bool,
    pub io_errno: Option<i32>,
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            deferred: false,
            io_errno: None,
        }
    }
    pub fn deferred(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            deferred: true,
            io_errno: None,
        }
    }
    pub fn is_errno(&self, errno: i32) -> bool {
        self.io_errno == Some(errno)
    }
    pub fn is_not_found(&self) -> bool {
        self.is_errno(libc::ENOENT)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self {
            message: e.to_string(),
            deferred: false,
            io_errno: e.raw_os_error(),
        }
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::new(e.to_string())
    }
}
impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::new(e.to_string())
    }
}
pub fn require(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::new(message))
    }
}
pub fn text(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| Error::new("expected a string"))
}
pub fn uint(v: &Value) -> Result<u64> {
    v.as_u64()
        .ok_or_else(|| Error::new("expected an unsigned integer"))
}
pub fn boolean(v: &Value) -> Result<bool> {
    v.as_bool().ok_or_else(|| Error::new("expected a boolean"))
}
pub fn list(v: &Value) -> Result<&Vec<Value>> {
    v.as_array().ok_or_else(|| Error::new("expected an array"))
}
pub fn object(v: &Value) -> Result<&Map<String, Value>> {
    v.as_object()
        .ok_or_else(|| Error::new("expected an object"))
}
pub fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
    object(v)?
        .get(key)
        .ok_or_else(|| Error::new(format!("missing field: {key}")))
}

// Read objects as raw values so serde_json's arbitrary-precision number tag
// cannot be confused with an input object containing the same private key.
struct RawObject(Map<String, Value>);
struct ObjectSeed(usize);
impl<'de> serde::de::DeserializeSeed<'de> for ObjectSeed {
    type Value = RawObject;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<RawObject, D::Error> {
        struct ObjectVisitor(usize);
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = RawObject;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object without duplicate keys")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<RawObject, A::Error> {
                let mut values = Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON key: {key}"
                        )));
                    }
                    let raw = access.next_value::<Box<serde_json::value::RawValue>>()?;
                    let value = parse_at(raw.get().as_bytes(), self.0 + 1)
                        .map_err(serde::de::Error::custom)?;
                    values.insert(key, value);
                }
                Ok(RawObject(values))
            }
        }
        d.deserialize_map(ObjectVisitor(self.0))
    }
}
fn parse_at(data: &[u8], depth: usize) -> Result<Value> {
    use serde::de::DeserializeSeed;
    require(depth <= 128, "JSON nesting exceeds its limit")?;
    let raw = serde_json::from_slice::<Box<serde_json::value::RawValue>>(data)?;
    let source = raw.get();
    match source.as_bytes().first() {
        Some(b'{') => {
            let mut parser = serde_json::Deserializer::from_str(source);
            let value = ObjectSeed(depth).deserialize(&mut parser)?.0;
            parser.end()?;
            Ok(Value::Object(value))
        }
        Some(b'[') => {
            let values = serde_json::from_str::<Vec<Box<serde_json::value::RawValue>>>(source)?;
            Ok(Value::Array(
                values
                    .iter()
                    .map(|v| parse_at(v.get().as_bytes(), depth + 1))
                    .collect::<Result<_>>()?,
            ))
        }
        Some(b'"') => Ok(Value::String(serde_json::from_str(source)?)),
        Some(b't') => Ok(Value::Bool(true)),
        Some(b'f') => Ok(Value::Bool(false)),
        Some(b'n') => Ok(Value::Null),
        _ if source.contains(['.', 'e', 'E']) => {
            let number = source
                .parse::<f64>()
                .map_err(|_| Error::new("invalid JSON number"))?;
            Ok(Value::Number(
                Number::from_f64(number).ok_or_else(|| Error::new("non-finite JSON number"))?,
            ))
        }
        _ => Ok(Value::Number(if source == "-0" {
            Number::from(0)
        } else {
            source.parse::<Number>()?
        })),
    }
}
pub fn parse_json(data: &[u8]) -> Result<Value> {
    parse_at(data, 0)
}
pub fn read_bounded(path: impl AsRef<Path>, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path.as_ref())?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    require(
        bytes.len() <= maximum,
        format!(
            "observation exceeds its size limit: {}",
            path.as_ref().display()
        ),
    )?;
    Ok(bytes)
}
pub fn read_json(path: impl AsRef<Path>) -> Result<Value> {
    parse_json(&read_bounded(path, 8 * 1024 * 1024)?)
}

fn quoted(value: &str, output: &mut String) {
    use std::fmt::Write as _;
    output.push('"');
    for c in value.chars() {
        match c {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{8}' => output.push_str("\\b"),
            '\u{c}' => output.push_str("\\f"),
            c if !(' '..'\u{7f}').contains(&c) => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    let _ = write!(output, "\\u{unit:04x}");
                }
            }
            c => output.push(c),
        }
    }
    output.push('"');
}
fn python_float(value: &Number) -> Result<String> {
    // serde_json's shortest-decimal conversion rounds ties to even. Rust's
    // Debug formatter can choose the other equally short decimal, changing
    // persisted Python digests. Keep those digits and apply Python's notation.
    let rendered = value.to_string();
    let (negative, unsigned) = rendered
        .strip_prefix('-')
        .map_or((false, rendered.as_str()), |v| (true, v));
    let (mantissa, exponent) = unsigned
        .split_once('e')
        .map_or(Ok((unsigned, 0)), |(m, e)| {
            e.parse::<i32>()
                .map(|e| (m, e))
                .map_err(|_| Error::new("invalid JSON exponent"))
        })?;
    let mut digits = mantissa.chars().filter(|c| *c != '.').collect::<String>();
    let point = mantissa.find('.').unwrap_or(mantissa.len()) as i32 + exponent;
    let first = digits.find(|c| c != '0');
    let Some(first) = first else {
        return Ok(if negative { "-0.0" } else { "0.0" }.into());
    };
    digits.drain(..first);
    while digits.ends_with('0') {
        digits.pop();
    }
    let power = point - first as i32 - 1;
    let sign = if negative { "-" } else { "" };
    if !(-4..16).contains(&power) {
        let fraction = if digits.len() == 1 {
            String::new()
        } else {
            format!(".{}", &digits[1..])
        };
        return Ok(format!("{sign}{}{fraction}e{power:+03}", &digits[..1]));
    }
    let point = power + 1;
    if point <= 0 {
        return Ok(format!("{sign}0.{}{digits}", "0".repeat((-point) as usize)));
    }
    let point = point as usize;
    if point >= digits.len() {
        return Ok(format!(
            "{sign}{digits}{}.0",
            "0".repeat(point - digits.len())
        ));
    }
    Ok(format!("{sign}{}.{}", &digits[..point], &digits[point..]))
}
fn encode(value: &Value, depth: usize, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Value::String(v) => quoted(v, out),
        Value::Number(v) => {
            if v.is_f64() {
                let number = v
                    .as_f64()
                    .ok_or_else(|| Error::new("invalid JSON number"))?;
                require(number.is_finite(), "non-finite JSON number")?;
                out.push_str(&python_float(v)?);
            } else {
                out.push_str(&v.to_string());
            }
        }
        Value::Array(values) => {
            if values.is_empty() {
                out.push_str("[]");
            } else {
                out.push_str("[\n");
                for (i, v) in values.iter().enumerate() {
                    out.push_str(&" ".repeat((depth + 1) * 2));
                    encode(v, depth + 1, out)?;
                    out.push_str(if i + 1 == values.len() { "\n" } else { ",\n" });
                }
                out.push_str(&" ".repeat(depth * 2));
                out.push(']');
            }
        }
        Value::Object(values) => {
            if values.is_empty() {
                out.push_str("{}");
            } else {
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort();
                out.push_str("{\n");
                for (i, k) in keys.iter().enumerate() {
                    out.push_str(&" ".repeat((depth + 1) * 2));
                    quoted(k, out);
                    out.push_str(": ");
                    encode(&values[*k], depth + 1, out)?;
                    out.push_str(if i + 1 == keys.len() { "\n" } else { ",\n" });
                }
                out.push_str(&" ".repeat(depth * 2));
                out.push('}');
            }
        }
    }
    Ok(())
}
pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut out = String::new();
    encode(value, 0, &mut out)?;
    out.push('\n');
    Ok(out.into_bytes())
}
pub fn hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}
pub fn digest(value: &Value) -> Result<String> {
    Ok(hex(&Sha256::digest(canonical(value)?)))
}
pub fn hash_file(path: impl AsRef<Path>, size: Option<u64>) -> Result<String> {
    let mut stream = File::open(path)?;
    let mut digest = Sha256::new();
    let mut remaining = size;
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let limit = remaining.map_or(buffer.len(), |n| n.min(buffer.len() as u64) as usize);
        if limit == 0 {
            break;
        }
        let count = stream.read(&mut buffer[..limit])?;
        if count == 0 {
            require(remaining.is_none_or(|n| n == 0), "short file read")?;
            break;
        }
        digest.update(&buffer[..count]);
        if let Some(n) = remaining.as_mut() {
            *n -= count as u64;
        }
    }
    Ok(hex(&digest.finalize()))
}
pub fn atomic_write(path: impl AsRef<Path>, data: &[u8], mode: u32) -> Result<()> {
    let path = path.as_ref();
    let parent = path
        .parent()
        .ok_or_else(|| Error::new("missing state parent"))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| Error::from(e.error))?;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?
        .sync_all()?;
    Ok(())
}
pub fn write_json(path: impl AsRef<Path>, value: &Value) -> Result<()> {
    atomic_write(path, &canonical(value)?, 0o600)
}
pub struct Lock {
    _file: File,
}
impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: this descriptor is still owned and locked here. Explicit
        // unlock releases authority even if another thread briefly inherited
        // the CLOEXEC descriptor between fork and exec.
        let _ = unsafe { libc::flock(self._file.as_raw_fd(), libc::LOCK_UN) };
    }
}
pub fn lock(directory: impl AsRef<Path>) -> Result<Lock> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory.as_ref())?;
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.as_ref().join("maintenance.lock"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    // SAFETY: this descriptor remains owned by Lock; flock neither borrows memory nor transfers ownership.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Err(Error::deferred(
                "another maintenance operation holds the lock",
            ));
        }
        return Err(error.into());
    }
    Ok(Lock { _file: file })
}

#[derive(Debug)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Only this transient command is signalled. VM runners use their separate supervisor.
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
pub fn command(
    args: &[String],
    input: Option<&[u8]>,
    timeout: Option<Duration>,
    maximum: usize,
    check: bool,
) -> Result<Output> {
    require(!args.is_empty(), "empty command")?;
    let mut child = OwnedChild(
        Command::new(&args[0])
            .args(&args[1..])
            .env("LC_ALL", "C")
            .env("SYSTEMD_PAGER", "cat")
            .env("SYSTEMD_COLORS", "0")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let mut stdin = child.0.stdin.take();
    let mut stdout = child
        .0
        .stdout
        .take()
        .map(|stream| File::from(OwnedFd::from(stream)));
    let mut stderr = child
        .0
        .stderr
        .take()
        .map(|stream| File::from(OwnedFd::from(stream)));
    for fd in [
        stdin.as_ref().map(AsRawFd::as_raw_fd),
        stdout.as_ref().map(AsRawFd::as_raw_fd),
        stderr.as_ref().map(AsRawFd::as_raw_fd),
    ]
    .into_iter()
    .flatten()
    {
        crate::platform::nonblocking(fd)?;
    }
    let deadline = timeout.map(|v| Instant::now() + v);
    let mut written = 0;
    let mut outputs = [Vec::new(), Vec::new()];
    while stdin.is_some() || stdout.is_some() || stderr.is_some() {
        if deadline.is_some_and(|v| Instant::now() >= v) {
            return Err(Error::new(format!("{} exceeded its deadline", args[0])));
        }
        let mut polls = [
            libc::pollfd {
                fd: stdin.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: stdout.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stderr.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        crate::platform::poll(&mut polls, 100)?;
        if let Some(stream) = stdin.as_mut() {
            let data = input.unwrap_or_default();
            if written == data.len() {
                stdin = None;
            } else if polls[0].revents != 0 {
                match stream.write(&data[written..]) {
                    Ok(n) => written += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => stdin = None,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        for (index, stream) in [&mut stdout, &mut stderr].into_iter().enumerate() {
            if polls[index + 1].revents == 0 {
                continue;
            }
            if let Some(reader) = stream.as_mut() {
                let mut data = [0; 65536];
                match reader.read(&mut data) {
                    Ok(0) => *stream = None,
                    Ok(n) => outputs[index].extend_from_slice(&data[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
                require(
                    outputs[0].len() + outputs[1].len() <= maximum,
                    "command output exceeds its size limit",
                )?;
            }
        }
    }
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if deadline.is_some_and(|v| Instant::now() >= v) {
            return Err(Error::new("command exit exceeded its deadline"));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    let output = Output {
        code,
        stdout: String::from_utf8(std::mem::take(&mut outputs[0]))?,
        stderr: String::from_utf8(std::mem::take(&mut outputs[1]))?,
    };
    require(
        !check || code == 0,
        format!("{} failed ({code}): {}", args[0], output.stderr.trim()),
    )?;
    Ok(output)
}
pub fn run(args: &[&str]) -> Result<Output> {
    command(
        &args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        None,
        Some(Duration::from_secs(120)),
        8 * 1024 * 1024,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn atomic_state_and_stable_lock_ownership() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let first = lock(directory.path())?;
        let inode = fs::metadata(directory.path().join("maintenance.lock"))?.ino();
        assert!(lock(directory.path()).is_err_and(|error| error.deferred));
        let state = directory.path().join("state.json");
        write_json(&state, &serde_json::json!({"attempt":1}))?;
        write_json(&state, &serde_json::json!({"attempt":2}))?;
        assert_eq!(read_json(&state)?, serde_json::json!({"attempt":2}));
        assert_eq!(fs::metadata(&state)?.mode() & 0o777, 0o600);
        drop(first);
        let _second = lock(directory.path())?;
        assert_eq!(
            inode,
            fs::metadata(directory.path().join("maintenance.lock"))?.ino()
        );
        Ok(())
    }

    #[test]
    fn captures_both_pipes_with_one_bound_and_deadline() -> Result<()> {
        let arguments = [
            "/usr/bin/python3",
            "-c",
            "import os; os.write(1,b'x'*65536); os.write(2,b'y'*65536)",
        ]
        .map(str::to_owned);
        let captured = command(&arguments, None, Some(Duration::from_secs(5)), 131072, true)?;
        assert_eq!(captured.stdout.len(), 65536);
        assert_eq!(captured.stderr.len(), 65536);
        assert!(command(&arguments, None, Some(Duration::from_secs(5)), 131071, true).is_err());
        let waiting =
            ["/usr/bin/python3", "-c", "import signal; signal.pause()"].map(str::to_owned);
        let started = Instant::now();
        assert!(command(&waiting, None, Some(Duration::from_millis(50)), 128, true).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn short_reads_and_symlinked_lock_fail_closed() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let file = directory.path().join("data");
        fs::write(&file, b"short")?;
        assert!(hash_file(&file, Some(6)).is_err());
        assert!(read_bounded(&file, 4).is_err());
        std::os::unix::fs::symlink(&file, directory.path().join("maintenance.lock"))?;
        assert!(lock(directory.path()).is_err());
        Ok(())
    }
}
