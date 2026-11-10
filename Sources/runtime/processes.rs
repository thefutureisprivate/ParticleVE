//! Bounded descriptor-relative observations remain tied to one Linux task.
use crate::common::{Error, Result, require};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    pub pid: u32,
    pub starttime: u64,
}
pub const MAX_STATUS: usize = 1024 * 1024;
pub const MAX_CMDLINE: usize = 8 * 1024 * 1024;
pub const MAX_FDS: usize = 65536;
pub const MAX_NAMESPACES: usize = 64;
pub struct Process {
    pub pid: u32,
    directory: File,
}
impl Process {
    pub fn open(pid: u32, expected: Option<u64>, proc: &Path) -> Result<Self> {
        require(pid > 0, "invalid process PID")?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(proc.join(pid.to_string()))?;
        let process = Self { pid, directory };
        if let Some(expected) = expected {
            require(
                process.identity()?.starttime == expected,
                "process identity changed during inspection",
            )?;
        }
        Ok(process)
    }
    fn descriptor(&self, name: &str, flags: i32) -> Result<OwnedFd> {
        let name = relative(name)?;
        // SAFETY: the CString is terminated, the directory is live, and the returned descriptor is uniquely owned.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: successful openat created a new descriptor that no other owner will close.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    pub fn read(&self, name: &str, maximum: usize) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        File::from(self.descriptor(name, libc::O_RDONLY)?)
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)?;
        require(
            bytes.len() <= maximum,
            "process observation exceeds its bound",
        )?;
        Ok(bytes)
    }
    pub fn text(&self, name: &str, maximum: usize) -> Result<String> {
        Ok(String::from_utf8(self.read(name, maximum)?)?)
    }
    pub fn identity(&self) -> Result<Identity> {
        let stat = self.text("stat", 65536)?;
        let (prefix, tail) = stat
            .rsplit_once(')')
            .ok_or_else(|| Error::new("invalid process stat"))?;
        require(
            prefix.starts_with(&format!("{} (", self.pid)),
            "process stat PID differs",
        )?;
        let starttime = tail
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| Error::new("missing process starttime"))?
            .parse()
            .map_err(|_| Error::new("invalid process starttime"))?;
        Ok(Identity {
            pid: self.pid,
            starttime,
        })
    }
    pub fn status(&self) -> Result<BTreeMap<String, String>> {
        let mut status = BTreeMap::new();
        for line in self.text("status", 1024 * 1024)?.lines() {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| Error::new("invalid process status"))?;
            require(
                !name.is_empty() && !status.contains_key(name),
                "invalid or duplicate process status field",
            )?;
            status.insert(name.to_owned(), value.trim().to_owned());
        }
        require(!status.is_empty(), "empty process status")?;
        Ok(status)
    }
    pub fn arguments(&self) -> Result<Vec<String>> {
        let bytes = self.read("cmdline", 8 * 1024 * 1024)?;
        let text = String::from_utf8(bytes)?;
        let trimmed = text.trim_end_matches('\0');
        Ok(if trimmed.is_empty() {
            Vec::new()
        } else {
            trimmed.split('\0').map(str::to_owned).collect()
        })
    }
    pub fn readlink(&self, name: &str) -> Result<PathBuf> {
        let name = relative(name)?;
        let mut bytes = vec![0; 65537];
        // SAFETY: readlinkat writes at most the passed initialized buffer length and retains no pointer.
        let count = unsafe {
            libc::readlinkat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if count < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        require((count as usize) < bytes.len(), "oversized process link")?;
        bytes.truncate(count as usize);
        Ok(Path::new(std::ffi::OsStr::from_bytes(&bytes)).to_owned())
    }
    pub fn stat(&self, name: &str) -> Result<std::fs::Metadata> {
        let name = relative(name)?;
        // SAFETY: descriptor-relative O_PATH follows the proc fd symlink to observe the actual
        // open object (including anonymous devices); no object data or device operation is read.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a new exclusively owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(File::from(fd).metadata()?)
    }
    pub fn entries(&self, name: &str, maximum: usize) -> Result<Vec<String>> {
        let descriptor = self.descriptor(name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        use std::os::fd::IntoRawFd;
        let raw = descriptor.into_raw_fd();
        // SAFETY: fdopendir takes ownership only on success; failure closes the still-owned descriptor below.
        let directory = unsafe { libc::fdopendir(raw) };
        if directory.is_null() {
            // SAFETY: fdopendir failed and did not consume this descriptor.
            let error = std::io::Error::last_os_error();
            drop(unsafe { OwnedFd::from_raw_fd(raw) });
            return Err(error.into());
        }
        struct Directory(*mut libc::DIR);
        impl Drop for Directory {
            fn drop(&mut self) {
                // SAFETY: this is the only owner of the successfully opened DIR.
                unsafe { libc::closedir(self.0) };
            }
        }
        let directory = Directory(directory);
        let mut result = Vec::new();
        loop {
            // SAFETY: the DIR remains live and is exclusively accessed; d_name is read before the next call.
            let entry = unsafe {
                *libc::__errno_location() = 0;
                libc::readdir(directory.0)
            };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(0) {
                    return Err(error.into());
                }
                break;
            }
            // SAFETY: readdir returns a live dirent with a NUL-terminated d_name until the next call.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
                .to_str()
                .map_err(|_| Error::new("invalid process directory encoding"))?;
            if name == "." || name == ".." {
                continue;
            }
            require(
                result.len() < maximum,
                "process directory observation exceeds its bound",
            )?;
            result.push(name.to_owned());
        }
        Ok(result)
    }
}

fn relative(name: &str) -> Result<CString> {
    require(
        !name.is_empty()
            && !name.starts_with('/')
            && name
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."),
        "invalid process observation path",
    )?;
    CString::new(name).map_err(|_| Error::new("invalid process observation path"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pins_own_identity() {
        let process = Process::open(std::process::id(), None, Path::new("/proc")).unwrap();
        let id = process.identity().unwrap();
        assert_eq!(id.pid, std::process::id());
        assert!(
            Process::open(
                id.pid,
                Some(id.starttime.wrapping_add(1)),
                Path::new("/proc")
            )
            .is_err()
        );
        assert!(process.text("../status", 65536).is_err());
        assert!(process.status().unwrap().contains_key("Uid"));
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::fs;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    fn stat(pid: u32, start: u64) -> String {
        format!(
            "{pid} (spaces and ) parentheses)) S {}{start}\n",
            "0 ".repeat(18)
        )
    }
    #[test]
    fn pinned_directory_cannot_redirect_to_a_replacement_and_closes_its_descriptor() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("123");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("status"), "Name: original\n").unwrap();
        fs::write(directory.join("stat"), stat(123, 42)).unwrap();
        let process = Process::open(123, Some(42), root.path()).unwrap();
        let descriptor = process.directory.as_raw_fd(); // SAFETY: F_GETFD only reads the live owned descriptor's flags.
        assert_ne!(
            unsafe { libc::fcntl(descriptor, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        fs::rename(&directory, root.path().join("old")).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("status"), "Name: replacement\n").unwrap();
        fs::write(directory.join("stat"), stat(123, 43)).unwrap();
        assert_eq!(process.status().unwrap()["Name"], "original");
        assert_eq!(
            process.identity().unwrap(),
            Identity {
                pid: 123,
                starttime: 42
            }
        );
        drop(process); // SAFETY: fcntl intentionally tests that the uniquely owned descriptor was closed.
        assert_eq!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        assert!(Process::open(123, Some(42), root.path()).is_err());
        let identity = Identity {
            pid: 123,
            starttime: 42,
        };
        assert!(crate::security::process_evidence(&identity, root.path()).is_err());
        assert!(crate::confinement::verify_processes(&[identity], root.path()).is_err());
    }
    #[test]
    fn reaped_native_child_never_becomes_a_successful_pinned_observation() {
        let mut child = Command::new("/usr/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let process = Process::open(child.id(), None, Path::new("/proc")).unwrap();
        assert_eq!(process.identity().unwrap().pid, child.id());
        assert_eq!(process.status().unwrap()["Pid"], child.id().to_string());
        assert!(
            process
                .entries("ns", MAX_NAMESPACES)
                .unwrap()
                .contains(&"pid".to_owned())
        );
        drop(child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("inert child did not exit after stdin EOF");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            process
                .status()
                .is_err_and(|e| e.is_not_found() || e.is_errno(libc::ESRCH))
        );
    }
    #[test]
    fn bounded_and_malformed_observations_fail_instead_of_truncating() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("123");
        fs::create_dir(&directory).unwrap();
        fs::create_dir(directory.join("fd")).unwrap();
        for name in ["1", "2", "3"] {
            fs::write(directory.join("fd").join(name), []).unwrap();
        }
        fs::write(directory.join("status"), b"Name: ab").unwrap();
        let process = Process::open(123, None, root.path()).unwrap();
        assert_eq!(process.read("status", 8).unwrap(), b"Name: ab");
        assert!(process.read("status", 7).is_err());
        assert_eq!(process.entries("fd", 3).unwrap().len(), 3);
        assert!(process.entries("fd", 2).is_err());
        assert_eq!(process.status().unwrap()["Name"], "ab");
        for bad in [
            &b""[..],
            b"Seccomp: 0\nSeccomp: 2\n",
            b"no separator\n",
            b"Name: \xff\n",
        ] {
            fs::write(directory.join("status"), bad).unwrap();
            assert!(process.status().is_err());
        }
        fs::write(directory.join("cmdline"), b"qemu\0\xff").unwrap();
        assert!(process.arguments().is_err());
        fs::remove_file(directory.join("status")).unwrap();
        std::os::unix::fs::symlink("cmdline", directory.join("status")).unwrap();
        assert!(process.status().is_err_and(|e| e.is_errno(libc::ELOOP)));
    }
}
