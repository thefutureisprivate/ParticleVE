//! Audited Linux ABI calls. Descriptors stay owned by the caller.
use crate::common::{Result, require};
pub fn nonblocking(fd: i32) -> Result<()> {
    // SAFETY: fcntl only reads/changes flags on this live, caller-owned descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: F_SETFL takes an integer argument, not a pointer.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
pub fn poll(fds: &mut [libc::pollfd], timeout: i32) -> Result<()> {
    // SAFETY: poll receives exactly the initialized, mutable slice length and cannot retain its pointer.
    let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    Ok(())
}
pub fn no_new_privileges() -> Result<()> {
    // SAFETY: PR_SET_NO_NEW_PRIVS uses a scalar flag; unused arguments are explicitly zero.
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    require(result == 0, "cannot enforce no-new-privileges")
}
