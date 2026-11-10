//! The TLS sender must deny filesystem writes after its irreversible handoff.
use crate::common::{Result, require};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
pub const MIN_ABI: i64 = 5;
pub const FS_WRITES: u64 = (1 << 1) | (((1u64 << 16) - 1) & !((1u64 << 4) - 1));
fn checked_abi(abi: i64) -> Result<i64> {
    require(abi >= MIN_ABI, "Landlock ABI 5 or newer must be enabled")?;
    Ok(abi)
}
pub fn abi_version() -> Result<i64> {
    // SAFETY: supported x86-64 Linux UAPI; VERSION reads no attribute pointer.
    checked_abi(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32,
        )
    })
}
fn close_inherited() -> Result<()> {
    // SAFETY: only the sealed input and diagnostics remain in the protocol. The
    // caller has dropped directory iterators and owns no Rust descriptor above2.
    require(
        unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } == 0,
        "cannot close inherited sender descriptors",
    )
}
fn create_ruleset(attributes: u64) -> Result<OwnedFd> {
    // SAFETY: the ABI5 ruleset prefix is one aligned live u64, retained only for this call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attributes as *const u64,
            std::mem::size_of::<u64>(),
            0u32,
        )
    };
    require(fd >= 0, "cannot create sender filesystem ruleset")?;
    // SAFETY: successful creation returned one uniquely owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}
fn restrict_self(fd: &OwnedFd) -> Result<()> {
    // SAFETY: the descriptor stays live; the caller already set no-new-privileges.
    require(
        unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd.as_raw_fd(), 0u32) } == 0,
        "cannot enforce sender filesystem ruleset",
    )
}
fn confine_sequence<D, A, C, R, S>(
    threads: usize,
    abi: A,
    close: C,
    create: R,
    restrict: S,
) -> Result<i64>
where
    A: FnOnce() -> Result<i64>,
    C: FnOnce() -> Result<()>,
    R: FnOnce(u64) -> Result<D>,
    S: FnOnce(&D) -> Result<()>,
{
    require(threads == 1, "sender must be single-threaded at handoff")?;
    let abi = abi()?;
    close()?;
    let ruleset = create(FS_WRITES)?;
    restrict(&ruleset)?;
    Ok(abi)
}
pub fn confine_filesystem() -> Result<i64> {
    let tasks = {
        // DirEntry retains its read_dir descriptor on Unix. Drop every entry
        // before close_range so no standard-library owner outlives that close.
        let entries = std::fs::read_dir("/proc/self/task")?.collect::<std::io::Result<Vec<_>>>()?;
        entries.len()
    };
    confine_sequence(
        tasks,
        abi_version,
        close_inherited,
        create_ruleset,
        restrict_self,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Error;
    use std::cell::{Cell, RefCell};
    #[test]
    fn old_or_unavailable_abi_never_selects_a_reduced_profile() {
        for abi in [-1, 0, 1, 4] {
            assert!(checked_abi(abi).is_err());
        }
        assert_eq!(checked_abi(5).unwrap(), 5);
    }
    #[test]
    fn sibling_threads_fail_before_any_kernel_operation() {
        assert!(
            confine_sequence(
                2,
                || panic!("must reject before ABI query"),
                || Ok(()),
                |_| Ok(()),
                |_| Ok(())
            )
            .is_err()
        );
    }
    struct Ruleset<'a>(&'a Cell<bool>);
    impl Drop for Ruleset<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    #[test]
    fn complete_rights_are_enforced_in_order_and_owned_rulesets_close_on_failure() {
        for failure in [None, Some("close"), Some("create"), Some("restrict")] {
            let events = RefCell::new(Vec::new());
            let dropped = Cell::new(false);
            let result = confine_sequence(
                1,
                || {
                    events.borrow_mut().push("abi");
                    Ok(10)
                },
                || {
                    events.borrow_mut().push("close");
                    if failure == Some("close") {
                        Err(Error::new("close"))
                    } else {
                        Ok(())
                    }
                },
                |rights| {
                    events.borrow_mut().push("create");
                    assert_eq!(rights, (1 << 1) | (4..16).map(|bit| 1 << bit).sum::<u64>());
                    if failure == Some("create") {
                        Err(Error::new("create"))
                    } else {
                        Ok(Ruleset(&dropped))
                    }
                },
                |_| {
                    events.borrow_mut().push("restrict");
                    if failure == Some("restrict") {
                        Err(Error::new("restrict"))
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(result.is_err(), failure.is_some());
            assert_eq!(
                dropped.get(),
                failure.is_none() || failure == Some("restrict")
            );
            let expected = match failure {
                Some("close") => vec!["abi", "close"],
                Some("create") => vec!["abi", "close", "create"],
                _ => vec!["abi", "close", "create", "restrict"],
            };
            assert_eq!(*events.borrow(), expected);
        }
    }
}
