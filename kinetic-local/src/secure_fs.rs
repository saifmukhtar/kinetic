//! Secure filesystem utilities for atomic, permissions-enforced secret storage.

use std::path::Path;

/// Safely writes cryptographic material to disk using an atomic `.tmp` swap and POSIX `0o600` permissions.
///
/// This guarantees that:
/// 1. The key is never partially written if the node crashes or loses power.
/// 2. No other user on the OS can read the key while it's being written or after it's persisted.
#[cfg(unix)]
pub fn write_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);

    let mut f = options.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;

    std::fs::rename(tmp, path)
}

/// Fallback for non-Unix environments.
#[cfg(not(unix))]
pub fn write_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}
