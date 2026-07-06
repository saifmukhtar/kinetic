//! # kinetic-storage
//!
//! Persistent key-value storage for the Kinetic daemon, backed by
//! [`sled`](https://docs.rs/sled) — a pure-Rust embedded database.
//!
//! This crate implements the [`StorageEngine`] trait from `kinetic-core`,
//! providing the daemon with durable storage for DHT routing tables, private
//! keys, and in-progress VDF states so that the daemon can survive a reboot
//! without losing state.
//!
//! ## Error handling
//!
//! On startup, if the database is detected as locked by another process,
//! [`SledStorage::new`] immediately returns [`StorageError::DatabaseLocked`]
//! rather than attempting recovery. If the database appears corrupted, it is
//! automatically renamed to `<path>.corrupt.bak` and a fresh database is
//! created in its place.

#![deny(missing_docs)]

use kinetic_core::error::StorageError;
use kinetic_core::traits::StorageEngine;
use sled::Db;
use std::path::Path;

/// A pure-Rust embedded Key-Value store using `sled`.
/// This acts as the persistent cache for the Kademlia DHT routing tables,
/// saved private keys, and in-progress VDF states so the daemon can survive a reboot.
pub struct SledStorage {
    db: Db,
}

impl SledStorage {
    /// Opens or creates the Sled database at the specified directory path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let path = path.as_ref();
        match sled::open(path) {
            Ok(db) => Ok(Self { db }),
            Err(e) => {
                let err_str = e.to_string().to_lowercase();

                // Locked database: another daemon process is already running. Do not recover.
                if err_str.contains("lock")
                    || err_str.contains("resource temporarily unavailable")
                    || err_str.contains("in use")
                    || err_str.contains("would block")
                {
                    return Err(StorageError::DatabaseLocked);
                }

                // Corrupted database: rename to .bak and open a fresh one.
                let mut bak_path = path.to_path_buf().into_os_string();
                bak_path.push(".corrupt.bak");

                let _ = std::fs::remove_dir_all(&bak_path);
                if std::fs::rename(path, &bak_path).is_ok() {
                    if let Ok(db) = sled::open(path) {
                        return Ok(Self { db });
                    }
                }

                Err(StorageError::OperationFailed(e.to_string()))
            }
        }
    }

    /// Iterate over all key-value pairs whose key starts with `prefix`.
    /// Returns an owned iterator of (key_bytes, value_bytes) pairs.
    #[allow(clippy::type_complexity)]
    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let iter = self.db.scan_prefix(prefix);
        let mut results = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(|e| StorageError::OperationFailed(e.to_string()))?;
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }
}

impl StorageEngine for SledStorage {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.db
            .insert(key, value)
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
        // Flush is intentionally omitted: sled persists asynchronously to avoid
        // blocking Tokio worker threads on every write.
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let res = self
            .db
            .get(key)
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
        Ok(res.map(|ivec| ivec.to_vec()))
    }

    fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        self.db
            .remove(key)
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sled_put_get_delete() {
        let dir = tempdir().unwrap();
        let storage = SledStorage::new(dir.path()).unwrap();

        let key = b"test_key";
        let val = b"test_value";

        storage.put(key, val).unwrap();

        let res = storage.get(key).unwrap();
        assert_eq!(res, Some(val.to_vec()));

        storage.delete(key).unwrap();
        let res2 = storage.get(key).unwrap();
        assert_eq!(res2, None);
    }

    #[test]
    fn test_sled_scan_prefix() {
        let dir = tempdir().unwrap();
        let storage = SledStorage::new(dir.path()).unwrap();

        storage.put(b"prefix:1", b"val1").unwrap();
        storage.put(b"prefix:2", b"val2").unwrap();
        storage.put(b"other:1", b"val3").unwrap();

        let mut results = storage.scan_prefix(b"prefix:").unwrap();
        results.sort();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0], (b"prefix:1".to_vec(), b"val1".to_vec()));
        assert_eq!(results[1], (b"prefix:2".to_vec(), b"val2".to_vec()));
    }
}
