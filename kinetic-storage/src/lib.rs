//! # kinetic-storage
//!
//! Persistent key-value storage for the Kinetic daemon, backed by
//! [`sled`](https://docs.rs/sled) — a pure-Rust embedded database on native,
//! and an in-memory BTreeMap on Wasm.

#![deny(missing_docs)]

use kinetic_core::error::StorageError;
use kinetic_core::traits::StorageEngine;
use std::path::Path;

#[cfg(not(target_arch = "wasm32"))]
pub use native::*;
#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use sled::Db;

    /// A pure-Rust embedded Key-Value store using `sled`.
    pub struct SledStorage {
        db: Db,
    }

    impl SledStorage {
        /// Opens or creates the Sled database at the specified directory path.
        ///
        /// # Errors
        /// Returns a `StorageError` if the database cannot be opened, is locked by another process, or encounters corruption.
        pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
            let path = path.as_ref();
            match sled::open(path) {
                Ok(db) => Ok(Self { db }),
                Err(sled::Error::Io(e)) => {
                    let kind = e.kind();
                    if kind == std::io::ErrorKind::WouldBlock
                        || kind == std::io::ErrorKind::PermissionDenied
                    {
                        return Err(StorageError::DatabaseLocked);
                    }
                    // Fallback for platform-specific locks
                    let err_str = e.to_string().to_lowercase();
                    if err_str.contains("resource temporarily unavailable")
                        || err_str.contains("in use")
                    {
                        return Err(StorageError::DatabaseLocked);
                    }
                    Err(StorageError::OperationFailed(format!("IO error: {}", e)))
                }
                Err(sled::Error::Corruption { .. }) => {
                    static CORRUPT_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                    let count = CORRUPT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    let mut bak_path = path.to_path_buf().into_os_string();
                    bak_path.push(format!(".corrupt.{}_{}_{}.bak", ts, std::process::id(), count));

                    tracing::error!(
                        "CRITICAL: Sled database corruption detected at {:?}. Backing up to {:?}",
                        path,
                        bak_path
                    );

                    if let Err(e) = std::fs::rename(path, &bak_path) {
                        return Err(StorageError::OperationFailed(format!(
                            "Database corrupted. Failed to backup corrupted database: {}. Manual intervention required.",
                            e
                        )));
                    }

                    Err(StorageError::OperationFailed(format!(
                        "Database corrupted. Manual recovery required. Backup moved to {:?}",
                        bak_path
                    )))
                }
                Err(e) => Err(StorageError::OperationFailed(e.to_string())),
            }
        }

        /// Opens an in-memory temporary database.
        ///
        /// # Errors
        /// Returns a `StorageError` if the temporary database cannot be created or opened.
        pub fn new_temp() -> Result<Self, StorageError> {
            let db = sled::Config::new()
                .temporary(true)
                .open()
                .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
            Ok(Self { db })
        }
    }

    impl StorageEngine for SledStorage {
        fn scan_prefix(
            &self,
            prefix: &[u8],
            limit: Option<usize>,
        ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            let iter = self.db.scan_prefix(prefix);
            let mut results = Vec::new();
            for item in iter {
                if let Some(l) = limit {
                    if results.len() >= l {
                        break;
                    }
                }
                let (k, v) = item.map_err(|e| StorageError::OperationFailed(e.to_string()))?;
                results.push((k.to_vec(), v.to_vec()));
            }
            Ok(results)
        }

        fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            self.db
                .insert(key, value)
                .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
            Ok(())
        }

        fn get(&self, key: &[u8]) -> Result<Option<bytes::Bytes>, StorageError> {
            let res = self
                .db
                .get(key)
                .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
            Ok(res.map(|ivec| bytes::Bytes::copy_from_slice(&ivec)))
        }

        fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
            self.db
                .remove(key)
                .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
            Ok(())
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::RwLock;

    /// An in-memory Key-Value store for Wasm.
    pub struct SledStorage {
        db: RwLock<BTreeMap<Vec<u8>, Vec<u8>>>,
    }

    impl SledStorage {
        /// Mock new for Wasm
        ///
        /// # Errors
        /// Returns a `StorageError` if initialization fails (currently always succeeds).
        pub fn new<P: AsRef<Path>>(_path: P) -> Result<Self, StorageError> {
            Ok(Self {
                db: RwLock::new(BTreeMap::new()),
            })
        }

        /// Mock new_temp for Wasm
        ///
        /// # Errors
        /// Returns a `StorageError` if initialization fails (currently always succeeds).
        pub fn new_temp() -> Result<Self, StorageError> {
            Ok(Self {
                db: RwLock::new(BTreeMap::new()),
            })
        }
    }

    impl StorageEngine for SledStorage {
        fn scan_prefix(
            &self,
            prefix: &[u8],
            limit: Option<usize>,
        ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            let db = self
                .db
                .read()
                .map_err(|_| StorageError::OperationFailed("Lock poisoned".into()))?;
            let mut results = Vec::new();
            for (k, v) in db.range(prefix.to_vec()..) {
                if let Some(l) = limit {
                    if results.len() >= l {
                        break;
                    }
                }
                if k.starts_with(prefix) {
                    results.push((k.clone(), v.clone()));
                } else {
                    break;
                }
            }
            Ok(results)
        }

        fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            let mut db = self
                .db
                .write()
                .map_err(|_| StorageError::OperationFailed("Lock poisoned".into()))?;
            
            if db.len() >= 10_000 && !db.contains_key(key) {
                return Err(StorageError::OperationFailed(
                    "WASM storage quota exceeded (10,000 keys). Cannot insert new keys.".into(),
                ));
            }
            
            db.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn get(&self, key: &[u8]) -> Result<Option<bytes::Bytes>, StorageError> {
            let db = self
                .db
                .read()
                .map_err(|_| StorageError::OperationFailed("Lock poisoned".into()))?;
            Ok(db.get(key).map(|v| bytes::Bytes::copy_from_slice(v)))
        }

        fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
            let mut db = self
                .db
                .write()
                .map_err(|_| StorageError::OperationFailed("Lock poisoned".into()))?;
            db.remove(key);
            Ok(())
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
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
        assert_eq!(res, Some(bytes::Bytes::copy_from_slice(val)));

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

        let mut results = storage.scan_prefix(b"prefix:", None).unwrap();
        results.sort();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0], (b"prefix:1".to_vec(), b"val1".to_vec()));
        assert_eq!(results[1], (b"prefix:2".to_vec(), b"val2".to_vec()));
    }
}
