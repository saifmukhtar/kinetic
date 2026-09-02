//! # kinetic-storage
//!
//! Persistent key-value storage for the Kinetic daemon, backed by
//! [`redb`](https://docs.rs/redb) — a pure-Rust embedded database on native,
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
    use redb::{Database, ReadableDatabase, TableDefinition};

    const KINETIC_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("kinetic_state");

    /// A pure-Rust embedded Key-Value store using `redb`.
    pub struct KineticStorage {
        db: Database,
    }

    impl KineticStorage {
        /// Opens or creates the Redb database at the specified directory path.
        ///
        /// # Errors
        ///
        /// - Returns [`StorageError::DatabaseLocked`](kinetic_core::error::StorageError::DatabaseLocked) (`KIN-DBE-001`) if the database directory is already opened by another process.
        /// - Returns [`StorageError::OpenFailed`](kinetic_core::error::StorageError::OpenFailed) (`KIN-DBE-007`) if IO errors occur.
        pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
            let base_path = path.as_ref();
            // Older storage engines used directories, Redb uses a single file. For backward compatibility
            // with the rest of the workspace, we treat the input as a directory and append a filename.
            let db_path = base_path.join("state.redb");

            // Create the directory if it doesn't exist to prevent IO errors
            if let Some(parent) = db_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| StorageError::OpenFailed(e.to_string()))?;
            }

            match Database::create(&db_path) {
                Ok(db) => {
                    // Ensure the table exists
                    let write_txn = db
                        .begin_write()
                        .map_err(|e| StorageError::OpenFailed(e.to_string()))?;
                    {
                        write_txn
                            .open_table(KINETIC_TABLE)
                            .map_err(|e| StorageError::OpenFailed(e.to_string()))?;
                    }
                    write_txn
                        .commit()
                        .map_err(|e| StorageError::OpenFailed(e.to_string()))?;
                    Ok(Self { db })
                }
                Err(e) => {
                    let err_str = e.to_string().to_lowercase();
                    if err_str.contains("lock")
                        || err_str.contains("resource temporarily unavailable")
                        || err_str.contains("would block")
                        || err_str.contains("already open")
                    {
                        return Err(StorageError::DatabaseLocked);
                    }
                    if err_str.contains("corrupt")
                        || err_str.contains("invalid magic number")
                        || err_str.contains("magic number mismatch")
                    {
                        static CORRUPT_COUNTER: std::sync::atomic::AtomicU64 =
                            std::sync::atomic::AtomicU64::new(0);
                        let count =
                            CORRUPT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);

                        let mut bak_path = base_path.to_path_buf();
                        let mut new_name = bak_path.file_name().unwrap_or_default().to_os_string();
                        new_name.push(format!(
                            ".corrupt.{}_{}_{}.bak",
                            ts,
                            std::process::id(),
                            count
                        ));
                        bak_path.set_file_name(new_name);

                        let err = StorageError::Corruption("CRITICAL: Embedded database corruption detected".to_string());
                        tracing::error!(
                            error_code = err.code(),
                            "CRITICAL: Embedded database corruption detected at {:?}. Backing up to {:?}",
                            base_path,
                            bak_path
                        );

                        if let Err(err) = std::fs::rename(base_path, &bak_path) {
                            return Err(StorageError::OpenFailed(format!(
                                "Database corrupted. Failed to backup corrupted database: {}. Manual intervention required.",
                                err
                            )));
                        }

                        return Err(StorageError::OpenFailed(format!(
                            "Database corrupted. Manual recovery required. Backup moved to {:?}",
                            bak_path
                        )));
                    }
                    Err(StorageError::OpenFailed(e.to_string()))
                }
            }
        }

        /// Opens an in-memory temporary database.
        ///
        /// # Errors
        ///
        /// - Returns [`StorageError::OpenFailed`](kinetic_core::error::StorageError::OpenFailed) (`KIN-DBE-007`) if temporary storage creation fails.
        pub fn new_temp() -> Result<Self, StorageError> {
            let temp_path = std::env::temp_dir().join(format!(
                "kinetic-temp-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            Self::new(temp_path)
        }
    }

    impl StorageEngine for KineticStorage {
        /// Scans all keys starting with the specified prefix, up to an optional count limit.
        ///
        /// # Errors
        ///
        /// - Returns [`StorageError::ScanFailed`](kinetic_core::error::StorageError::ScanFailed) (`KIN-DBE-006`) if iteration fails.
        fn scan_prefix(
            &self,
            prefix: &[u8],
            limit: Option<usize>,
        ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            let read_txn = self
                .db
                .begin_read()
                .map_err(|e| StorageError::ScanFailed(e.to_string()))?;
            let table = read_txn
                .open_table(KINETIC_TABLE)
                .map_err(|e| StorageError::ScanFailed(e.to_string()))?;

            let mut results = Vec::new();
            let range = table
                .range(prefix..)
                .map_err(|e| StorageError::ScanFailed(e.to_string()))?;

            for item in range {
                let (k, v) = item.map_err(|e| StorageError::ScanFailed(e.to_string()))?;
                let k_val = k.value();
                if !k_val.starts_with(prefix) {
                    break;
                }
                if let Some(l) = limit
                    && results.len() >= l
                {
                    break;
                }
                results.push((k_val.to_vec(), v.value().to_vec()));
            }
            Ok(results)
        }

        /// Inserts or overwrites a key-value pair in Redb.
        ///
        /// # Errors
        ///
        /// - Returns [`StorageError::WriteFailed`](kinetic_core::error::StorageError::WriteFailed) (`KIN-DBE-004`) if insertion fails.
        fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            let write_txn = self
                .db
                .begin_write()
                .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(KINETIC_TABLE)
                    .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
                table
                    .insert(key, value)
                    .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
            }
            write_txn
                .commit()
                .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
            Ok(())
        }

        /// Retrieves the value associated with a key from Redb.
        ///
        /// # Errors
        ///
        /// - Returns [`StorageError::ReadFailed`](kinetic_core::error::StorageError::ReadFailed) (`KIN-DBE-003`) if lookup fails.
        fn get(&self, key: &[u8]) -> Result<Option<bytes::Bytes>, StorageError> {
            let read_txn = self
                .db
                .begin_read()
                .map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            let table = read_txn
                .open_table(KINETIC_TABLE)
                .map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            let value = table
                .get(key)
                .map_err(|e| StorageError::ReadFailed(e.to_string()))?;

            Ok(value.map(|v| bytes::Bytes::copy_from_slice(v.value())))
        }

        /// Removes a key-value pair from Redb.
        ///
        /// # Errors
        ///
        /// - Returns [`StorageError::DeleteFailed`](kinetic_core::error::StorageError::DeleteFailed) (`KIN-DBE-005`) if deletion fails.
        fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
            let write_txn = self
                .db
                .begin_write()
                .map_err(|e| StorageError::DeleteFailed(e.to_string()))?;
            {
                let mut table = write_txn
                    .open_table(KINETIC_TABLE)
                    .map_err(|e| StorageError::DeleteFailed(e.to_string()))?;
                table
                    .remove(key)
                    .map_err(|e| StorageError::DeleteFailed(e.to_string()))?;
            }
            write_txn
                .commit()
                .map_err(|e| StorageError::DeleteFailed(e.to_string()))?;
            Ok(())
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::RwLock;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::FileSystemSyncAccessHandle;

    /// A wrapper for the OPFS handle to allow Send + Sync
    /// since WASM is single-threaded (without atomics) and we need to satisfy traits.
    struct OpfsHandleWrapper(Option<FileSystemSyncAccessHandle>);

    unsafe impl Send for OpfsHandleWrapper {}
    unsafe impl Sync for OpfsHandleWrapper {}

    /// An OPFS-backed Append-Only Log Key-Value store for Wasm.
    pub struct KineticStorage {
        db: RwLock<BTreeMap<Vec<u8>, Vec<u8>>>,
        opfs_handle: RwLock<OpfsHandleWrapper>,
    }

    impl KineticStorage {
        /// Fallback in-memory init if OPFS is not used.
        pub fn new<P: AsRef<Path>>(_path: P) -> Result<Self, StorageError> {
            Ok(Self {
                db: RwLock::new(BTreeMap::new()),
                opfs_handle: RwLock::new(OpfsHandleWrapper(None)),
            })
        }

        /// Fallback in-memory init for temporary storage.
        pub fn new_temp() -> Result<Self, StorageError> {
            Ok(Self {
                db: RwLock::new(BTreeMap::new()),
                opfs_handle: RwLock::new(OpfsHandleWrapper(None)),
            })
        }

        /// Asynchronously initializes the OPFS storage, reading the append-only log into memory.
        pub async fn init_opfs(db_name: &str) -> Result<Self, StorageError> {
            let window = web_sys::window()
                .ok_or_else(|| StorageError::OpenFailed("No window/worker context".into()))?;
            let navigator = window.navigator();
            let storage = navigator.storage();

            let root_dir_promise = storage.get_directory();
            let root_dir_val = JsFuture::from(root_dir_promise)
                .await
                .map_err(|e| StorageError::OpenFailed(format!("{:?}", e)))?;
            let root_dir: web_sys::FileSystemDirectoryHandle = root_dir_val.into();

            let opts = web_sys::FileSystemGetFileOptions::new();
            opts.set_create(true);
            let get_file_promise = root_dir.get_file_handle_with_options(db_name, &opts);
            let file_handle_val = JsFuture::from(get_file_promise)
                .await
                .map_err(|e| StorageError::OpenFailed(format!("{:?}", e)))?;
            let file_handle: web_sys::FileSystemFileHandle = file_handle_val.into();

            let access_promise = file_handle.create_sync_access_handle();
            let access_val = JsFuture::from(access_promise)
                .await
                .map_err(|e| StorageError::OpenFailed(format!("{:?}", e)))?;
            let handle: web_sys::FileSystemSyncAccessHandle = access_val.into();

            let file_size = handle
                .get_size()
                .map_err(|e| StorageError::OpenFailed(format!("{:?}", e)))?
                as usize;

            let mut db = BTreeMap::new();

            if file_size > 0 {
                let mut buffer = vec![0u8; file_size];
                let opts = web_sys::FileSystemReadWriteOptions::new();
                opts.set_at(0.0);
                handle
                    .read_with_u8_array_and_options(&mut buffer, &opts)
                    .map_err(|e| StorageError::OpenFailed(format!("{:?}", e)))?;

                let mut cursor = 0;
                while cursor < buffer.len() {
                    if cursor + 4 > buffer.len() {
                        break;
                    }
                    let key_len = u32::from_le_bytes(buffer[cursor..cursor + 4].try_into().unwrap())
                        as usize;
                    cursor += 4;

                    if cursor + key_len > buffer.len() {
                        break;
                    }
                    let key = buffer[cursor..cursor + key_len].to_vec();
                    cursor += key_len;

                    if cursor + 4 > buffer.len() {
                        break;
                    }
                    let val_len = u32::from_le_bytes(buffer[cursor..cursor + 4].try_into().unwrap())
                        as usize;
                    cursor += 4;

                    if val_len == 0xFFFF_FFFF {
                        // Tombstone
                        db.remove(&key);
                    } else {
                        if cursor + val_len > buffer.len() {
                            break;
                        }
                        let val = buffer[cursor..cursor + val_len].to_vec();
                        cursor += val_len;
                        db.insert(key, val);
                    }
                }
            }

            Ok(Self {
                db: RwLock::new(db),
                opfs_handle: RwLock::new(OpfsHandleWrapper(Some(handle))),
            })
        }

        fn append_to_log(&self, key: &[u8], value: Option<&[u8]>) -> Result<(), StorageError> {
            let opfs = self
                .opfs_handle
                .read()
                .map_err(|_| StorageError::WriteFailed("Lock poisoned".into()))?;
            if let Some(handle) = &opfs.0 {
                let mut payload = Vec::new();
                payload.extend_from_slice(&(key.len() as u32).to_le_bytes());
                payload.extend_from_slice(key);

                if let Some(v) = value {
                    payload.extend_from_slice(&(v.len() as u32).to_le_bytes());
                    payload.extend_from_slice(v);
                } else {
                    payload.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
                }

                let size = handle
                    .get_size()
                    .map_err(|e| StorageError::WriteFailed(format!("{:?}", e)))?;
                let opts = web_sys::FileSystemReadWriteOptions::new();
                opts.set_at(size as f64);
                handle
                    .write_with_u8_array_and_options(&mut payload, &opts)
                    .map_err(|e| StorageError::WriteFailed(format!("{:?}", e)))?;
                handle
                    .flush()
                    .map_err(|e| StorageError::WriteFailed(format!("{:?}", e)))?;
            }
            Ok(())
        }
    }

    impl StorageEngine for KineticStorage {
        fn scan_prefix(
            &self,
            prefix: &[u8],
            limit: Option<usize>,
        ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            let db = self
                .db
                .read()
                .map_err(|_| StorageError::ScanFailed("Lock poisoned".into()))?;
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
                .map_err(|_| StorageError::WriteFailed("Lock poisoned".into()))?;
            
            // Check quota only if this is an in-memory session (no OPFS handle)
            let is_opfs_active = self.opfs_handle.read().map(|h| h.0.is_some()).unwrap_or(false);
            if !is_opfs_active && db.len() >= 10_000 && !db.contains_key(key) {
                return Err(StorageError::WriteFailed(
                    "WASM storage quota exceeded (10,000 keys). Cannot insert new keys.".into(),
                ));
            }

            db.insert(key.to_vec(), value.to_vec());

            // Sync to OPFS
            self.append_to_log(key, Some(value))?;

            Ok(())
        }

        fn get(&self, key: &[u8]) -> Result<Option<bytes::Bytes>, StorageError> {
            let db = self
                .db
                .read()
                .map_err(|_| StorageError::ReadFailed("Lock poisoned".into()))?;
            Ok(db.get(key).map(|v| bytes::Bytes::copy_from_slice(v)))
        }

        fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
            let mut db = self
                .db
                .write()
                .map_err(|_| StorageError::DeleteFailed("Lock poisoned".into()))?;
            db.remove(key);

            // Sync tombstone to OPFS
            self.append_to_log(key, None)?;

            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_wasm_storage_quota_exhaustion() {
            let storage = KineticStorage::new_temp().unwrap();

            // Insert 10,000 keys (the quota limit)
            for i in 0..10_000 {
                let key = format!("key_{}", i);
                storage.put(key.as_bytes(), b"val").unwrap();
            }

            // Attempting to insert the 10,001st key should fail with the quota error
            let result = storage.put(b"key_10001", b"val");

            assert!(
                result.is_err(),
                "WASM Storage failed to enforce the 10,000 key limit!"
            );

            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("WASM storage quota exceeded"),
                "Expected WASM quota error, got: {}",
                err_msg
            );

            // However, overwriting an existing key should still succeed, as it doesn't increase length
            assert!(storage.put(b"key_0", b"new_val").is_ok());
        }
    }
}
