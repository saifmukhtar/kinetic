use kinetic_core::traits::StorageEngine;
use kinetic_core::KineticError;
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
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, KineticError> {
        let db = sled::open(path).map_err(|e| KineticError::StorageError(e.to_string()))?;
        Ok(Self { db })
    }

    /// Iterate over all key-value pairs whose key starts with `prefix`.
    /// Returns an owned iterator of (key_bytes, value_bytes) pairs.
    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, KineticError> {
        let iter = self.db.scan_prefix(prefix);
        let mut results = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(|e| KineticError::StorageError(e.to_string()))?;
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }
}

impl StorageEngine for SledStorage {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KineticError> {
        self.db
            .insert(key, value)
            .map_err(|e| KineticError::StorageError(e.to_string()))?;
        // Flush immediately to ensure durability across sudden daemon crashes
        self.db
            .flush()
            .map_err(|e| KineticError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KineticError> {
        let res = self
            .db
            .get(key)
            .map_err(|e| KineticError::StorageError(e.to_string()))?;
        Ok(res.map(|ivec| ivec.to_vec()))
    }

    fn delete(&self, key: &[u8]) -> Result<(), KineticError> {
        self.db
            .remove(key)
            .map_err(|e| KineticError::StorageError(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| KineticError::StorageError(e.to_string()))?;
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
        
        // Put
        storage.put(key, val).unwrap();
        
        // Get
        let res = storage.get(key).unwrap();
        assert_eq!(res, Some(val.to_vec()));
        
        // Delete
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
