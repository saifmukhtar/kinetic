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
