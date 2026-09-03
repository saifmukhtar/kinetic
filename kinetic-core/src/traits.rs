//! Core trait abstractions and dependency inversion interfaces for the Kinetic engine.
//!
//! Defines the abstract contracts for Kinetic's three primary pluggable backends:
//!
//! - `VdfEngine`: CPU-bound Wesolowski VDF proof evaluation and verification.
//! - `StorageEngine`: Key-value persistence and prefix scanning (B-tree storage engine).
//! - `GovernanceEngine`: Protocol proposal verification and state transitions.
//!
//! These traits enable `kinetic-core` to be network-agnostic. The concrete implementations
//! live in `kinetic-vdf`, `kinetic-storage`, and `kinetic-core/src/governance/engine/`
//! respectively. The active `GovernanceEngine` is selected at compile time from `network.json`
//! via the `GOVERNANCE_MODEL` constant.

use crate::error::{StorageError, VdfError};
use crate::types::{Commitment, VdfProof};

/// Abstract interface for Verifiable Delay Function (VDF) computation engines.
///
/// The canonical implementation wraps a Wesolowski
/// VDF library. The challenge is always a 32-byte SHA-256 hash derived from
/// `NETWORK_SALT || name || salt || drand_signature_hex`.
pub trait VdfEngine: Send + Sync {
    /// Evaluates the VDF sequentially for the given number of iterations.
    ///
    /// This is a **CPU-intensive, sequential operation** that blocks the calling
    /// thread for the full duration (seconds to minutes depending on hardware
    /// and iteration count). It must not be called on an async executor thread.
    ///
    /// # Errors
    ///
    /// - Returns [`VdfError::LockFileError`] (`KIN-VDF-001`) if the serialization lock file cannot be created.
    /// - Returns [`VdfError::LockAcquireError`] (`KIN-VDF-002`) if the lock cannot be acquired (retryable).
    /// - Returns [`VdfError::DiscriminantError`] (`KIN-VDF-003`) if discriminant generation fails.
    /// - Returns [`VdfError::ProofGenerationError`] (`KIN-VDF-004`) if the underlying prover panics or fails.
    /// - Returns [`VdfError::UnsupportedPlatform`] (`KIN-VDF-005`) if the platform is not supported.
    fn evaluate(&self, challenge: &Commitment, iterations: u64) -> Result<VdfProof, VdfError>;

    /// Instantly verifies a provided VDF proof against a challenge and target iteration count.
    ///
    /// Unlike [`evaluate`](Self::evaluate), verification is O(log n) and non-blocking.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the proof is valid for the given challenge and iteration count.
    /// `Ok(false)` if the proof is structurally valid but does not verify.
    ///
    /// # Errors
    ///
    /// - Returns [`VdfError::DiscriminantError`] (`KIN-VDF-003`) if discriminant creation from the challenge fails.
    /// - Returns [`VdfError::InvalidProof`] (`KIN-VDF-006`) if the proof bytes are malformed or too large.
    fn verify(
        &self,
        challenge: &Commitment,
        proof: &VdfProof,
        iterations: u64,
    ) -> Result<bool, VdfError>;
}

/// Abstract interface for local embedded database storage engines.
///
/// The canonical implementation in `kinetic-storage` wraps a B-tree storage engine database.
/// All keys in Kinetic are namespaced with a `{NETWORK_ID}_` prefix so that multiple
/// NSP networks can share a physical database file without key collisions.
pub trait StorageEngine: Send + Sync {
    /// Stores a key-value byte pair, overwriting any existing entry.
    ///
    /// # Errors
    ///
    /// - Returns [`StorageError::WriteFailed`] (`KIN-DBE-004`) if the write fails.
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Retrieves the stored value for a given key.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(bytes))` if the key exists.
    /// - `Ok(None)` if the key has never been written.
    ///
    /// # Errors
    ///
    /// - Returns [`StorageError::ReadFailed`] (`KIN-DBE-003`) if the read fails.
    fn get(&self, key: &[u8]) -> Result<Option<bytes::Bytes>, StorageError>;

    /// Removes an entry by key.
    ///
    /// This is a no-op if the key does not exist — no error is returned for
    /// missing keys.
    ///
    /// # Errors
    ///
    /// - Returns [`StorageError::DeleteFailed`] (`KIN-DBE-005`) if the deletion fails.
    fn delete(&self, key: &[u8]) -> Result<(), StorageError>;

    /// Iterates over all key-value pairs whose keys begin with `prefix`, up to an optional `limit`.
    ///
    /// # Returns
    ///
    /// A `Vec` of `(key_bytes, value_bytes)` pairs. Returns an empty Vec if no
    /// keys match the prefix.
    ///
    /// # Errors
    ///
    /// - Returns [`StorageError::ScanFailed`] (`KIN-DBE-006`) if prefix iteration fails.
    #[allow(clippy::type_complexity)]
    fn scan_prefix(
        &self,
        prefix: &[u8],
        limit: Option<usize>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError>;
}

use crate::drand::RawKyn;
use crate::error::kyn_provider::KynProviderError;
use async_trait::async_trait;

/// Abstract interface for fetching and validating the network's consensus clock (Kyn).
///
/// The canonical implementation is `kinetic_network::client::drand::DrandProvider` which fetches cryptographic
/// randomness beacons from the League of Entropy's Quicknet.
#[async_trait]
pub trait KynProvider: Send + Sync {
    /// Fetches the latest cryptographically verifiable kyn from the network.
    async fn fetch_latest(&self) -> Result<RawKyn, KynProviderError>;

    /// Loads the most recently cached kyn from local memory or disk.
    fn load_cached_kyn(&self) -> Result<RawKyn, KynProviderError>;

    /// Caches a newly verified kyn to memory and disk.
    fn cache_kyn(&self, kyn: &RawKyn) -> Result<(), KynProviderError>;
}
