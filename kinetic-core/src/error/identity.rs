//! Node identity key errors (`KIN-IDN-NNN`).
//!
//! [`IdentityError`] is returned by [`load_keypair`](crate::types::load_keypair) and
//! `save_keypair` when the ML-DSA-65 identity file is
//! missing, truncated, or the BIP-39 seed phrase is malformed.
//!
//! The identity file at `{base_dir}/identity.key` stores the raw ML-DSA-65 signing
//! key bytes and is required for daemon startup. If it is absent, a new key is generated.
use super::Severity;
use thiserror::Error;

/// Error type for node identity keys and mnemonic parsing.
#[derive(Error, Debug)]
pub enum IdentityError {
    /// The node encountered an operating system I/O error when trying to read or write an identity file.
    /// Check disk space and filesystem permissions for the target directory.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The node identity file exists but is structurally corrupted (e.g., incorrect byte length).
    /// The node may need to be re-provisioned or the file restored from a secure backup.
    #[error("Identity file is corrupted: {0}")]
    CorruptedIdentityFile(String),

    /// The required node identity file could not be found on disk.
    /// Ensure the daemon was initialized properly and the file path is correct.
    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    /// The provided mnemonic seed phrase failed BIP-39 validation.
    /// Verify that the phrase contains 12 or 24 valid BIP-39 English words.
    #[error("Invalid seed phrase: {0}")]
    InvalidSeedPhrase(String),

    /// The node could not decrypt the identity file.
    /// This usually means the provided encryption password is incorrect, or the encrypted payload is corrupted.
    #[error("Failed to decrypt identity file: {0}")]
    DecryptionFailed(String),

    /// An attempt was made to register a KID (Kinetic ID) that already exists on the network.
    /// To update an existing KID, use the cryptographic key rotation endpoint instead.
    #[error("KID already exists for name: {0}")]
    KidAlreadyExists(String),

    /// The requested KID document could not be found on the network.
    /// Ensure the identity name is spelled correctly and has been officially registered.
    #[error("KID not found for name: {0}")]
    KidNotFound(String),

    /// An attempt to rotate the keys of a KID document failed validation.
    /// Ensure the rotation payload is signed by the currently active private key and the sequence number is strictly increasing.
    #[error("Invalid KID rotation: {0}")]
    InvalidRotation(String),

    /// The daemon failed to cryptographically sign the KID document.
    /// This indicates an internal cryptographic failure or an invalid private key state.
    #[error("Failed to sign KID document: {0}")]
    KidSigningFailed(String),

    /// The provided Decentralized Identifier (DID) string was malformed.
    /// Kinetic DIDs must strictly follow the `did:kin:<network>:<name>` format.
    #[error("Invalid DID: {0}")]
    InvalidDid(String),

    /// An operation was attempted on a KID that has been permanently deactivated by its owner.
    /// Deactivated KIDs cannot be updated, rotated, or used for signing.
    #[error("KID is deactivated: {0}")]
    KidDeactivated(String),

    /// The provided KID document was rejected because it is missing required fields or contains malformed data.
    /// Ensure fields like the creation timestamp are strictly formatted and not in the future.
    #[error("Malformed KID document: {0}")]
    MalformedDocument(String),

    /// The provided apex KID document failed validation.
    /// Apex documents have stricter formatting rules than standard KIDs and must be precisely structured.
    #[error("Malformed apex KID document: {0}")]
    MalformedApexDocument(String),

    /// The provided capability manifest was missing required fields or contained invalid endpoint formats.
    #[error("Malformed capability manifest: {0}")]
    MalformedManifest(String),

    /// The daemon could not serialize the identity document into valid JSON.
    /// This indicates a structural failure in the document fields.
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    /// The daemon failed to cryptographically sign the capability manifest.
    /// Verify the node has access to the correct private signing key for this identity.
    #[error("Failed to sign manifest: {0}")]
    ManifestSigningFailed(String),

    /// The local daemon was asked to sign a payload for a specific KID, but the corresponding private key file could not be found.
    /// Ensure the key file exists locally in the configured secrets directory.
    #[error("KID private key not found: {0}")]
    KidPrivateKeyNotFound(String),

    /// The public key used to sign the transaction does not match the registered owner of the name.
    /// You cannot modify or rotate an identity document that you do not cryptographically own.
    #[error("Public key mismatch: {0}")]
    PubkeyMismatch(String),
}

impl PartialEq for IdentityError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(a), Self::Io(b)) => a.kind() == b.kind(),
            (Self::CorruptedIdentityFile(a), Self::CorruptedIdentityFile(b)) => a == b,
            (Self::IdentityNotFound(a), Self::IdentityNotFound(b)) => a == b,
            (Self::InvalidSeedPhrase(a), Self::InvalidSeedPhrase(b)) => a == b,
            (Self::DecryptionFailed(a), Self::DecryptionFailed(b)) => a == b,
            (Self::KidAlreadyExists(a), Self::KidAlreadyExists(b)) => a == b,
            (Self::KidNotFound(a), Self::KidNotFound(b)) => a == b,
            (Self::InvalidRotation(a), Self::InvalidRotation(b)) => a == b,
            (Self::KidSigningFailed(a), Self::KidSigningFailed(b)) => a == b,
            (Self::InvalidDid(a), Self::InvalidDid(b)) => a == b,
            (Self::KidDeactivated(a), Self::KidDeactivated(b)) => a == b,
            (Self::MalformedDocument(a), Self::MalformedDocument(b)) => a == b,
            (Self::MalformedApexDocument(a), Self::MalformedApexDocument(b)) => a == b,
            (Self::MalformedManifest(a), Self::MalformedManifest(b)) => a == b,
            (Self::SerializationFailed(a), Self::SerializationFailed(b)) => a == b,
            (Self::ManifestSigningFailed(a), Self::ManifestSigningFailed(b)) => a == b,
            (Self::KidPrivateKeyNotFound(a), Self::KidPrivateKeyNotFound(b)) => a == b,
            (Self::PubkeyMismatch(a), Self::PubkeyMismatch(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for IdentityError {}

impl IdentityError {
    /// Stable protocol error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io(_) => "KIN-IDN-001",
            Self::CorruptedIdentityFile(_) => "KIN-IDN-002",
            Self::IdentityNotFound(_) => "KIN-IDN-003",
            Self::InvalidSeedPhrase(_) => "KIN-IDN-004",
            Self::DecryptionFailed(_) => "KIN-IDN-005",
            Self::KidAlreadyExists(_) => "KIN-IDN-006",
            Self::KidNotFound(_) => "KIN-IDN-007",
            Self::InvalidRotation(_) => "KIN-IDN-008",
            Self::KidSigningFailed(_) => "KIN-IDN-009",
            Self::InvalidDid(_) => "KIN-IDN-010",
            Self::KidDeactivated(_) => "KIN-IDN-011",
            Self::MalformedDocument(_) => "KIN-IDN-012",
            Self::MalformedApexDocument(_) => "KIN-IDN-013",
            Self::MalformedManifest(_) => "KIN-IDN-014",
            Self::SerializationFailed(_) => "KIN-IDN-015",
            Self::ManifestSigningFailed(_) => "KIN-IDN-016",
            Self::KidPrivateKeyNotFound(_) => "KIN-IDN-017",
            Self::PubkeyMismatch(_) => "KIN-IDN-018",
        }
    }

    /// RFC 7807 type URI for this error.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }

    /// Severity level for logging and monitoring.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Io(_)
            | Self::CorruptedIdentityFile(_)
            | Self::IdentityNotFound(_)
            | Self::DecryptionFailed(_)
            | Self::InvalidRotation(_)
            | Self::KidSigningFailed(_)
            | Self::InvalidDid(_)
            | Self::MalformedDocument(_)
            | Self::MalformedApexDocument(_)
            | Self::MalformedManifest(_)
            | Self::SerializationFailed(_)
            | Self::ManifestSigningFailed(_) => Severity::Error,
            Self::InvalidSeedPhrase(_)
            | Self::KidAlreadyExists(_)
            | Self::KidNotFound(_)
            | Self::KidDeactivated(_)
            | Self::KidPrivateKeyNotFound(_)
            | Self::PubkeyMismatch(_) => Severity::Warning,
        }
    }

    /// Whether the client should offer a retry action.
    pub fn is_retryable(&self) -> bool {
        false
    }

    /// Returns the user-facing message.
    pub fn user_message(&self) -> String {
        match self {
            Self::Io(_) => {
                "An I/O error occurred while reading or writing the identity file.".to_string()
            }
            Self::CorruptedIdentityFile(_) => {
                "The identity file is corrupted and cannot be used.".to_string()
            }
            Self::IdentityNotFound(_) => "The identity file could not be found.".to_string(),
            Self::InvalidSeedPhrase(_) => "The provided seed phrase is invalid.".to_string(),
            Self::DecryptionFailed(_) => {
                "Failed to decrypt the identity file. Incorrect password or corrupted payload."
                    .to_string()
            }
            Self::KidAlreadyExists(name) => {
                format!("A KID document already exists for {name}. Use rotation to update keys.")
            }
            Self::KidNotFound(name) => {
                format!("No KID document found for {name}.")
            }
            Self::InvalidRotation(msg) => {
                format!("KID key rotation failed: {msg}")
            }
            Self::KidSigningFailed(msg) => {
                format!("Failed to sign KID document: {msg}")
            }
            Self::InvalidDid(msg) => {
                format!("Invalid DID format: {msg}")
            }
            Self::KidDeactivated(name) => {
                format!("The KID document for {name} has been permanently deactivated.")
            }
            Self::MalformedDocument(msg) => {
                format!("The KID document is malformed: {msg}")
            }
            Self::MalformedApexDocument(msg) => {
                format!("The apex KID document is malformed: {msg}")
            }
            Self::MalformedManifest(msg) => {
                format!("The capability manifest is malformed: {msg}")
            }
            Self::SerializationFailed(msg) => {
                format!("Failed to serialize the document: {msg}")
            }
            Self::ManifestSigningFailed(msg) => {
                format!("Failed to cryptographically sign the manifest: {msg}")
            }
            Self::KidPrivateKeyNotFound(name) => {
                format!("The private key file for {name} could not be found.")
            }
            Self::PubkeyMismatch(name) => {
                format!("The presented public key does not match the registered owner key for '{name}'. You cannot update a name you do not own.")
            }
        }
    }
}
