//! RFC 7807 Problem Details HTTP API error serialization boundary.
//!
//! `ApiError` is the single unified error payload that crosses HTTP network boundaries.
//! All domain-specific error enums in [`crate::error`] implement `From<T> for ApiError`,
//! mapping internal failures to RFC 7807 Problem Details JSON format with Kinetic extensions.

use crate::error::{
    DnsError, DrandError, GovernanceError, IdentityError, NamesError, NetworkClientError,
    PublishError, RegistrationError, ResolutionError, StorageError, VdfError,
};
use serde::{Deserialize, Serialize};

/// RFC 7807 Problem Details representation for HTTP API responses, augmented with Kinetic extensions.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiError {
    /// RFC 7807: URI identifying the specific error category (e.g. `"https://kinetic.network/errors/KIN-RES-002"`).
    #[serde(rename = "type")]
    pub error_type: String,
    /// RFC 7807: Short human-readable title summarizing the error category.
    pub title: String,
    /// RFC 7807: Associated HTTP response status code (e.g. `404`, `503`).
    pub status: u16,
    /// RFC 7807: Human-facing explanation of the specific error occurrence.
    pub detail: String,
    /// RFC 7807: Optional URI identifying the specific request instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Kinetic Extension: Stable protocol error code (e.g. `"KIN-RES-002"`).
    pub code: String,
    /// Kinetic Extension: Indicates whether client applications should retry the request.
    pub retryable: bool,
    /// Kinetic Extension: Developer-facing structured JSON diagnostic details.
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub details: serde_json::Value,
    /// Kinetic Extension: Task-local correlation ID for server log tracing.
    pub request_id: String,
}

impl ApiError {
    /// Returns the HTTP status code associated with this error.
    pub fn http_status(&self) -> u16 {
        self.status
    }
}

fn current_request_id() -> String {
    crate::request_id::current().to_string()
}

impl From<ResolutionError> for ApiError {
    fn from(e: ResolutionError) -> Self {
        let (status, title): (u16, &'static str) = match &e {
            ResolutionError::Offline => (503, "Node Offline"),
            ResolutionError::NotFound { .. } => (404, "Name Not Found"),
            ResolutionError::VdfVerificationFailed { .. } => {
                (422, "Cryptographic Verification Failed")
            }
            ResolutionError::Expired { .. } => (410, "Registration Expired"),
            ResolutionError::Timeout { .. } => (504, "Resolution Timeout"),
            ResolutionError::Internal { .. } => (500, "Internal Resolution Error"),
        };
        ApiError {
            error_type: e.error_type_uri(),
            title: title.to_string(),
            status,
            detail: e.user_message(),
            instance: None,
            code: e.code().to_string(),
            retryable: e.is_retryable(),
            details: e.details(),
            request_id: current_request_id(),
        }
    }
}

impl From<PublishError> for ApiError {
    fn from(e: PublishError) -> Self {
        let (status, title): (u16, &'static str) = match &e {
            PublishError::Offline => (503, "Node Offline"),
            PublishError::InvalidProof(_) => (400, "Invalid VDF Proof"),
            PublishError::AlreadyOwned { .. } => (409, "Name Already Owned"),
            PublishError::AllFailed { .. } => (503, "Publish Failed"),
            PublishError::Rejected(_) => (422, "Publish Rejected"),
            PublishError::Internal { .. } => (500, "Internal Publish Error"),
        };
        ApiError {
            error_type: e.error_type_uri(),
            title: title.to_string(),
            status,
            detail: e.user_message(),
            instance: None,
            code: e.code().to_string(),
            retryable: e.is_retryable(),
            details: e.details(),
            request_id: current_request_id(),
        }
    }
}

impl From<RegistrationError> for ApiError {
    fn from(e: RegistrationError) -> Self {
        let (status, title): (u16, &'static str) = match &e {
            RegistrationError::InvalidName { .. } => (400, "Invalid Name"),
            RegistrationError::VdfFailed(_) => (500, "VDF Computation Failed"),
            RegistrationError::CommitmentMismatch => (422, "Commitment Mismatch"),
            RegistrationError::AlreadyOwned { .. } => (409, "Name Already Owned"),
            RegistrationError::AlreadyInProgress { .. } => (409, "Registration In Progress"),
            RegistrationError::NetworkRejected { .. } => (422, "Registration Rejected"),
            RegistrationError::Internal { .. } => (500, "Internal Registration Error"),
        };
        ApiError {
            error_type: e.error_type_uri(),
            title: title.to_string(),
            status,
            detail: e.user_message(),
            instance: None,
            code: e.code().to_string(),
            retryable: e.is_retryable(),
            details: e.details(),
            request_id: current_request_id(),
        }
    }
}

impl From<GovernanceError> for ApiError {
    fn from(e: GovernanceError) -> Self {
        let (status, title): (u16, &'static str) = match &e {
            GovernanceError::MissingRootKey => (500, "Configuration Error"),
            GovernanceError::StaleProposal
            | GovernanceError::TimelockNotExpired
            | GovernanceError::NotPendingOrVetoed => (409, "Conflict"),
            GovernanceError::InsufficientSignatures => (401, "Unauthorized"),
            GovernanceError::GovernanceDisabled => (403, "Forbidden"),
            GovernanceError::KeyLengthMismatch | GovernanceError::InvalidPremiumNameLength | GovernanceError::InvalidInfrastructureName => {
                (400, "Bad Request")
            }
        };
        ApiError {
            error_type: e.error_type_uri(),
            title: title.to_string(),
            status,
            detail: e.user_message(),
            instance: None,
            code: e.code().to_string(),
            retryable: e.is_retryable(),
            details: serde_json::Value::Null,
            request_id: current_request_id(),
        }
    }
}

impl From<NetworkClientError> for ApiError {
    fn from(e: NetworkClientError) -> Self {
        let (status, title): (u16, &'static str) = match &e {
            NetworkClientError::Timeout | NetworkClientError::StreamDropped => {
                (504, "Gateway Timeout")
            }
            NetworkClientError::Offline | NetworkClientError::RoutingTableEmpty => {
                (503, "Service Unavailable")
            }
            NetworkClientError::ChannelClosed
            | NetworkClientError::StoreError(_)
            | NetworkClientError::Other(_) => (500, "Internal Server Error"),
            NetworkClientError::UnsupportedProtocol => (501, "Not Implemented"),
            NetworkClientError::GossipSubError(_) => (502, "Bad Gateway"),
        };
        ApiError {
            error_type: e.error_type_uri(),
            title: title.to_string(),
            status,
            detail: e.user_message(),
            instance: None,
            code: e.code().to_string(),
            retryable: e.is_retryable(),
            details: serde_json::Value::Null,
            request_id: current_request_id(),
        }
    }
}

impl From<StorageError> for ApiError {
    fn from(e: StorageError) -> Self {
        let (status, title): (u16, &'static str) = match &e {
            StorageError::DatabaseLocked => (423, "Locked"),
            StorageError::Corruption(_) => (500, "Storage Corruption"),
            StorageError::OperationFailed(_) => (500, "Storage Operation Failed"),
        };
        ApiError {
            error_type: e.error_type_uri(),
            title: title.to_string(),
            status,
            detail: e.user_message(),
            instance: None,
            code: e.code().to_string(),
            retryable: e.is_retryable(),
            details: serde_json::Value::Null,
            request_id: current_request_id(),
        }
    }
}

impl From<VdfError> for ApiError {
    fn from(e: VdfError) -> Self {
        let (status, title): (u16, &'static str) = match &e {
            VdfError::LockFileError(_) | VdfError::LockAcquireError(_) => {
                (503, "Service Unavailable")
            }
            VdfError::DiscriminantError | VdfError::ProofGenerationError => {
                (500, "VDF Computation Error")
            }
            VdfError::UnsupportedPlatform => (501, "Not Implemented"),
            VdfError::InvalidProof => (400, "Bad Request"),
        };
        ApiError {
            error_type: e.error_type_uri(),
            title: title.to_string(),
            status,
            detail: e.user_message(),
            instance: None,
            code: e.code().to_string(),
            retryable: e.is_retryable(),
            details: serde_json::Value::Null,
            request_id: current_request_id(),
        }
    }
}

impl From<DrandError> for ApiError {
    fn from(e: DrandError) -> Self {
        let (status, title): (u16, &'static str) = match &e {
            DrandError::AllEndpointsFailed | DrandError::Network(_) | DrandError::Reqwest(_) => {
                (502, "Bad Gateway")
            }
            DrandError::HttpError(s) => (*s, "Upstream Error"),
            DrandError::NoCachedPulse => (404, "Not Found"),
            DrandError::Serde(_) | DrandError::Storage(_) => (500, "Internal Server Error"),
            DrandError::InvalidSignature => (422, "Cryptographic Verification Failed"),
            DrandError::StalePulse { .. } => (400, "Stale Drand Pulse"),
        };
        ApiError {
            error_type: e.error_type_uri(),
            title: title.to_string(),
            status,
            detail: e.user_message(),
            instance: None,
            code: e.code().to_string(),
            retryable: e.is_retryable(),
            details: serde_json::Value::Null,
            request_id: current_request_id(),
        }
    }
}

impl From<DnsError> for ApiError {
    fn from(e: DnsError) -> Self {
        let (status, title): (u16, &'static str) = match &e {
            DnsError::NestedTooDeeply
            | DnsError::ParseError(_)
            | DnsError::TooManyRecords
            | DnsError::InvalidLabelLength(_)
            | DnsError::InvalidLabelCharacters(_)
            | DnsError::InvalidCnameConfiguration(_)
            | DnsError::TxtRecordTooLong(_)
            | DnsError::InvalidCnameTarget(_)
            | DnsError::InvalidPeerId(_)
            | DnsError::InvalidKid(_)
            | DnsError::InvalidIpfsCid(_) => (400, "Bad Request"),
        };
        ApiError {
            error_type: e.error_type_uri(),
            title: title.to_string(),
            status,
            detail: e.user_message(),
            instance: None,
            code: e.code().to_string(),
            retryable: e.is_retryable(),
            details: serde_json::Value::Null,
            request_id: current_request_id(),
        }
    }
}

impl From<IdentityError> for ApiError {
    fn from(e: IdentityError) -> Self {
        let (status, title): (u16, &'static str) = match &e {
            IdentityError::Io(_) | IdentityError::CorruptedIdentityFile(_) => {
                (500, "Internal Server Error")
            }
            IdentityError::IdentityNotFound(_) => (404, "Not Found"),
            IdentityError::InvalidSeedPhrase(_) => (400, "Bad Request"),
            IdentityError::DecryptionFailed(_) => (401, "Unauthorized"),
        };
        ApiError {
            error_type: e.error_type_uri(),
            title: title.to_string(),
            status,
            detail: e.user_message(),
            instance: None,
            code: e.code().to_string(),
            retryable: e.is_retryable(),
            details: serde_json::Value::Null,
            request_id: current_request_id(),
        }
    }
}

impl From<NamesError> for ApiError {
    fn from(e: NamesError) -> Self {
        // All NamesError variants are deterministic input validation failures — 400 Bad Request.
        ApiError {
            error_type: e.error_type_uri(),
            title: "Invalid Domain Name".to_string(),
            status: 400,
            detail: e.user_message(),
            instance: None,
            code: e.code().to_string(),
            retryable: e.is_retryable(),
            details: serde_json::Value::Null,
            request_id: current_request_id(),
        }
    }
}
