//! RFC 7807-compatible API error type.
//! This is the ONLY error type that crosses HTTP boundaries.
//! Internal Rust errors are converted to ApiError at the API layer.

use crate::error::{
    GovernanceError, NetworkClientError, PublishError, RegistrationError, ResolutionError,
    StorageError, UpdaterError, VdfError,
};
use serde::{Deserialize, Serialize};

/// RFC 7807 Problem Details for HTTP APIs, with Kinetic extensions.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiError {
    /// RFC 7807: URI identifying the error type
    #[serde(rename = "type")]
    pub error_type: String,
    /// RFC 7807: Short stable human-readable summary
    pub title: String,
    /// RFC 7807: HTTP status code
    pub status: u16,
    /// RFC 7807: Human-facing explanation
    pub detail: String,
    /// RFC 7807: URI of the specific request instance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Kinetic: stable protocol error code (e.g. "KIN-RES-002")
    pub code: String,
    /// Kinetic: whether the client should retry
    pub retryable: bool,
    /// Kinetic: developer-facing structured diagnostics
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub details: serde_json::Value,
    /// Kinetic: correlation ID for log tracing
    pub request_id: String,
}

impl ApiError {
    /// Returns the HTTP status code associated with this error.
    pub fn http_status(&self) -> u16 {
        self.status
    }
}

fn current_request_id() -> String {
    crate::request_id::current()
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
            GovernanceError::MissingRootKey | GovernanceError::MissingGuardKey => {
                (500, "Configuration Error")
            }
            GovernanceError::KeyLengthMismatch | GovernanceError::CouncilSizeMismatch => {
                (400, "Bad Request")
            }
            GovernanceError::StaleProposal
            | GovernanceError::TimelockNotExpired
            | GovernanceError::OtaTimelockNotExpired
            | GovernanceError::NotPendingOrVetoed => (409, "Conflict"),
            GovernanceError::InvalidGuardSignature | GovernanceError::InsufficientSignatures => {
                (401, "Unauthorized")
            }
            GovernanceError::EmergencyResetVetoed
            | GovernanceError::EmergencyResetRequiresRoot
            | GovernanceError::EmergencyResetRequiresGuard
            | GovernanceError::RotateRequiresGuard
            | GovernanceError::EmptyCouncil => (403, "Forbidden"),
            GovernanceError::UnhandledThresholdMath => (501, "Not Implemented"),
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

impl From<UpdaterError> for ApiError {
    fn from(e: UpdaterError) -> Self {
        let (status, title): (u16, &'static str) = match &e {
            UpdaterError::NoMirrorsProvided | UpdaterError::HashMismatch(..) => {
                (400, "Bad Request")
            }
            UpdaterError::HttpError(_)
            | UpdaterError::NetworkError(_)
            | UpdaterError::ReqwestError(_) => (502, "Bad Gateway"),
            UpdaterError::IoError(_)
            | UpdaterError::SpawnFailed(_)
            | UpdaterError::SelfReplaceError(_) => (500, "Internal Server Error"),
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
