//! RFC 7807 Problem Details HTTP API error serialization boundary.
//!
//! `ApiError` is the single unified error payload that crosses HTTP network boundaries.
//! All domain-specific error enums in [`crate::error`] implement `From<T> for ApiError`,
//! mapping internal failures to RFC 7807 Problem Details JSON format with Kinetic extensions.

use crate::error::{
    DrandError, GovernanceError, IdentityError, NamesError, NetworkClientError, NrsError, P2pError,
    PublishError, RegistrationError, ResolutionError, StorageError, VdfError,
};
use serde::{Deserialize, Serialize};

/// RFC 7807 Problem Details representation for HTTP API responses, augmented with Kinetic extensions.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiError {
    /// RFC 7807: URI identifying the specific error category (e.g. `"https://kinetic.network/errors/KIN-QRY-002"`).
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
    /// Kinetic Extension: Stable protocol error code (e.g. `"KIN-QRY-002"`).
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

pub(crate) fn current_request_id() -> String {
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
            PublishError::InvalidProof(_) => (422, "Invalid VDF Proof"),
            PublishError::AlreadyOwned { .. } => (409, "Name Already Owned"),
            PublishError::AllFailed { .. } => (503, "Publish Failed"),
            PublishError::Rejected(_) => (422, "Publish Rejected"),
            PublishError::Internal { .. } => (500, "Internal Publish Error"),
            PublishError::QuorumFailed(..) | PublishError::CommitmentQuorumFailed(..) => (503, "Quorum Failed"),
            PublishError::QuorumCheckError(..) | PublishError::CommitmentQuorumCheckError(..) => (503, "Quorum Check Failed"),
            PublishError::ZonePublishFailed(_) | PublishError::CommitmentPublishFailed(_) | PublishError::KidPublishFailed(_) | PublishError::ManifestPublishFailed(_) | PublishError::HostRoutingRecordPublishFailed(_) => (502, "DHT Publish Failed"),
            PublishError::MissingLocalRevealForKid(_) | PublishError::MissingLocalRevealForManifest(_) => (404, "Missing Local Reveal"),
            PublishError::ZoneSerializationFailed(_) => (500, "Serialization Failed"),
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
            GovernanceError::MissingRootKey | GovernanceError::MalformedRootKey | GovernanceError::StateCorrupted => {
                (500, "Internal Server Error")
            }
            GovernanceError::GovernanceDisabled => (403, "Forbidden"),
            GovernanceError::StaleProposal | GovernanceError::AlreadyExecuted => (409, "Conflict"),
            GovernanceError::KeyLengthMismatch
            | GovernanceError::InvalidSignature
            | GovernanceError::InvalidPrimeLength
            | GovernanceError::InvalidProtocolName
            | GovernanceError::AlreadyMapped
            | GovernanceError::NotMapped
            | GovernanceError::UnnormalizedName
            | GovernanceError::InvalidSeedState => (400, "Bad Request"),
            GovernanceError::StateSaveFailed | GovernanceError::StateReadFailed => (500, "Internal Server Error"),
            GovernanceError::P2pPublishFailed | GovernanceError::BootstrapFetchFailed => (502, "Bad Gateway"),
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
            NetworkClientError::Timeout => (504, "Gateway Timeout"),
            NetworkClientError::Offline | NetworkClientError::RoutingTableEmpty => {
                (503, "Service Unavailable")
            }
            NetworkClientError::ChannelClosed | NetworkClientError::Other(_) => {
                (500, "Internal Server Error")
            }
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
            StorageError::DeserializationFailed(_) => (500, "Storage Deserialization Failed"),
            StorageError::ReadFailed(_)
            | StorageError::WriteFailed(_)
            | StorageError::DeleteFailed(_)
            | StorageError::ScanFailed(_)
            | StorageError::OpenFailed(_) => (500, "Storage Operation Failed"),
            StorageError::InvalidRecordDiscarded | StorageError::OrphanedHeartbeatPurged => (500, "Storage Consistency Warning"),
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
            VdfError::InvalidChallenge => (400, "Bad Request"),
            VdfError::MaxIterationsExceeded => (400, "Bad Request"),
            VdfError::TooManyTasks => (429, "Too Many Requests"),
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
            DrandError::AllEndpointsFailed
            | DrandError::StreamReadFailed(_)
            | DrandError::ResponseTooLarge(_)
            | DrandError::Reqwest(_)
            | DrandError::HttpError(_) => (502, "Bad Gateway"),
            DrandError::NoCachedKyn => (404, "Not Found"),
            DrandError::Serde(_) | DrandError::Storage(_) => (500, "Internal Server Error"),
            DrandError::InvalidSignature => (422, "Cryptographic Verification Failed"),
            DrandError::StaleKyn { .. } => (400, "Stale Network Kyn"),
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

impl From<P2pError> for ApiError {
    fn from(e: P2pError) -> Self {
        ApiError {
            error_type: e.error_type_uri(),
            title: "Service Unavailable".to_string(),
            status: 503,
            detail: e.user_message(),
            instance: None,
            code: e.code().to_string(),
            retryable: e.is_retryable(),
            details: serde_json::Value::Null,
            request_id: current_request_id(),
        }
    }
}

impl From<NrsError> for ApiError {
    fn from(e: NrsError) -> Self {
        let (status, title): (u16, &'static str) = match &e {
            NrsError::TooManyRecords
            | NrsError::InvalidLabelLength(_)
            | NrsError::InvalidLabelCharacters(_)
            | NrsError::InvalidCnameConfiguration(_)
            | NrsError::TxtRecordTooLong(_)
            | NrsError::InvalidCnameTarget(_)
            | NrsError::InvalidPeerId(_)
            | NrsError::InvalidKid(_)
            | NrsError::InvalidIpfsCid(_)
            | NrsError::ParseError(_)
            | NrsError::MultipleCnames(_) => (400, "Bad Request"),
            NrsError::UpstreamResolveError(_)
            | NrsError::DnsRequestFailed(_)
            | NrsError::NrsServerExecutionError(_)
            | NrsError::SeedDomainResolutionFailed(_)
            | NrsError::DnsResolverInitFailed(_)
            | NrsError::DnsLookupFailed { .. }
            | NrsError::Web2BridgeResolveFailed { .. }
            | NrsError::Web2BridgeNoIpsFound(_) => (502, "Bad Gateway"),
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
            IdentityError::Io(_)
            | IdentityError::CorruptedIdentityFile(_)
            | IdentityError::KidSigningFailed(_) => (500, "Internal Server Error"),
            IdentityError::IdentityNotFound(_) | IdentityError::KidNotFound(_) => {
                (404, "Not Found")
            }
            IdentityError::InvalidSeedPhrase(_) | IdentityError::InvalidDid(_) => {
                (400, "Bad Request")
            }
            IdentityError::DecryptionFailed(_) => (401, "Unauthorized"),
            IdentityError::KidAlreadyExists(_) => (409, "Conflict"),
            IdentityError::PubkeyMismatch(_) => (409, "Conflict"),
            IdentityError::InvalidRotation(_) => (422, "Unprocessable Entity"),
            IdentityError::KidDeactivated(_) => (410, "Gone"),
            IdentityError::SerializationFailed(_) | IdentityError::ManifestSigningFailed(_) => {
                (500, "Internal Server Error")
            }
            IdentityError::MalformedDocument(_)
            | IdentityError::MalformedApexDocument(_)
            | IdentityError::MalformedManifest(_) => (422, "Unprocessable Entity"),
            IdentityError::KidPrivateKeyNotFound(_) => (404, "Not Found"),
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
            title: "Invalid Name".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{DrandError, IdentityError, PublishError, ResolutionError};

    #[test]
    fn test_status_code_mappings() {
        // Test 404 mapping
        let err = ResolutionError::NotFound {
            name: "test.kin".to_string(),
            peers_queried: 5,
        };
        assert_eq!(ApiError::from(err).status, 404);

        // Test proxy leak fix (Drand 404 shouldn't leak to client)
        let drand_err = DrandError::HttpError(404);
        assert_eq!(ApiError::from(drand_err).status, 502);

        // Test blame-shifting fix (Malformed docs shouldn't be 500)
        let id_err = IdentityError::MalformedManifest("bad".to_string());
        assert_eq!(ApiError::from(id_err).status, 422);

        // Test crypto consistency (Invalid Proof should be 422, not 400)
        let pub_err = PublishError::InvalidProof(crate::error::VdfRejectReason::MalformedProof);
        assert_eq!(ApiError::from(pub_err).status, 422);
    }
}
