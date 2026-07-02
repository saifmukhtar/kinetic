//! RFC 7807-compatible API error type.
//! This is the ONLY error type that crosses HTTP boundaries.
//! Internal Rust errors are converted to ApiError at the API layer.

use crate::error::{PublishError, RegistrationError, ResolutionError};
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
