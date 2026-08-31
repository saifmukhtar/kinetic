use thiserror::Error;

/// REST API errors (KIN-API-NNN)
#[derive(Debug, Error)]
pub enum RestApiError {
    /// The client failed to provide a valid Bearer token in the Authorization header.
    /// This happens when making REST calls without the token provided in the daemon config file.
    #[error("Missing or invalid authorization token")]
    InvalidToken,

    /// A Server-Sent Events (SSE) subscriber lagged behind and skipped messages.
    /// This is typically a terminal warning indicating the client cannot process events fast enough.
    #[error("SSE subscriber lagged behind")]
    SseStreamLagged,

    /// An internal client (like the NRS resolver) received an API response that exceeded the 100KB safety limit.
    /// This prevents memory exhaustion from malicious or oversized daemon responses.
    #[error("API response exceeded size limits")]
    ResponseTooLarge,

    /// The client has a valid token but lacks the correct Role (e.g., trying to publish with a Read-Only role).
    /// To fix this, update the daemon's API token configuration to grant `Publish` or `Admin` privileges.
    #[error("Insufficient privileges to perform this action")]
    InsufficientPrivileges,

    /// The specific resource (like a local zone file) does not exist on disk.
    /// This happens if you try to query or edit a zone before calling POST to create it.
    #[error("The requested resource was not found")]
    NotFound,

    /// The request payload was invalid or the endpoint was used incorrectly.
    /// For example, trying to register a TLD when the endpoint is strictly for subdomains.
    #[error("Bad request or invalid endpoint usage")]
    BadRequest(String),
}

impl RestApiError {
    /// Returns the stable `KIN-API-XXX` string code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidToken => "KIN-API-001",
            Self::SseStreamLagged => "KIN-API-002",
            Self::ResponseTooLarge => "KIN-API-003",
            Self::InsufficientPrivileges => "KIN-API-004",
            Self::NotFound => "KIN-API-005",
            Self::BadRequest(_) => "KIN-API-006",
        }
    }

    /// Returns the HTTP status code for this error.
    pub fn status(&self) -> u16 {
        match self {
            Self::InvalidToken => 401,
            Self::InsufficientPrivileges => 403,
            Self::NotFound => 404,
            Self::BadRequest(_) => 400,
            Self::SseStreamLagged | Self::ResponseTooLarge => 500,
        }
    }
    
    /// Returns the RFC 7807 type URI pointing to documentation.
    pub fn error_type_uri(&self) -> String {
        format!("{}/errors/{}", crate::constants::DOCS_URL, self.code())
    }
}

impl From<RestApiError> for crate::ApiError {
    fn from(e: RestApiError) -> Self {
        crate::ApiError {
            error_type: e.error_type_uri(),
            title: match e {
                RestApiError::InvalidToken => "Unauthorized".to_string(),
                RestApiError::InsufficientPrivileges => "Forbidden".to_string(),
                RestApiError::NotFound => "Not Found".to_string(),
                RestApiError::BadRequest(_) => "Bad Request".to_string(),
                RestApiError::SseStreamLagged => "SSE Lagged".to_string(),
                RestApiError::ResponseTooLarge => "Payload Too Large".to_string(),
            },
            status: e.status(),
            detail: e.to_string(),
            instance: None,
            code: e.code().to_string(),
            retryable: false,
            details: serde_json::Value::Null,
            request_id: crate::api_error::current_request_id(),
        }
    }
}
