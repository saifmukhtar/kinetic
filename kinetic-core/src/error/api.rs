use thiserror::Error;

/// REST API errors (KIN-API-NNN)
#[derive(Debug, Error)]
pub enum RestApiError {
    /// The client failed to provide a valid Bearer token in the Authorization header.
    /// The daemon requires authentication for this endpoint, but the request was missing a token or provided an incorrect one.
    /// Ensure you pass the `Authorization: Bearer <token>` header, matching the token defined in your `kinetic.toml` config file.
    #[error("Missing or invalid authorization token")]
    InvalidToken,

    /// A Server-Sent Events (SSE) subscriber lagged behind and skipped messages.
    /// The client consuming the SSE event stream is processing events slower than the daemon is emitting them, overflowing the internal channel buffer.
    /// Ensure your client loop does not block when processing events, or increase the channel buffer size if burst traffic is expected.
    #[error("SSE subscriber lagged behind")]
    SseStreamLagged,

    /// An internal client received an API response that exceeded the maximum safety limit.
    /// To prevent memory exhaustion attacks, the daemon strictly limits the maximum size of incoming payload responses.
    /// This usually indicates an upstream anomaly. No direct action is required unless the daemon is failing to resolve legitimate records.
    #[error("API response exceeded size limits")]
    ResponseTooLarge,

    /// The client provided a valid token but lacks the correct Role to perform this action.
    /// The endpoint requires an elevated permission tier (e.g., attempting a write operation with a read-only token).
    /// Update the daemon's API token configuration in `kinetic.toml` to grant `Write` or `Admin` privileges to this token.
    #[error("Insufficient privileges to perform this action")]
    InsufficientPrivileges,

    /// The requested API resource does not exist.
    /// The client attempted to read, update, or delete a resource (like a local zone file) that hasn't been created yet.
    /// Verify the resource ID in the URL path. If managing zones, ensure a `POST` request was successfully made to create the zone first.
    #[error("The requested resource was not found")]
    NotFound,

    /// The REST API rejected the request payload or URL parameters.
    /// The client provided malformed JSON, missing required fields, or used the endpoint incorrectly.
    /// Review the accompanying error string and the API documentation to ensure your request matches the expected schema.
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
