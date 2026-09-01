use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use kinetic_core::ApiError;

/// A web-layer wrapper around the core `ApiError`.
/// This implements the "Newtype" pattern, allowing us to define how
/// standard Kinetic protocol errors are serialized into HTTP responses
/// without coupling the core engine to the Axum web framework.
#[derive(Debug, Clone)]
pub struct AppError(pub ApiError);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self.0)).into_response()
    }
}

// ─── Auto-Converters for Core Errors ──────────────────────────────────────────

impl From<kinetic_core::error::PublishError> for AppError {
    fn from(err: kinetic_core::error::PublishError) -> Self {
        AppError(ApiError::from(err))
    }
}

impl From<kinetic_core::error::ResolutionError> for AppError {
    fn from(err: kinetic_core::error::ResolutionError) -> Self {
        AppError(ApiError::from(err))
    }
}

impl From<kinetic_core::error::RegistrationError> for AppError {
    fn from(err: kinetic_core::error::RegistrationError) -> Self {
        AppError(ApiError::from(err))
    }
}

impl From<kinetic_core::error::VdfError> for AppError {
    fn from(err: kinetic_core::error::VdfError) -> Self {
        AppError(ApiError::from(err))
    }
}

impl From<kinetic_core::error::IdentityError> for AppError {
    fn from(err: kinetic_core::error::IdentityError) -> Self {
        AppError(ApiError::from(err))
    }
}

impl From<kinetic_core::error::StorageError> for AppError {
    fn from(err: kinetic_core::error::StorageError) -> Self {
        AppError(ApiError::from(err))
    }
}

impl From<kinetic_core::error::KynProviderError> for AppError {
    fn from(err: kinetic_core::error::KynProviderError) -> Self {
        AppError(ApiError::from(err))
    }
}

impl From<kinetic_core::error::NrsError> for AppError {
    fn from(err: kinetic_core::error::NrsError) -> Self {
        AppError(ApiError::from(err))
    }
}

impl From<kinetic_core::error::NamesError> for AppError {
    fn from(err: kinetic_core::error::NamesError) -> Self {
        AppError(ApiError::from(err))
    }
}

impl From<kinetic_core::error::network::NetworkClientError> for AppError {
    fn from(err: kinetic_core::error::network::NetworkClientError) -> Self {
        AppError(ApiError::from(err))
    }
}

impl From<kinetic_core::error::RestApiError> for AppError {
    fn from(err: kinetic_core::error::RestApiError) -> Self {
        AppError(ApiError::from(err))
    }
}

impl From<ApiError> for AppError {
    fn from(err: ApiError) -> Self {
        AppError(err)
    }
}
