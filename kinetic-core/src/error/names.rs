use thiserror::Error;

/// Errors related to domain name validation.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum NamesError {
    /// The name exceeds the 253 character limit or is completely empty.
    #[error("Name is empty or exceeds the 253 character limit")]
    NameTooLong,

    /// A single label (word between dots) exceeds 63 characters or is empty.
    #[error("Label is empty or exceeds the 63 character limit")]
    LabelTooLong,

    /// The name contains invalid characters not permitted by the LDH rule.
    #[error("Name contains invalid characters (only lowercase letters, digits, and internal hyphens allowed)")]
    InvalidCharacter,

    /// The name is a permanently reserved public utility name (e.g., localhost).
    #[error("Name is a protected public utility name (e.g., localhost, test)")]
    ReservedName,

    /// The name is reserved for critical network infrastructure.
    #[error("Name is a protected infrastructure name (e.g., seed, explorer)")]
    InfrastructureName,

    /// The name has an invalid TLD.
    #[error("Name has an invalid Top-Level Domain")]
    InvalidTLD,

    /// The name is a subdomain, but the operation requires an apex domain.
    #[error("Only apex domains are allowed (subdomains must be managed by the apex owner)")]
    NotAnApexDomain,
}
