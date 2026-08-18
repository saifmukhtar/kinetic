//! Domain name validation, normalization, and RFC reserved name checks.

/// Canonical Namespace (NSP) string for the Kinetic network.
pub const NSP: &str = "kin";

/// Normalizes a given name string.
///
/// Ensures a domain name is lowercase, trimmed, and ends with the
/// Kinetic NSP suffix ([`crate::constants::NSP_SUFFIX`]) if missing.
///
/// # Examples
///
/// ```
/// use kinetic_core::types::names::normalize_name;
///
/// assert_eq!(normalize_name("example.KIN"), "example.kin");
/// assert_eq!(normalize_name("example"), "example.kin");
/// ```
pub fn normalize_name(name: &str) -> String {
    let mut norm = name.to_lowercase();
    while norm.ends_with('.') {
        norm.pop();
    }
    if !norm.ends_with(crate::constants::NSP_SUFFIX) {
        norm.push_str(crate::constants::NSP_SUFFIX);
    }
    norm
}

/// Checks whether a given name is a Category 1 reserved public utility name.
///
/// Hardcoded reserved names (e.g. `localhost`, `test`, `example`) are permanently
/// locked and cannot be registered under any NSP instance.
pub fn is_reserved_name(name: &str) -> bool {
    let nsp = crate::constants::NSP_SUFFIX;
    let name_lower = name.to_lowercase();
    RESERVED_NAMES
        .iter()
        .any(|&r| format!("{}{}", r, nsp) == name_lower)
}

/// Category 1: Public Utility Names (Based on RFC 2606 & RFC 6761).
///
/// These names are permanently locked across the network to prevent collisions.
pub const RESERVED_NAMES: &[&str] = &[
    "test",
    "example",
    "invalid",
    "localhost",
    "local",
    "onion",
    "arpa",
    "null",
    "none",
    "zero",
    "corp",
    "lan",
    "internal",
    "home",
];

/// Validates whether a given name is a valid apex name that can be registered.
///
/// Enforces standard DNS LDH (Letters, Digits, Hyphen) rules, total/label length limits,
/// apex structure, and Category 1/2 reservation checks.
///
/// # Errors
///
/// - Returns [`crate::error::NamesError::NameTooLong`] if the total name length exceeds 253 characters.
/// - Returns [`crate::error::NamesError::LabelTooLong`] if any individual dot-separated label exceeds 63 characters.
/// - Returns [`crate::error::NamesError::InvalidCharacter`] if a label contains non-LDH characters or invalid hyphen/digit placements.
/// - Returns [`crate::error::NamesError::NotAnApexName`] if the input is a subdomain (e.g. `blog.example.kin`) instead of an apex name (`example.kin`).
/// - Returns [`crate::error::NamesError::ReservedName`] if the label matches a Category 1 public utility name.
/// - Returns [`crate::error::NamesError::ProtocolName`] if the label is a locked Category 2 network protocol name.
pub fn is_valid_apex_name(name: &str) -> Result<(), crate::error::NamesError> {
    let norm = normalize_name(name);

    if norm.len() > 253 {
        return Err(crate::error::NamesError::NameTooLong);
    }
    for part in norm.split('.') {
        if part.is_empty() {
            return Err(crate::error::NamesError::EmptyLabel);
        }
        if part.len() > 63 {
            return Err(crate::error::NamesError::LabelTooLong);
        }

        // DNS LDH Rule: Only lowercase letters, digits, and hyphens allowed.
        for c in part.chars() {
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
                return Err(crate::error::NamesError::InvalidCharacter);
            }
        }

        // Labels cannot start or end with a hyphen
        if part.starts_with('-') || part.ends_with('-') {
            return Err(crate::error::NamesError::InvalidHyphenPlacement);
        }
    }

    let apex = extract_apex_name(&norm);
    if norm != apex {
        return Err(crate::error::NamesError::NotAnApexName);
    }

    // Ensure the registered label is not a Category 1 reserved public utility name.
    if is_reserved_name(&norm) {
        return Err(crate::error::NamesError::ReservedName);
    }

    // Category 2: Protocol Names (Locked until Phase 2)
    if crate::types::protocol::is_protocol_name(&norm) {
        return Err(crate::error::NamesError::ProtocolName);
    }

    Ok(())
}

/// Extracts the apex name (e.g., `example.kin`) from a subdomain string (e.g., `blog.example.kin`).
pub fn extract_apex_name(name: &str) -> String {
    let norm = normalize_name(name);

    let parts: Vec<&str> = norm.split('.').collect();
    if parts.len() >= 2 {
        let last_two = &parts[parts.len() - 2..];
        format!("{}.{}", last_two[0], last_two[1])
    } else {
        norm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_name() {
        assert_eq!(
            normalize_name("SAIFMUKHTAR.KIN"),
            format!("{}{}", "saifmukhtar", crate::constants::NSP_SUFFIX)
        );
        assert_eq!(
            normalize_name("saifmukhtar..."),
            format!("{}{}", "saifmukhtar", crate::constants::NSP_SUFFIX)
        );
        assert_eq!(
            normalize_name("saifmukhtar"),
            format!("{}{}", "saifmukhtar", crate::constants::NSP_SUFFIX)
        );
        assert_eq!(
            normalize_name("blog.saifmukhtar.kin."),
            format!("{}{}", "blog.saifmukhtar", crate::constants::NSP_SUFFIX)
        );
    }

    #[test]
    fn test_is_valid_apex_name() {
        assert!(
            is_valid_apex_name(&format!(
                "{}{}",
                "saifmukhtar",
                crate::constants::NSP_SUFFIX
            ))
            .is_ok()
        );
        
        // Edge Case: Total name length exceeds 253 characters
        let long_name = "a".repeat(250) + crate::constants::NSP_SUFFIX;
        assert_eq!(
            is_valid_apex_name(&long_name),
            Err(crate::error::NamesError::NameTooLong)
        );

        // Edge Case: Label length exceeds 63 characters
        let long_label = "a".repeat(64) + crate::constants::NSP_SUFFIX;
        assert_eq!(
            is_valid_apex_name(&long_label),
            Err(crate::error::NamesError::LabelTooLong)
        );
        assert!(
            is_valid_apex_name(&format!(
                "{}{}",
                "saifmukhtar-123",
                crate::constants::NSP_SUFFIX
            ))
            .is_ok()
        );
        assert!(
            is_valid_apex_name(&format!("{}{}", "007", crate::constants::NSP_SUFFIX))
            .is_ok()
        );

        assert_eq!(
            is_valid_apex_name(&format!(
                "{}{}",
                "blog.saifmukhtar",
                crate::constants::NSP_SUFFIX
            )),
            Err(crate::error::NamesError::NotAnApexName)
        );
        // Edge Case: Empty label
        assert_eq!(
            is_valid_apex_name(&format!(
                "{}{}",
                "blog..saifmukhtar",
                crate::constants::NSP_SUFFIX
            )),
            Err(crate::error::NamesError::EmptyLabel)
        );

        assert_eq!(
            is_valid_apex_name(&format!(
                "{}{}",
                "saifmukhtar_123",
                crate::constants::NSP_SUFFIX
            )),
            Err(crate::error::NamesError::InvalidCharacter)
        );
        assert_eq!(
            is_valid_apex_name(&format!(
                "{}{}",
                "saifmukhtar!",
                crate::constants::NSP_SUFFIX
            )),
            Err(crate::error::NamesError::InvalidCharacter)
        );
        assert_eq!(
            is_valid_apex_name(&format!(
                "{}{}",
                "-saifmukhtar",
                crate::constants::NSP_SUFFIX
            )),
            Err(crate::error::NamesError::InvalidHyphenPlacement)
        );
        assert_eq!(
            is_valid_apex_name(&format!(
                "{}{}",
                "saifmukhtar-",
                crate::constants::NSP_SUFFIX
            )),
            Err(crate::error::NamesError::InvalidHyphenPlacement)
        );

        // Test RFC Category 1 Reserved Names
        assert_eq!(
            is_valid_apex_name(&format!("test{}", crate::constants::NSP_SUFFIX)),
            Err(crate::error::NamesError::ReservedName)
        );
        assert_eq!(
            is_valid_apex_name(&format!("localhost{}", crate::constants::NSP_SUFFIX)),
            Err(crate::error::NamesError::ReservedName)
        );
        assert_eq!(
            is_valid_apex_name(&format!("null{}", crate::constants::NSP_SUFFIX)),
            Err(crate::error::NamesError::ReservedName)
        );
    }

    #[test]
    fn test_extract_apex_name() {
        assert_eq!(
            extract_apex_name(&format!(
                "{}{}",
                "blog.saifmukhtar",
                crate::constants::NSP_SUFFIX
            )),
            format!("{}{}", "saifmukhtar", crate::constants::NSP_SUFFIX)
        );
        assert_eq!(
            extract_apex_name(&format!(
                "{}{}",
                "saifmukhtar",
                crate::constants::NSP_SUFFIX
            )),
            format!("{}{}", "saifmukhtar", crate::constants::NSP_SUFFIX)
        );
        assert_eq!(
            extract_apex_name(&format!(
                "{}{}",
                "api.v1.saifmukhtar",
                crate::constants::NSP_SUFFIX
            )),
            format!("{}{}", "saifmukhtar", crate::constants::NSP_SUFFIX)
        );
    }
}

#[cfg(test)]
mod names_tests {
    use super::*;

    #[test]
    fn test_lock_protocol_names() {
        // These should be rejected because they are locked Category 2
        assert_eq!(
            is_valid_apex_name("docs.kin"),
            Err(crate::error::NamesError::ProtocolName)
        );
        assert_eq!(
            is_valid_apex_name("seed.kin"),
            Err(crate::error::NamesError::ProtocolName)
        );
        assert_eq!(
            is_valid_apex_name("subdomain.explorer.kin"),
            Err(crate::error::NamesError::NotAnApexName)
        );

        // These should be accepted (Category 3/normal names)
        assert!(is_valid_apex_name("satoshi.kin").is_ok());
        assert!(is_valid_apex_name("myname.kin").is_ok());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn doesnt_crash_normalize_name(s in any::<String>()) {
            let normalized = normalize_name(&s);
            assert!(normalized.ends_with(crate::constants::NSP_SUFFIX));
        }

        #[test]
        fn doesnt_crash_extract_apex(s in any::<String>()) {
            let _ = extract_apex_name(&s);
        }

        #[test]
        fn doesnt_crash_is_valid_apex(s in any::<String>()) {
            let _ = is_valid_apex_name(&s);
        }
    }
}
