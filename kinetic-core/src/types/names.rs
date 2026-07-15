pub const TLD: &str = "kin";
// We use the TLD_SUFFIX from constants.rs directly instead of crate::constants::TLD_SUFFIX.

/// Normalizes a given name string by converting to lowercase, removing trailing dots, and ensuring it ends with the Kinetic TLD suffix.
pub fn normalize_name(name: &str) -> String {
    let mut norm = name.to_lowercase();
    while norm.ends_with('.') {
        norm.pop();
    }
    if !norm.ends_with(crate::constants::TLD_SUFFIX) {
        norm.push_str(crate::constants::TLD_SUFFIX);
    }
    norm
}

/// Checks if a given domain name is a reserved name.
/// Hardcoded reserved names are evaluated dynamically based on TLD.
pub fn is_reserved_name(name: &str) -> bool {
    let tld = crate::constants::TLD_SUFFIX;
    let reserved = vec![
        format!("co.uk{}", tld),
        format!("uk{}", tld),
        format!("co{}", tld),
        format!("id{}", tld),
        format!("app{}", tld),
        format!("dapp{}", tld),
        format!("localhost{}", tld),
        format!("test{}", tld),
        format!("invalid{}", tld),
        format!("local{}", tld),
        format!("null{}", tld),
    ];
    reserved.contains(&name.to_lowercase())
}

pub const KINETIC_TLDS: &[&str] = &[
    "co.uk.kin",
    "uk.kin",
    "co.kin",
    "id.kin",
    "app.kin",
    "dapp.kin",
    TLD,
];

/// Category 1: Public Utility Names (Based on RFC 2606 & RFC 6761)
/// These names are permanently locked and cannot be registered by anyone.
pub const PUBLIC_NAMES: &[&str] = &[
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
];

/// Validates whether a given domain name is a valid apex domain that can be registered.
/// It checks against standard DNS label rules, lengths, and Kinetic reserved name categories.
pub fn is_valid_apex_name(name: &str) -> Result<(), crate::error::NamesError> {
    let name_lower = name.to_lowercase();
    if !name_lower.ends_with(crate::constants::TLD_SUFFIX) {
        let err = crate::error::NamesError::InvalidTLD;
        return Err(err);
    }

    let norm = normalize_name(name);

    if norm.len() > 253 || norm.is_empty() {
        return Err(crate::error::NamesError::NameTooLong);
    }
    for part in norm.split('.') {
        if part.len() > 63 || part.is_empty() {
            return Err(crate::error::NamesError::LabelTooLong);
        }

        // DNS LDH Rule: Only lowercase letters, digits, and hyphens allowed.
        for c in part.chars() {
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
                return Err(crate::error::NamesError::InvalidCharacter);
            }
        }

        // Hyphens cannot be at the start or end of a label
        if part.starts_with('-') || part.ends_with('-') {
            return Err(crate::error::NamesError::InvalidCharacter);
        }
    }

    let apex = extract_apex_domain(&norm);
    if norm != apex {
        return Err(crate::error::NamesError::NotAnApexDomain);
    }

    // Ensure the registered label is not a Category 1 reserved public utility name.
    if is_reserved_name(&name_lower) {
        return Err(crate::error::NamesError::ReservedName);
    }

    // Category 2: Infrastructure Names (Locked until Phase 2)
    if crate::types::infrastructure::is_infrastructure_name(&norm) {
        return Err(crate::error::NamesError::InfrastructureName);
    }

    Ok(())
}

/// Extracts the apex domain (e.g., `saif.kin`) from a potentially longer subdomain name (e.g., `blog.saif.kin`).
pub fn extract_apex_domain(name: &str) -> String {
    let norm = normalize_name(name);

    for tld in KINETIC_TLDS {
        if norm.ends_with(tld) {
            if norm.len() == tld.len() {
                return norm;
            }

            let suffix_start = norm.len() - tld.len();
            if norm.as_bytes()[suffix_start - 1] == b'.' {
                let without_tld = &norm[0..suffix_start - 1];
                if without_tld.is_empty() {
                    return norm;
                }
                let parts: Vec<&str> = without_tld.split('.').collect();
                let apex_label = parts.last().unwrap_or(&"");
                return format!("{}.{}", apex_label, tld);
            }
        }
    }

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
            normalize_name("SAIF.KIN"),
            format!("{}{}", "saif", crate::constants::TLD_SUFFIX)
        );
        assert_eq!(
            normalize_name("saif..."),
            format!("{}{}", "saif", crate::constants::TLD_SUFFIX)
        );
        assert_eq!(
            normalize_name("saif"),
            format!("{}{}", "saif", crate::constants::TLD_SUFFIX)
        );
        assert_eq!(
            normalize_name("blog.saif.kin."),
            format!("{}{}", "blog.saif", crate::constants::TLD_SUFFIX)
        );
    }

    #[test]
    fn test_is_valid_apex_name() {
        assert!(is_valid_apex_name(&format!("{}{}", "saif", crate::constants::TLD_SUFFIX)).is_ok());
        assert!(is_valid_apex_name(&format!("{}{}", "saif", crate::constants::TLD_SUFFIX)).is_ok());
        assert!(
            is_valid_apex_name(&format!("{}{}", "saif-123", crate::constants::TLD_SUFFIX)).is_ok()
        );
        assert!(is_valid_apex_name(&format!("{}{}", "007", crate::constants::TLD_SUFFIX)).is_ok());

        assert_eq!(
            is_valid_apex_name(&format!("{}{}", "blog.saif", crate::constants::TLD_SUFFIX)),
            Err(crate::error::NamesError::NotAnApexDomain)
        );
        assert_eq!(
            is_valid_apex_name(&format!("{}{}", "saif_123", crate::constants::TLD_SUFFIX)),
            Err(crate::error::NamesError::InvalidCharacter)
        );
        assert_eq!(
            is_valid_apex_name(&format!("{}{}", "saif!", crate::constants::TLD_SUFFIX)),
            Err(crate::error::NamesError::InvalidCharacter)
        );
        assert_eq!(
            is_valid_apex_name(&format!("{}{}", "-saif", crate::constants::TLD_SUFFIX)),
            Err(crate::error::NamesError::InvalidCharacter)
        );
        assert_eq!(
            is_valid_apex_name(&format!("{}{}", "saif-", crate::constants::TLD_SUFFIX)),
            Err(crate::error::NamesError::InvalidCharacter)
        );

        // Test RFC Category 1 Reserved Names
        assert_eq!(
            is_valid_apex_name(&format!("test{}", crate::constants::TLD_SUFFIX)),
            Err(crate::error::NamesError::ReservedName)
        );
        assert_eq!(
            is_valid_apex_name(&format!("localhost{}", crate::constants::TLD_SUFFIX)),
            Err(crate::error::NamesError::ReservedName)
        );
        assert_eq!(
            is_valid_apex_name(&format!("null{}", crate::constants::TLD_SUFFIX)),
            Err(crate::error::NamesError::ReservedName)
        );
    }

    #[test]
    fn test_extract_apex_domain() {
        assert_eq!(
            extract_apex_domain(&format!("{}{}", "blog.saif", crate::constants::TLD_SUFFIX)),
            format!("{}{}", "saif", crate::constants::TLD_SUFFIX)
        );
        assert_eq!(
            extract_apex_domain(&format!("{}{}", "saif", crate::constants::TLD_SUFFIX)),
            format!("{}{}", "saif", crate::constants::TLD_SUFFIX)
        );
        assert_eq!(
            extract_apex_domain(&format!(
                "{}{}",
                "api.v1.saif",
                crate::constants::TLD_SUFFIX
            )),
            format!("{}{}", "saif", crate::constants::TLD_SUFFIX)
        );
    }
}

#[cfg(test)]
mod names_tests {
    use super::*;

    #[test]
    fn test_lock_infrastructure_names() {
        // These should be rejected because they are locked Category 2
        assert_eq!(
            is_valid_apex_name("docs.kin"),
            Err(crate::error::NamesError::InfrastructureName)
        );
        assert_eq!(
            is_valid_apex_name("seed.kin"),
            Err(crate::error::NamesError::InfrastructureName)
        );
        assert_eq!(
            is_valid_apex_name("subdomain.explorer.kin"),
            Err(crate::error::NamesError::NotAnApexDomain)
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
            assert!(normalized.ends_with(crate::constants::TLD_SUFFIX));
        }

        #[test]
        fn doesnt_crash_extract_apex(s in any::<String>()) {
            let _ = extract_apex_domain(&s);
        }

        #[test]
        fn doesnt_crash_is_valid_apex(s in any::<String>()) {
            let _ = is_valid_apex_name(&s);
        }
    }
}
