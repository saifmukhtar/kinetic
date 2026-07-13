pub const TLD: &str = "kin";
pub const DOT_TLD: &str = ".kin";

pub fn normalize_name(name: &str) -> String {
    let mut norm = name.to_lowercase();
    while norm.ends_with('.') {
        norm.pop();
    }
    if !norm.ends_with(DOT_TLD) {
        norm.push_str(DOT_TLD);
    }
    norm
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

pub fn is_valid_apex_name(name: &str) -> Result<(), crate::error::NamesError> {
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
    let parts: Vec<&str> = apex.split('.').collect();
    if !parts.is_empty() && PUBLIC_NAMES.contains(&parts[0]) {
        return Err(crate::error::NamesError::ReservedName);
    }

    // Category 2: Infrastructure Names (Locked until Phase 2)
    if crate::types::infrastructure::is_infrastructure_name(&norm) {
        return Err(crate::error::NamesError::InfrastructureName);
    }

    Ok(())
}

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
        assert_eq!(normalize_name("SAIF.KIN"), format!("{}{}", "saif", DOT_TLD));
        assert_eq!(normalize_name("saif..."), format!("{}{}", "saif", DOT_TLD));
        assert_eq!(normalize_name("saif"), format!("{}{}", "saif", DOT_TLD));
        assert_eq!(normalize_name("blog.saif.kin."), format!("{}{}", "blog.saif", DOT_TLD));
    }

    #[test]
    fn test_is_valid_apex_name() {
        assert!(is_valid_apex_name(&format!("{}{}", "saif", DOT_TLD)).is_ok());
        assert!(is_valid_apex_name("saif").is_ok());
        assert!(is_valid_apex_name("saif-123").is_ok());
        assert!(is_valid_apex_name("007").is_ok());
        
        assert_eq!(is_valid_apex_name(&format!("{}{}", "blog.saif", DOT_TLD)), Err(crate::error::NamesError::NotAnApexDomain));
        assert_eq!(is_valid_apex_name("saif_123"), Err(crate::error::NamesError::InvalidCharacter));
        assert_eq!(is_valid_apex_name("saif!"), Err(crate::error::NamesError::InvalidCharacter));
        assert_eq!(is_valid_apex_name("-saif"), Err(crate::error::NamesError::InvalidCharacter));
        assert_eq!(is_valid_apex_name("saif-"), Err(crate::error::NamesError::InvalidCharacter));
        
        // Test RFC Category 1 Reserved Names
        assert_eq!(is_valid_apex_name("test.kin"), Err(crate::error::NamesError::ReservedName));
        assert_eq!(is_valid_apex_name("example"), Err(crate::error::NamesError::ReservedName));
        assert_eq!(is_valid_apex_name("localhost.co.uk.kin"), Err(crate::error::NamesError::ReservedName));
        assert_eq!(is_valid_apex_name("null.kin"), Err(crate::error::NamesError::ReservedName));
    }

    #[test]
    fn test_extract_apex_domain() {
        assert_eq!(
            extract_apex_domain(&format!("{}{}", "blog.saif", DOT_TLD)),
            format!("{}{}", "saif", DOT_TLD)
        );
        assert_eq!(
            extract_apex_domain(&format!("{}{}", "saif", DOT_TLD)),
            format!("{}{}", "saif", DOT_TLD)
        );
        assert_eq!(
            extract_apex_domain(&format!("{}{}", "api.v1.saif", DOT_TLD)),
            format!("{}{}", "saif", DOT_TLD)
        );
    }
}

#[cfg(test)]
mod names_tests {
    use super::*;

    #[test]
    fn test_lock_infrastructure_names() {
        // These should be rejected because they are locked Category 2
        assert_eq!(is_valid_apex_name("docs.kin"), Err(crate::error::NamesError::InfrastructureName));
        assert_eq!(is_valid_apex_name("seed.kin"), Err(crate::error::NamesError::InfrastructureName));
        assert_eq!(is_valid_apex_name("subdomain.explorer.kin"), Err(crate::error::NamesError::NotAnApexDomain));

        // These should be accepted (Category 3/normal names)
        assert!(is_valid_apex_name("satoshi.kin").is_ok());
        assert!(is_valid_apex_name("myname.kin").is_ok());
    }
}
