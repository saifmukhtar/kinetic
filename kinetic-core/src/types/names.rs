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
];

pub fn is_valid_apex_name(name: &str) -> bool {
    let norm = normalize_name(name);

    if norm.len() > 253 || norm.is_empty() {
        return false;
    }
    for part in norm.split('.') {
        if part.len() > 63 || part.is_empty() {
            return false;
        }

        // DNS LDH Rule: Only lowercase letters, digits, and hyphens allowed.
        for c in part.chars() {
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
                return false;
            }
        }

        // Hyphens cannot be at the start or end of a label
        if part.starts_with('-') || part.ends_with('-') {
            return false;
        }
    }

    let apex = extract_apex_domain(&norm);
    if norm != apex {
        return false;
    }

    // Ensure the registered label is not a Category 1 reserved public utility name.
    let parts: Vec<&str> = apex.split('.').collect();
    if !parts.is_empty() && PUBLIC_NAMES.contains(&parts[0]) {
        return false;
    }

    // Category 2: Infrastructure Names (Locked until Phase 2)
    if crate::types::infrastructure::is_infrastructure_name(&norm) {
        return false;
    }

    true
}

pub fn extract_apex_domain(name: &str) -> String {
    let norm = normalize_name(name);

    for tld in KINETIC_TLDS {
        if norm.ends_with(&format!(".{}", tld)) || norm == *tld {
            let without_tld = norm.strip_suffix(&format!(".{}", tld)).unwrap_or(&norm);
            if without_tld.is_empty() || without_tld == norm {
                return norm;
            }
            let parts: Vec<&str> = without_tld.split('.').collect();
            let apex_label = parts.last().unwrap_or(&"");
            return format!("{}.{}", apex_label, tld);
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
        assert!(is_valid_apex_name(&format!("{}{}", "saif", DOT_TLD)));
        assert!(is_valid_apex_name("saif"));
        assert!(is_valid_apex_name("saif-123"));
        assert!(is_valid_apex_name("007"));
        
        assert!(!is_valid_apex_name(&format!("{}{}", "blog.saif", DOT_TLD))); // Not an apex
        assert!(!is_valid_apex_name("saif_123")); // Invalid char (_)
        assert!(!is_valid_apex_name("saif!")); // Invalid char (!)
        assert!(!is_valid_apex_name("-saif")); // Leading hyphen
        assert!(!is_valid_apex_name("saif-")); // Trailing hyphen
        
        // Test RFC Category 1 Reserved Names
        assert!(!is_valid_apex_name("test.kin"));
        assert!(!is_valid_apex_name("example"));
        assert!(!is_valid_apex_name("localhost.co.uk.kin"));
        assert!(!is_valid_apex_name("null.kin"));
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
        assert_eq!(is_valid_apex_name("docs.kin"), false);
        assert_eq!(is_valid_apex_name("seed.kin"), false);
        assert_eq!(is_valid_apex_name("subdomain.explorer.kin"), false);

        // These should be accepted (Category 3/normal names)
        assert_eq!(is_valid_apex_name("satoshi.kin"), true);
        assert_eq!(is_valid_apex_name("myname.kin"), true);
    }
}
