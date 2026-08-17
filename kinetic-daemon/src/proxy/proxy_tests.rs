#[cfg(test)]
mod tests {
    use crate::proxy::validate_ssrf_risk;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_ssrf_protection_loopback() {
        assert!(validate_ssrf_risk(IpAddr::from_str("127.0.0.1").unwrap()).is_err());
        assert!(validate_ssrf_risk(IpAddr::from_str("::1").unwrap()).is_err());
    }

    #[test]
    fn test_ssrf_protection_private() {
        assert!(validate_ssrf_risk(IpAddr::from_str("10.0.0.1").unwrap()).is_err());
        assert!(validate_ssrf_risk(IpAddr::from_str("172.16.0.1").unwrap()).is_err());
        assert!(validate_ssrf_risk(IpAddr::from_str("192.168.1.1").unwrap()).is_err());
    }

    #[test]
    fn test_ssrf_protection_cgnat() {
        // Blocks Cloud Metadata APIs
        assert!(validate_ssrf_risk(IpAddr::from_str("100.64.0.1").unwrap()).is_err());
    }

    #[test]
    fn test_ssrf_protection_link_local() {
        assert!(validate_ssrf_risk(IpAddr::from_str("169.254.169.254").unwrap()).is_err());
        assert!(validate_ssrf_risk(IpAddr::from_str("fe80::1").unwrap()).is_err());
    }

    #[test]
    fn test_ssrf_protection_public_allowed() {
        assert!(validate_ssrf_risk(IpAddr::from_str("8.8.8.8").unwrap()).is_ok());
        assert!(validate_ssrf_risk(IpAddr::from_str("1.1.1.1").unwrap()).is_ok());
    }

    // Path Traversal & Proxy Size tests are covered in P2P handling internally
}
