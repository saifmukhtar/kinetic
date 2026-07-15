use super::*;

pub(crate) fn is_ssrf_risk(ip: std::net::IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // 100.64.0.0/10 (CGNAT / Cloud Metadata)
            if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
                return true;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 {
                return true;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 169.254.0.0/16 (Link-local)
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // 192.0.2.0/24 (TEST-NET-1)
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
                return true;
            }
            // 198.51.100.0/24 (TEST-NET-2)
            if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
                return true;
            }
            // 203.0.113.0/24 (TEST-NET-3)
            if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
                return true;
            }
            // 240.0.0.0/4 (Reserved)
            if (octets[0] & 0b1111_0000) == 240 {
                return true;
            }
            false
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            // fc00::/7 (Unique local)
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // fe80::/10 (Link-local)
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr};

    proptest! {
        #[test]
        fn test_fuzz_is_ssrf_risk_rejects_loopback(
            a in 127u8..=127,
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255
        ) {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            prop_assert!(is_ssrf_risk(ip));
        }

        #[test]
        fn test_fuzz_is_ssrf_risk_rejects_internal_10(
            a in 10u8..=10,
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255
        ) {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            prop_assert!(is_ssrf_risk(ip));
        }

        #[test]
        fn test_fuzz_is_ssrf_risk_allows_public(
            a in 1u8..=9, // Avoid 0 (unspecified) and 10 (internal)
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255
        ) {
            let ip = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            prop_assert!(!is_ssrf_risk(ip));
        }
    }
}
