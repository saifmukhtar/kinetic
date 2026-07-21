use std::net::IpAddr;

/// Checks if an IP address is safe to connect to or proxy through.
/// Blocks loopback, unspecified, private, link-local, broadcast, multicast,
/// documentation, CGNAT (100.64.0.0/10), and NAT64 (64:ff9b::/96) addresses.
pub fn is_ssrf_safe(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
            {
                return false;
            }
            let octets = v4.octets();
            if octets[0] == 0 {
                return false; // 0.0.0.0/8
            }
            if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
                return false; // 100.64.0.0/10 CGNAT
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }

            let segments = v6.segments();
            // IPv6 Link-Local (fe80::/10)
            if segments[0] & 0xffc0 == 0xfe80 {
                return false;
            }
            // IPv6 Unique Local (fc00::/7)
            if segments[0] & 0xfe00 == 0xfc00 {
                return false;
            }

            // Check for IPv4-mapped IPv6 address that wraps a dangerous v4
            if let Some(v4_mapped) = v6.to_ipv4_mapped() {
                return is_ssrf_safe(IpAddr::V4(v4_mapped));
            }

            let segments = v6.segments();
            // IPv6 NAT64 64:ff9b::/96
            if segments[0] == 0x0064
                && segments[1] == 0xff9b
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0
            {
                return false;
            }
            true
        }
    }
}
