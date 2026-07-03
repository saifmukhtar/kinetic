fn main() {
    let ip = std::net::Ipv4Addr::new(172, 31, 25, 188);
    println!("Private: {}", ip.is_private());
    println!("Loopback: {}", ip.is_loopback());
}
