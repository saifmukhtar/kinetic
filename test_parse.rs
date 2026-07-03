fn main() {
    let payload = r#"{"records":{"@":[{"type":"KID","value":"did:kin:3c83f05d3e92506380c0f32e70bbf5eef571fb478556109cede6a0bc7245d0b6"},{"type":"PeerId","value":"12D3KooWLpZ6Xc5g7w691YcSnseJBUemHbo625aqRB4wAL1sjnaN"}]}}"#;
    let zone: kinetic_core::types::DnsZone = serde_json::from_str(payload).unwrap();
    println!("{:?}", zone);
}
