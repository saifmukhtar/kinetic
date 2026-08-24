use kinetic_core::types::{DnsRecord, DnsZone, DnsZoneExt};

#[test]
fn test_dns_zone_validation() {
    let mut zone = DnsZone {
        records: std::collections::HashMap::new(),
    };

    // 1. Max Records Bomb Test
    let mut massive_records = Vec::new();
    for _ in 0..51 {
        massive_records.push(DnsRecord::TXT("bomb".to_string()));
    }
    zone.records.insert("@".to_string(), massive_records);
    assert!(
        zone.validate().is_err(),
        "Zone with 51 records should be rejected!"
    );

    zone.records.clear();

    // 2. Invalid Label Tests
    zone.records.insert(
        "-bad-prefix".to_string(),
        vec![DnsRecord::TXT("value".to_string())],
    );
    assert!(
        zone.validate().is_err(),
        "Label starting with hyphen should fail!"
    );
    zone.records.clear();

    zone.records.insert(
        "bad-suffix-".to_string(),
        vec![DnsRecord::TXT("value".to_string())],
    );
    assert!(
        zone.validate().is_err(),
        "Label ending with hyphen should fail!"
    );
    zone.records.clear();

    let long_label = "a".repeat(64);
    zone.records
        .insert(long_label, vec![DnsRecord::TXT("value".to_string())]);
    assert!(zone.validate().is_err(), "Label over 63 chars should fail!");
    zone.records.clear();

    // 3. Valid Labels
    zone.records.insert(
        "api-v1".to_string(),
        vec![DnsRecord::TXT("value".to_string())],
    );
    assert!(zone.validate().is_ok(), "Valid LDH label should pass!");
}
