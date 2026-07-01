use kinetic_core::types::extract_apex_domain;

#[test]
fn test_cctld_extraction() {
    let simple = extract_apex_domain("blog.saif.kin");
    assert_eq!(simple, "saif.kin");

    let cctld = extract_apex_domain("blog.saif.co.uk.kin");
    assert_eq!(cctld, "saif.co.uk.kin");
}
