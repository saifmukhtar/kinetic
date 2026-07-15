use kinetic_core::types::extract_apex_domain;

#[test]
fn test_cctld_extraction() {
    let simple = extract_apex_domain(&format!(
        "{}{}",
        "blog.saif",
        kinetic_core::constants::TLD_SUFFIX
    ));
    assert_eq!(
        simple,
        format!("{}{}", "saif", kinetic_core::constants::TLD_SUFFIX)
    );

    let cctld = extract_apex_domain(&format!(
        "{}{}",
        "blog.saif.co.uk",
        kinetic_core::constants::TLD_SUFFIX
    ));
    assert_eq!(cctld, "saif.co.uk.kin");
}
