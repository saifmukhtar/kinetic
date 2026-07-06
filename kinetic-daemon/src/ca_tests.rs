#[cfg(test)]
mod tests {
    use crate::ca::{load_or_create_root_ca, LeafCertCache};
    use tempfile::tempdir;

    #[test]
    fn test_leaf_cert_cache_eviction() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let dir = tempdir().unwrap();
        let (root_ca, _) = load_or_create_root_ca(dir.path()).unwrap();

        let mut cache = LeafCertCache::new();
        cache.max_entries = 5;

        for i in 0..10 {
            let domain = format!("test{}.kin", i);
            cache.get_or_create(&domain, &root_ca).unwrap();
        }

        // Assert cache size is max 5
        assert_eq!(cache.entries.len(), 5);
        // Ensure newest domains are in the cache
        assert!(cache.entries.contains_key("test9.kin"));
    }

    #[test]
    fn test_ca_lock_file_stale_recovery() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let dir = tempdir().unwrap();
        let lock_path = dir.path().join(".ca.lock");

        // Create a stale lock file
        std::fs::write(&lock_path, "").unwrap();

        // Should recover and delete the lock
        let _ = load_or_create_root_ca(dir.path()).unwrap();
        assert!(!lock_path.exists());
    }

    #[test]
    fn test_load_existing_root_ca() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let dir = tempdir().unwrap();

        // First call should generate
        let (root_ca_1, generated) = load_or_create_root_ca(dir.path()).unwrap();
        assert!(generated);

        // Second call should load
        let (root_ca_2, generated_again) = load_or_create_root_ca(dir.path()).unwrap();
        assert!(!generated_again);

        assert_eq!(root_ca_1.cert_pem, root_ca_2.cert_pem);
    }

    #[test]
    fn test_generate_leaf_cert() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let dir = tempdir().unwrap();
        let (root_ca, _) = load_or_create_root_ca(dir.path()).unwrap();

        let _config = crate::ca::generate_leaf_cert("testdomain.kin", &root_ca).unwrap();
        // If it returns Ok, the generation and rustls struct conversion succeeded.
    }
}
