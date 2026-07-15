use moka::future::Cache;
use moka::Expiry;
use std::time::{Duration, Instant};

pub struct KineticExpiry;

impl Expiry<String, Option<Vec<u8>>> for KineticExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &Option<Vec<u8>>,
        _created_at: Instant,
    ) -> Option<Duration> {
        if value.is_some() {
            Some(Duration::from_secs(300)) // 5 minutes positive cache
        } else {
            Some(Duration::from_secs(30)) // 30 seconds negative cache (NXDOMAIN)
        }
    }

    fn expire_after_read(
        &self,
        _key: &String,
        _value: &Option<Vec<u8>>,
        _read_at: Instant,
        duration_until_expiry: Option<Duration>,
        _last_modified_at: Instant,
    ) -> Option<Duration> {
        duration_until_expiry // Do not extend TTL on read
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &Option<Vec<u8>>,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        if value.is_some() {
            Some(Duration::from_secs(300))
        } else {
            Some(Duration::from_secs(30))
        }
    }
}

pub fn create_cache() -> Cache<String, Option<Vec<u8>>> {
    Cache::builder().expire_after(KineticExpiry).build()
}
