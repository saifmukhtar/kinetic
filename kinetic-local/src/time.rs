use kinetic_kyn::types::{Kyn, UKyn};

/// Derives the current estimated Kyn purely from the local OS clock.
/// This should only be used as a fallback during genesis/initial sync when no Time Oracle data is available.
pub fn now_local(genesis: u64) -> Kyn {
    let now_sec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    UKyn(now_sec).to_kyn(genesis)
}
