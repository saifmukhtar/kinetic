use kinetic_types::clock::UTime;

/// Returns the current local system time in seconds.
///
/// # Security
/// **DO NOT USE FOR CONSENSUS LOGIC.** 
/// This relies on the local OS wall-clock which can be trivially manipulated by users 
/// (e.g., changing their device calendar). This should only be used for UI/UX rendering 
/// or extremely low-security local timeouts. All protocol logic MUST derive time from 
/// the network `Kyn`.
pub fn now_unverified_os() -> UTime {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    UTime(now)
}
