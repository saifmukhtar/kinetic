use crate::types::VdfJobRequest;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use web_time::{Duration, SystemTime};

/// An item residing in the mempool priority queue.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MempoolItem {
    /// The VDF job request payload.
    pub request: VdfJobRequest,
    /// The timestamp when this item was added to the mempool.
    pub timestamp: SystemTime,
}

impl PartialEq for MempoolItem {
    fn eq(&self, other: &Self) -> bool {
        // Complete equality check to ensure BTreeSet uniqueness
        self.request.hashcash_nonce == other.request.hashcash_nonce
            && self.timestamp == other.timestamp
            && self.request.challenge_hash == other.request.challenge_hash
    }
}

impl Eq for MempoolItem {}

impl PartialOrd for MempoolItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MempoolItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // BTreeSet pops the "first" (smallest) element for eviction,
        // and the "last" (largest) element when processing jobs.
        // Therefore, LARGER means HIGHER priority.

        // 1. Higher hashcash nonce = higher priority
        match self
            .request
            .hashcash_nonce
            .cmp(&other.request.hashcash_nonce)
        {
            Ordering::Equal => {
                // 2. Older timestamp = higher priority.
                // So smaller (older) SystemTime should be considered "Larger" in Ord.
                // We reverse the timestamp comparison:
                match other.timestamp.cmp(&self.timestamp) {
                    Ordering::Equal => {
                        // 3. Fallback tie-breaker to prevent BTreeSet from treating different requests as identical
                        self.request
                            .challenge_hash
                            .cmp(&other.request.challenge_hash)
                    }
                    other_cmp => other_cmp,
                }
            }
            other_cmp => other_cmp,
        }
    }
}

/// A priority queue staging area for VDF jobs before they are processed.
pub struct Mempool {
    queue: BTreeSet<MempoolItem>,
    max_capacity: usize,
    expiry: Duration,
}

impl Mempool {
    /// Creates a new `Mempool` with a specific maximum capacity and expiration duration for jobs.
    pub fn new(max_capacity: usize, expiry: Duration) -> Self {
        Self {
            queue: BTreeSet::new(),
            max_capacity,
            expiry,
        }
    }

    /// Add a request to the mempool. Returns true if added, false if rejected.
    pub fn add(&mut self, request: VdfJobRequest) -> bool {
        self.clean_expired();

        let new_item = MempoolItem {
            request,
            timestamp: SystemTime::now(),
        };

        if self.queue.len() >= self.max_capacity {
            // Check if the new item is strictly better (greater) than our worst item
            if let Some(lowest) = self.queue.first() {
                if new_item <= *lowest {
                    // New item is lower or equal priority than our worst item, reject it.
                    return false;
                }
            }

            // It's better than the worst, so we evict the lowest priority item (first)
            // and insert the new one. This takes O(log N) time instead of O(N log N).
            self.queue.pop_first();
            self.queue.insert(new_item);
            return true;
        }

        self.queue.insert(new_item);
        true
    }

    /// Removes and returns the highest priority job from the mempool.
    pub fn pop(&mut self) -> Option<VdfJobRequest> {
        self.clean_expired();
        // Pop the highest priority item (largest element)
        self.queue.pop_last().map(|item| item.request)
    }

    fn clean_expired(&mut self) {
        let now = SystemTime::now();
        let expiry = self.expiry;

        // BTreeSet allows us to filter out expired items.
        // For a full production node, we might want a background task that prunes this,
        // but for now we iterate and remove.
        // Note: since BTreeSet is sorted by priority, not timestamp, we must check all.
        // We use retain to keep only valid items.
        self.queue.retain(|item| {
            if let Ok(age) = now.duration_since(item.timestamp) {
                age <= expiry
            } else {
                false // If clock jumped backwards, err on the side of dropping
            }
        });
    }

    /// Returns a list of all items currently in the mempool, sorted by priority.
    pub fn get_items(&self) -> Vec<MempoolItem> {
        // Since BTreeSet's iterator goes from smallest to largest,
        // we reverse it so the highest priority items are first in the list.
        self.queue.iter().rev().cloned().collect()
    }

    /// Serializes the mempool state to bytes for persistence.
    pub fn dump(&self) -> Vec<u8> {
        let items: Vec<MempoolItem> = self.queue.iter().cloned().collect();
        serde_json::to_vec(&items).unwrap_or_default()
    }

    /// Restores the mempool state from persisted bytes.
    pub fn load(&mut self, data: &[u8]) {
        if let Ok(items) = serde_json::from_slice::<Vec<MempoolItem>>(data) {
            for item in items {
                self.queue.insert(item);
            }
            self.clean_expired();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::VdfJobRequest;

    fn mock_request(nonce: u64, challenge_byte: u8) -> VdfJobRequest {
        VdfJobRequest {
            challenge_hash: [challenge_byte; 32],
            name_length: 5,
            hashcash_nonce: nonce,
            drand_pulse: 1234,
        }
    }

    #[test]
    fn test_mempool_evicts_lowest_priority() {
        let mut mempool = Mempool::new(3, Duration::from_secs(60));

        mempool.add(mock_request(10, 1));
        mempool.add(mock_request(30, 2));
        mempool.add(mock_request(20, 3));

        // It is full now. Next one should evict the lowest priority (nonce 10)
        // if it is higher than 10.
        let added = mempool.add(mock_request(15, 4));
        assert!(added);

        // Try to add one with lower priority than the lowest (which is now 15)
        let added = mempool.add(mock_request(12, 5));
        assert!(!added); // Should be rejected!

        // Pop should return highest priority first (30 -> 20 -> 15)
        assert_eq!(mempool.pop().unwrap().hashcash_nonce, 30);
        assert_eq!(mempool.pop().unwrap().hashcash_nonce, 20);
        assert_eq!(mempool.pop().unwrap().hashcash_nonce, 15);
        assert!(mempool.pop().is_none());
    }

    #[test]
    fn test_mempool_timestamp_tiebreaker() {
        let mut mempool = Mempool::new(5, Duration::from_secs(60));

        mempool.add(mock_request(50, 1)); // Older
        std::thread::sleep(Duration::from_millis(5));
        mempool.add(mock_request(50, 2)); // Newer

        // Older should have higher priority
        let first_popped = mempool.pop().unwrap();
        assert_eq!(first_popped.challenge_hash[0], 1);

        let second_popped = mempool.pop().unwrap();
        assert_eq!(second_popped.challenge_hash[0], 2);
    }
}
