use crate::types::VdfJobRequest;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MempoolItem {
    pub request: VdfJobRequest,
    pub timestamp: SystemTime,
}

impl PartialEq for MempoolItem {
    fn eq(&self, other: &Self) -> bool {
        self.request.hashcash_nonce == other.request.hashcash_nonce
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
        // Higher hashcash nonce implies more work (for simplistic PoW proxy)
        // Ideally we re-hash to confirm leading zeros, but we assume it's pre-verified before insertion.
        // If equal, the older timestamp wins.
        match self
            .request
            .hashcash_nonce
            .cmp(&other.request.hashcash_nonce)
        {
            Ordering::Equal => other.timestamp.cmp(&self.timestamp),
            other_cmp => other_cmp,
        }
    }
}

pub struct Mempool {
    queue: BinaryHeap<MempoolItem>,
    max_capacity: usize,
    expiry: Duration,
}

impl Mempool {
    pub fn new(max_capacity: usize, expiry: Duration) -> Self {
        Self {
            queue: BinaryHeap::new(),
            max_capacity,
            expiry,
        }
    }

    /// Add a request to the mempool. Returns true if added, false if rejected.
    pub fn add(&mut self, request: VdfJobRequest) -> bool {
        self.clean_expired();

        // If we are at capacity, check if this request has a higher priority than the lowest one.
        // BinaryHeap is a max-heap, so finding the minimum requires inspecting all elements.
        // To simplify, we just let it grow and pop, or use a min-max heap.
        // For standard BinaryHeap, we can convert it into a vec, sort, truncate, and rebuild if we exceed capacity.
        if self.queue.len() >= self.max_capacity {
            let mut items: Vec<_> = self.queue.drain().collect();
            items.sort();
            // The lowest priority item is at index 0 (since it sorts ascending by default, wait, Ord is implemented so highest is last?
            // Wait, BinaryHeap pops the MAXIMUM element according to Ord.
            // If Ord implements `self.cmp(other)`, then the MAX element has the highest priority.
            // So items.sort() sorts in ascending order. The lowest priority is at index 0.
            if let Some(lowest) = items.first() {
                if request.hashcash_nonce <= lowest.request.hashcash_nonce {
                    // Rejected
                    self.queue = items.into();
                    return false;
                }
            }
            // Replace the lowest
            items[0] = MempoolItem {
                request,
                timestamp: SystemTime::now(),
            };
            self.queue = items.into();
            return true;
        }

        self.queue.push(MempoolItem {
            request,
            timestamp: SystemTime::now(),
        });
        true
    }

    pub fn pop(&mut self) -> Option<VdfJobRequest> {
        self.clean_expired();
        self.queue.pop().map(|item| item.request)
    }

    fn clean_expired(&mut self) {
        let now = SystemTime::now();
        let expiry = self.expiry;

        let mut valid_items = Vec::new();
        while let Some(item) = self.queue.pop() {
            if let Ok(age) = now.duration_since(item.timestamp) {
                if age <= expiry {
                    valid_items.push(item);
                }
            }
        }
        self.queue = valid_items.into();
    }

    pub fn dump(&self) -> Vec<u8> {
        let items: Vec<MempoolItem> = self.queue.clone().into_sorted_vec();
        serde_json::to_vec(&items).unwrap_or_default()
    }

    pub fn load(&mut self, data: &[u8]) {
        if let Ok(items) = serde_json::from_slice::<Vec<MempoolItem>>(data) {
            for item in items {
                self.queue.push(item);
            }
            self.clean_expired();
        }
    }
}
