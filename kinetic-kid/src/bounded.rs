//! Bounded Serde deserialization helpers for DoS and OOM protection.
//!
//! Standard JSON deserializers allocate memory based on sequence length hints, which
//! exposes the node to JSON memory bomb attacks (e.g., an array claiming 10 million items).
//! This module implements strict streaming boundaries that enforce compile-time limits
//! (derived from `network.json`) *during* stream parsing, instantly aborting on violation
//! before excessive memory can be allocated.
use serde::de::{Error, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::marker::PhantomData;

/// Custom Serde visitor enforcing maximum sequence element bounds.
struct BoundedVecVisitor<T> {
    max: usize,
    marker: PhantomData<fn() -> Vec<T>>,
}

impl<T> BoundedVecVisitor<T> {
    fn new(max: usize) -> Self {
        Self {
            max,
            marker: PhantomData,
        }
    }
}

impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a sequence with at most {} elements", self.max)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if let Some(size) = seq.size_hint()
            && size > self.max
        {
            return Err(A::Error::invalid_length(size, &self));
        }

        let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(self.max));
        let mut count = 0;

        while let Some(element) = seq.next_element()? {
            if count >= self.max {
                return Err(A::Error::custom(format!(
                    "array exceeded maximum allowed length of {}",
                    self.max
                )));
            }
            vec.push(element);
            count += 1;
        }

        Ok(vec)
    }
}

/// Deserializes a `Vec` with a strict memory-safe upper bound of 20 elements.
///
/// Used for protecting high-risk cryptographic arrays (like `controller_keys` and
/// `revocation_keys`) against deserialization memory exhaustion attacks.
///
/// # Errors
///
/// Returns a Serde deserialization error if the input array contains more than 20 items.
pub fn deserialize_max_20<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor::new(20))
}

/// Deserializes a `Vec` with a strict memory-safe upper bound of 50 elements.
///
/// Used for protecting manifest `services` arrays against deserialization memory exhaustion attacks.
///
/// # Errors
///
/// Returns a Serde deserialization error if the input array contains more than 50 items.
pub fn deserialize_max_50<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor::new(50))
}
