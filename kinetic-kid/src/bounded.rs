use serde::{Deserialize, Deserializer};
use serde::de::{Error, SeqAccess, Visitor};
use std::fmt;
use std::marker::PhantomData;

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
        if let Some(size) = seq.size_hint() {
            if size > self.max {
                return Err(A::Error::invalid_length(size, &self));
            }
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

/// Helper for serde to deserialize a Vec with a maximum length of 20 elements.
pub fn deserialize_max_20<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor::new(20))
}

/// Helper for serde to deserialize a Vec with a maximum length of 50 elements.
pub fn deserialize_max_50<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor::new(50))
}
