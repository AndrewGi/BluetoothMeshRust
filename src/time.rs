use alloc::collections::BinaryHeap;
use core::cmp::Ordering;
use core::time::Duration;

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy, Debug, Hash)]
pub struct Timestamp {}

impl Timestamp {
    pub fn now() -> Timestamp {
        unimplemented!()
    }
    pub fn duration_since(&self, other: &Timestamp) -> Option<Duration> {
        if other > self {
            None
        } else {
            Some(unimplemented!())
        }
    }
    pub fn duration_until(&self, other: &Timestamp) -> Option<Duration> {
        other.duration_since(self)
    }
}
