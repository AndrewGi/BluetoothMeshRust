//! Timestamp module for keeping track of time. Different systems have different clock sources so
//! this module generalizes over it. By default, it uses the `std::time::Instant` but it could use
//! a crystal oscillator clock (for ARM) or some other source.
use core::ops::Add;
use core::time::Duration;
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct Timestamp {}

pub trait TimestampTrait: Sized + Add<Duration, Output = Self> + Clone + Copy + Ord + Eq {
    fn now() -> Self;
    fn with_delay(delay: core::time::Duration) -> Self {
        Self::now() + delay
    }
    /// Returns `Some(self - other)` or `None` if `self > other`
    fn until(&self, other: Self) -> Option<Duration>;
}
