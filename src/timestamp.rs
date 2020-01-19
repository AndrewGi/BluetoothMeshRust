//! Timestamp module for keeping track of time. Different systems have different clock sources so
//! this module generalizes over it. By default, it uses the `std::time::Instant` but it could use
//! a crystal oscillator clock (for ARM) or some other source.
use core::ops::Add;
use core::time::Duration;

#[cfg(feature = "std")]
mod std_timestamp {
    use crate::timestamp::TimestampTrait;
    use core::ops::Add;
    use core::time::Duration;

    #[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Hash, Debug)]
    pub struct StdTimestamp(std::time::Instant);
    impl Add<Duration> for StdTimestamp {
        type Output = StdTimestamp;

        fn add(self, rhs: Duration) -> Self::Output {
            StdTimestamp(self.0 + rhs)
        }
    }
    impl TimestampTrait for StdTimestamp {
        fn now() -> Self {
            Self(std::time::Instant::now())
        }

        fn until(&self, later: Self) -> Option<Duration> {
            later.0.checked_duration_since(self.0)
        }

        fn since(&self, earlier: Self) -> Option<Duration> {
            self.0.checked_duration_since(earlier.0)
        }
    }
}
#[cfg(not(feature = "std"))]
type InternalTimestamp = DummyTimestamp;
#[cfg(feature = "std")]
type InternalTimestamp = std_timestamp::StdTimestamp;
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Timestamp(InternalTimestamp);

pub trait TimestampTrait: Sized + Add<Duration, Output = Self> + Clone + Copy + Ord + Eq {
    fn now() -> Self;
    fn with_delay(delay: core::time::Duration) -> Self {
        Self::now() + delay
    }
    /// Returns `Some(self - other)` or `None` if `self > other`.
    fn until(&self, later: Self) -> Option<Duration>;
    /// Returns `Some(other - self)` or `None` if `other > self`.
    fn since(&self, earlier: Self) -> Option<Duration>;
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct DummyTimestamp(());
impl Add<Duration> for DummyTimestamp {
    type Output = Self;

    fn add(self, _rhs: Duration) -> Self::Output {
        unimplemented!("dummy timestamp")
    }
}
impl TimestampTrait for DummyTimestamp {
    fn now() -> Self {
        unimplemented!("dummy timestamp")
    }

    fn until(&self, _later: Self) -> Option<Duration> {
        unimplemented!("dummy timestamp")
    }

    fn since(&self, _earlier: Self) -> Option<Duration> {
        unimplemented!("dummy timestamp")
    }
}
