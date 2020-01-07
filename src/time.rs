use core::ops::Add;
use core::time::Duration;

pub const fn check_timestamp_support() -> bool {
    if cfg!(feature = "std") {
        true
    } else {
        false
    }
}
const SUPPORTS_TIMESTAMP: bool = check_timestamp_support();
pub fn assert_timestamp() {
    assert!(SUPPORTS_TIMESTAMP, "need some timestamp implementation");
}
type DefaultTimestamp: TimestampTrait = ;

pub trait TimestampTrait: Sized {
    fn now() -> Self;
    fn duration_since(self: )
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy, Debug, Hash)]
pub struct Timestamp(DefaultTimestamp);

impl Timestamp {
    #[must_use]
    pub fn now() -> Timestamp {
        assert_timestamp()
        Timestamp(std::time::Instant::now())
    }
    #[must_use]
    pub fn duration_since(self, other: Timestamp) -> Option<Duration> {
        assert!(SUPPORTS_TIMESTAMP)
        if other > self {
            None
        } else {

        }
    }
    #[must_use]
    pub fn duration_until(self, other: Timestamp) -> Option<Duration> {
        other.duration_since(self)
    }
    #[must_use]
    pub fn with_delay(delay: Duration) -> Timestamp {
        Self::now() + delay
    }
}
impl core::ops::Add<Duration> for Timestamp {
    type Output = Timestamp;

    #[must_use]
    fn add(self, _rhs: Duration) -> Self::Output {
        unimplemented!()
    }
}
