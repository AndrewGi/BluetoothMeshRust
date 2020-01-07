#[cfg(feature = "std")]
extern crate std;

use crate::time::TimestampTrait;

#[cfg(feature = "std")]
pub struct StdTimestamp {
    instant: std::time::Instant,
}
impl TimestampTrait for StdTimestamp {}
