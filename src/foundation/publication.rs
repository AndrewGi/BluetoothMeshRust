use crate::address::Address;
use crate::mesh::{AppKeyIndex, TransmitInterval, TTL};
use core::time;

/// 2-bit Step Resoution used for `PublishPeriod`, etc.
#[derive(Copy, Clone, Ord, PartialOrd, Debug, Hash, Eq, PartialEq)]
pub enum StepResolution {
    Milliseconds100 = 0b00,
    Second1 = 0b01,
    Second10 = 0b10,
    Minute10 = 0b11,
}
impl StepResolution {
    pub fn to_milliseconds(&self) -> u32 {
        match self {
            StepResolution::Milliseconds100 => 100,
            StepResolution::Second1 => 1000,
            StepResolution::Second10 => 10 * 1000,
            StepResolution::Minute10 => 10 * 60 * 1000,
        }
    }
}
impl From<StepResolution> for u8 {
    fn from(s: StepResolution) -> Self {
        s as u8
    }
}
const STEPS_MAX: u8 = 0x3F;
/// 6-bit Steps for Periods.
#[derive(Copy, Clone, Ord, PartialOrd, Debug, Hash, Eq, PartialEq)]
pub struct Steps(u8);
impl Steps {
    /// # Panics
    /// Panics if `steps == 0` or `steps > STEPS_MAX`
    pub fn new(steps: u8) -> Self {
        assert!(steps != 0 && steps <= STEPS_MAX);
        Self(steps)
    }
}
impl From<Steps> for u8 {
    fn from(s: Steps) -> Self {
        s.0
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct PublishPeriod {
    pub resolution: StepResolution,
    pub steps: Steps,
}
impl PublishPeriod {
    pub fn new(resolution: StepResolution, steps: Steps) -> Self {
        Self { resolution, steps }
    }
    pub fn to_milliseconds(&self) -> u32 {
        self.resolution.to_milliseconds() * u32::from(self.steps.0)
    }
    pub fn to_duration(&self) -> time::Duration {
        time::Duration::from_millis(self.to_milliseconds().into())
    }
    pub fn packed(&self) -> u8 {
        u8::from(self.steps) | u8::from(self.resolution) << 6
    }
    pub fn unpack(b: u8) -> Self {
        let steps = Steps::new(b & STEPS_MAX);
        let resolution = match b >> 6 {
            0b00 => StepResolution::Milliseconds100,
            0b01 => StepResolution::Second1,
            0b10 => StepResolution::Second10,
            0b11 => StepResolution::Minute10,
            _ => unreachable!("step_resolution is only 2-bits"),
        };
        Self::new(resolution, steps)
    }
}
impl From<PublishPeriod> for u8 {
    fn from(p: PublishPeriod) -> Self {
        p.packed()
    }
}
impl From<PublishPeriod> for time::Duration {
    fn from(p: PublishPeriod) -> Self {
        p.to_duration()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct PublishRetransmit(pub TransmitInterval);
impl From<u8> for PublishRetransmit {
    fn from(b: u8) -> Self {
        Self(b.into())
    }
}
impl From<PublishRetransmit> for u8 {
    fn from(retransmit: PublishRetransmit) -> Self {
        retransmit.0.into()
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct ModelPublishInfo {
    address: Address,
    app_key_index: AppKeyIndex,
    credential_flag: bool,
    ttl: Option<TTL>, // None means default TTL
    period: PublishPeriod,
    retransmit: PublishRetransmit,
}
