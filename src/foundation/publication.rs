use crate::address::{Address, VirtualAddress};
use crate::mesh::{AppKeyIndex, KeyIndex, TransmitInterval, TTL};
use crate::serializable::bytes::ToFromBytesEndian;
use crate::uuid::UUID;
use core::convert::TryInto;
use core::time;

/// 2-bit Step Resoution used for `PublishPeriod`, etc.
#[derive(Copy, Clone, Ord, PartialOrd, Debug, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ModelPublishInfo {
    pub address: Address,
    pub app_key_index: AppKeyIndex,
    pub credential_flag: bool,
    pub ttl: Option<TTL>, // None means default TTL
    pub period: PublishPeriod,
    pub retransmit: PublishRetransmit,
}

impl ModelPublishInfo {
    pub const NON_VIRTUAL_LEN: usize = 7;
    pub const VIRTUAL_LEN: usize = 7 + 14;
    pub fn byte_len(&self) -> usize {
        if self.address.is_full_virtual() {
            Self::VIRTUAL_LEN
        } else {
            Self::NON_VIRTUAL_LEN
        }
    }
    pub fn unpack(buf: &[u8]) -> Option<Self> {
        match buf.len() {
            Self::NON_VIRTUAL_LEN => {
                //Sig NonVirtual
                let address = Address::from_bytes_le(&buf[..2])?;
                let index = u16::from_bytes_le(&buf[2..4])?;
                let credential_flag = index & (1 << 12) != 0;
                let publish_ttl = if buf[4] == 0xFF {
                    None
                } else {
                    if buf[4] & 0x80 != 0 {
                        return None;
                    }
                    Some(TTL::from_masked_u8(buf[4]))
                };
                Some(Self {
                    address,
                    app_key_index: AppKeyIndex(KeyIndex::new_masked(index)),
                    credential_flag,
                    ttl: publish_ttl,
                    period: PublishPeriod::unpack(buf[5]),
                    retransmit: PublishRetransmit::from(buf[6]),
                })
            }
            Self::VIRTUAL_LEN => {
                let uuid = UUID((&buf[..16]).try_into().ok()?);
                let index = u16::from_bytes_le(&buf[16..18])?;
                let credential_flag = index & (1 << 12) != 0;
                let publish_ttl = if buf[18] == 0xFF {
                    None
                } else {
                    if buf[0] & 0x80 != 0 {
                        return None;
                    }
                    Some(TTL::from_masked_u8(buf[18]))
                };
                Some(Self {
                    address: Address::Virtual(VirtualAddress::from(&uuid)),
                    app_key_index: AppKeyIndex(KeyIndex::new_masked(index)),
                    credential_flag,
                    ttl: publish_ttl,
                    period: PublishPeriod::unpack(buf[19]),
                    retransmit: PublishRetransmit::from(buf[20]),
                })
            }
            _ => None,
        }
    }
    pub fn pack_into(&self, buf: &mut [u8]) {
        assert!(
            buf.len() >= self.byte_len(),
            "not enough room for publication"
        );
        let address = u16::from(&self.address);
        let _pos = match &self.address {
            Address::Virtual(va) => {
                buf[..16].copy_from_slice(va.uuid().as_ref());
                16
            }
            _ => {
                buf[..2].copy_from_slice(&address.to_le_bytes());
                2
            }
        };
        unimplemented!()
    }
}
