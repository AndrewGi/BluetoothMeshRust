use crate::foundation::publication::PublishPeriod;
use crate::foundation::state::AttentionTimer;
use crate::mesh::{ElementCount, ElementIndex};
use core::convert::TryFrom;

#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
#[repr(u8)]
pub enum Opcode {
    Invite = 0x00,
    Capabilities = 0x01,
    Start = 0x02,
    PublicKey = 0x03,
    InputComplete = 0x04,
    Confirm = 0x05,
    Random = 0x06,
    Data = 0x07,
    Complete = 0x08,
    Failed = 0x09,
}
impl From<Opcode> for u8 {
    fn from(opcode: Opcode) -> Self {
        opcode as u8
    }
}
impl TryFrom<u8> for Opcode {
    type Error = ProtocolPDUError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Opcode::Invite),
            0x01 => Ok(Opcode::Capabilities),
            0x02 => Ok(Opcode::Start),
            0x03 => Ok(Opcode::PublicKey),
            0x04 => Ok(Opcode::InputComplete),
            0x05 => Ok(Opcode::Confirm),
            0x06 => Ok(Opcode::Random),
            0x07 => Ok(Opcode::Data),
            0x08 => Ok(Opcode::Complete),
            0x09 => Ok(Opcode::Failed),
            _ => Err(ProtocolPDUError::BadOpcode),
        }
    }
}
pub enum ProtocolPDUError {
    BadOpcode,
    BadBytes,
}

pub struct Invite(pub AttentionTimer);
pub enum AlgorithmsFlags {
    FIPSP256 = 0b1,
}
pub struct Algorithms(pub u16);
pub enum PublicKeyType {}
pub enum StaticOOBType {}
#[repr(u8)]
pub enum OutputOOBAction {
    Blink = 0x0,
    Beep = 0x1,
    Vibrate = 0x2,
    OutputNumeric = 0x3,
    OutputAlphanumeric = 0x4,
}

pub struct OOBSize(u8);
impl TryFrom<u8> for OOBSize {
    type Error = ProtocolPDUError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x1..=0x08 => Ok(OOBSize(value)),
            _ => Err(ProtocolPDUError::BadBytes),
        }
    }
}
impl From<OOBSize> for u8 {
    fn from(size: OOBSize) -> Self {
        size.0
    }
}
#[repr(u8)]
pub enum InputOOBAction {
    Push = 0x0,
    Twist = 0x1,
    InputNumber = 0x2,
    InputAlphanumeric = 0x3,
}
pub struct OutputOOBSize(pub u8);
pub struct Capabilities {
    num_elements: ElementCount,
    algorithms: Algorithms,
    pub_key_type: PublishPeriod,
}
