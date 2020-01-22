use crate::provisioning::generic::GPCF;
use crate::uuid::UUID;
use core::fmt::{Display, Error, Formatter};

/// Bearer Control Opcodes (8-bits).
/// 0x03-0xFF is RFU
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Ord, PartialOrd)]
#[repr(u8)]
pub enum Opcode {
    LinkOpen = 0x00,
    LinkAck = 0x01,
    LinkClose = 0x02,
}
impl Opcode {
    pub fn with_gpcf(self, gpcf: GPCF) -> u8 {
        gpcf.pack_with(self.into())
    }
    pub fn from_with_gpcf(value: u8) -> (Option<Opcode>, GPCF) {
        (
            match value >> 2 {
                0x00 => Some(Opcode::LinkOpen),
                0x01 => Some(Opcode::LinkAck),
                0x02 => Some(Opcode::LinkClose),
                _ => None,
            },
            GPCF::from_masked_u2(value),
        )
    }
}
impl From<Opcode> for u8 {
    fn from(opcode: Opcode) -> Self {
        opcode as u8
    }
}
#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd, PartialEq, Debug)]
pub struct LinkOpen(pub UUID);

impl LinkOpen {
    pub fn new(uuid: UUID) -> LinkOpen {
        LinkOpen(uuid)
    }
    pub fn uuid(&self) -> &UUID {
        &self.0
    }
    pub const fn byte_len() -> usize {
        16
    }
}
impl Display for LinkOpen {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "LinkOpen({})", self.0)
    }
}
#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd, PartialEq, Debug)]
pub struct LinkAck();
impl LinkAck {
    pub const fn byte_len() -> usize {
        0
    }
}
impl Display for LinkAck {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str("LinkAck")
    }
}
#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd, PartialEq, Debug)]
pub enum CloseReason {
    Success = 0x00,
    Timeout = 0x01,
    Fail = 0x02,
}
impl Display for CloseReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(match self {
            CloseReason::Success => "Success",
            CloseReason::Timeout => "Timeout",
            CloseReason::Fail => "Fail",
        })
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd, PartialEq, Debug)]
pub struct LinkClose(CloseReason);
impl LinkClose {
    pub fn new(reason: CloseReason) -> LinkClose {
        Self(reason)
    }
    pub const fn byte_len() -> usize {
        1
    }
}
impl Display for LinkClose {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "LinkClose({})", self.0)
    }
}
pub enum BearerControlError {}
#[derive(Clone, Copy, Eq, PartialEq, Debug, Hash, Ord, PartialOrd)]
pub enum PDU {
    LinkOpen(LinkOpen),
    LinkAck(LinkAck),
    LinkClose(LinkClose),
}
impl Display for PDU {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        match self {
            PDU::LinkOpen(o) => o.fmt(f),
            PDU::LinkAck(a) => a.fmt(f),
            PDU::LinkClose(c) => c.fmt(f),
        }
    }
}

impl PDU {
    pub fn opcode(&self) -> Opcode {
        match self {
            PDU::LinkOpen(_) => Opcode::LinkOpen,
            PDU::LinkAck(_) => Opcode::LinkAck,
            PDU::LinkClose(_) => Opcode::LinkClose,
        }
    }
}
