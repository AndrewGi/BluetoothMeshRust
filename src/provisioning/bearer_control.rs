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

#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd, PartialEq, Debug)]
pub struct LinkOpen(pub UUID);

impl LinkOpen {
    pub fn new(uuid: UUID) -> LinkOpen {
        LinkOpen(uuid)
    }
    pub fn uuid(&self) -> &UUID {
        &self.0
    }
}
impl Display for LinkOpen {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "LinkOpen({})", self.0)
    }
}
#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd, PartialEq, Debug)]
pub struct LinkAck();
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
}
impl Display for LinkClose {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "LinkClose{}", self.0)
    }
}
#[derive(Clone, Copy, Eq, PartialEq, Debug, Hash)]
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
