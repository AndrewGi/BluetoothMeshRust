use crate::provisioning::generic::GPCF;
use crate::uuid::UUID;
use btle::{ConversionError, PackError};
use core::convert::TryFrom;
use core::fmt::{Display, Error, Formatter};
use std::convert::TryInto;

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
impl TryFrom<u8> for Opcode {
    type Error = ConversionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Opcode::LinkOpen),
            0x01 => Ok(Opcode::LinkAck),
            0x02 => Ok(Opcode::LinkClose),
            _ => Err(ConversionError(())),
        }
    }
}
#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd, PartialEq, Debug)]
pub struct LinkOpen(pub UUID);

impl LinkOpen {
    pub const BYTE_LEN: usize = 16;
    pub fn new(uuid: UUID) -> LinkOpen {
        LinkOpen(uuid)
    }
    pub fn uuid(&self) -> &UUID {
        &self.0
    }
    pub const fn byte_len() -> usize {
        16
    }
    pub fn pack_into(&self, buf: &mut [u8]) -> Result<(), PackError> {
        PackError::expect_length(16, buf)?;
        buf.copy_from_slice(self.0.as_ref());
        Ok(())
    }
    pub fn unpack_from(buf: &[u8]) -> Result<LinkOpen, PackError> {
        PackError::expect_length(Self::BYTE_LEN, buf)?;
        Ok(LinkOpen(buf.try_into().expect("length checked above")))
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
    pub const BYTE_LEN: usize = 0;
    pub const fn byte_len() -> usize {
        0
    }
    pub fn pack_into(self, buf: &mut [u8]) -> Result<(), PackError> {
        PackError::expect_length(Self::BYTE_LEN, buf)?;
        Ok(())
    }
    pub fn unpack_from(buf: &[u8]) -> Result<LinkAck, PackError> {
        PackError::expect_length(Self::BYTE_LEN, buf)?;
        Ok(LinkAck())
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
impl From<CloseReason> for u8 {
    fn from(r: CloseReason) -> Self {
        r as u8
    }
}
impl TryFrom<u8> for CloseReason {
    type Error = ConversionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(CloseReason::Success),
            0x01 => Ok(CloseReason::Timeout),
            0x02 => Ok(CloseReason::Fail),
            _ => Err(ConversionError(())),
        }
    }
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
pub struct LinkClose(pub CloseReason);
impl LinkClose {
    pub const BYTE_LEN: usize = 1;
    pub fn new(reason: CloseReason) -> LinkClose {
        Self(reason)
    }
    pub const fn byte_len() -> usize {
        1
    }
    pub fn pack_into(self, buf: &mut [u8]) -> Result<(), PackError> {
        PackError::expect_length(Self::BYTE_LEN, buf)?;
        buf[0] = self.0.into();
        Ok(())
    }
    pub fn unpack_from(buf: &[u8]) -> Result<LinkClose, PackError> {
        PackError::expect_length(Self::BYTE_LEN, buf)?;
        Ok(LinkClose(
            buf[0].try_into().map_err(|_| PackError::bad_index(0))?,
        ))
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
    pub fn byte_len(&self) -> usize {
        match self {
            PDU::LinkOpen(_) => LinkOpen::BYTE_LEN + 1,
            PDU::LinkAck(_) => LinkAck::BYTE_LEN + 1,
            PDU::LinkClose(_) => LinkClose::BYTE_LEN + 1,
        }
    }
    pub fn pack_into(&self, buf: &mut [u8]) -> Result<(), PackError> {
        let opcode = match self {
            PDU::LinkOpen(o) => {
                o.pack_into(&mut buf[1..])?;
                Opcode::LinkOpen
            }
            PDU::LinkAck(a) => {
                a.pack_into(&mut buf[1..])?;
                Opcode::LinkAck
            }
            PDU::LinkClose(c) => {
                c.pack_into(&mut buf[1..])?;
                Opcode::LinkClose
            }
        };
        buf[0] = opcode.into();
        Ok(())
    }
    pub fn unpack_from(buf: &[u8]) -> Result<Self, PackError> {
        PackError::atleast_length(1, buf)?;
        match Opcode::try_from(buf[0]).map_err(|_| PackError::BadOpcode)? {
            Opcode::LinkOpen => Ok(PDU::LinkOpen(LinkOpen::unpack_from(&buf[1..])?)),
            Opcode::LinkAck => Ok(PDU::LinkAck(LinkAck::unpack_from(&buf[1..])?)),
            Opcode::LinkClose => Ok(PDU::LinkClose(LinkClose::unpack_from(&buf[1..])?)),
        }
    }
}
