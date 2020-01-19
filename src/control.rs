//! Bluetooth Mesh Control Layer.

use crate::lower::{BlockAck, SeqZero, UnsegmentedControlPDU, SEQ_ZERO_MAX};
use crate::serializable::bytes::ToFromBytesEndian;
use core::convert::TryFrom;

/// 7 Bit Control Opcode
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[repr(u8)]
pub enum ControlOpcode {
    Ack = 0x00, // Handled by the lower transport layer.
    FriendPoll = 0x01,
    FriendUpdate = 0x02,
    FriendRequest = 0x03,
    FriendOffer = 0x04,
    FriendClear = 0x05,
    FriendClearConfirm = 0x06,
    FriendSubscriptionListAdd = 0x07,
    FriendSubscriptionListRemove = 0x08,
    FriendSubscriptionListConfirm = 0x09,
    Heartbeat = 0x0A,
}
impl ControlOpcode {
    pub fn new(opcode: u8) -> Option<Self> {
        match opcode {
            0x00 => Some(ControlOpcode::Ack),
            0x01 => Some(ControlOpcode::FriendPoll),
            0x02 => Some(ControlOpcode::FriendUpdate),
            0x03 => Some(ControlOpcode::FriendRequest),
            0x04 => Some(ControlOpcode::FriendOffer),
            0x05 => Some(ControlOpcode::FriendClear),
            0x06 => Some(ControlOpcode::FriendClearConfirm),
            0x07 => Some(ControlOpcode::FriendSubscriptionListAdd),
            0x08 => Some(ControlOpcode::FriendSubscriptionListRemove),
            0x09 => Some(ControlOpcode::FriendSubscriptionListConfirm),
            0x0A => Some(ControlOpcode::Heartbeat),
            _ => None,
        }
    }
}
impl From<ControlOpcode> for u8 {
    fn from(opcode: ControlOpcode) -> Self {
        opcode as u8
    }
}
pub struct ControlPayload<Storage: AsRef<[u8]> + AsMut<[u8]>> {
    opcode: ControlOpcode,
    payload: Storage,
}
pub enum ControlPDU {
    Ack(Ack),
    FriendPoll(FriendPoll),
    FriendUpdate(FriendUpdate),
    FriendRequest(FriendRequest),
    FriendOffer(FriendOffer),
    FriendClear(FriendClear),
    FriendClearConfirm(FriendClearConfirm),
    FriendSubscriptionListAdd(FriendSubscriptionListAdd),
    FriendSubscriptionListRemove(FriendSubscriptionListRemove),
    FriendSubscriptionListConfirm(FriendSubscriptionListConfirm),
    Heartbeat(Heartbeat),
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct ControlPDUError(());
impl ControlPDU {
    pub fn try_unpack(_opcode: ControlOpcode, _buf: &[u8]) -> Result<Self, ControlPDUError> {
        unimplemented!()
    }
    pub fn try_pack(_buf: &mut [u8]) -> Result<(), ControlPDUError> {
        unimplemented!()
    }
}
pub enum ControlMessageError {
    BufferTooSmall,
    BadBytes,
    BadState,
    BadLength,
    BadOpcode,
}
pub trait ControlMessage: Sized {
    const OPCODE: ControlOpcode;
    fn byte_len(&self) -> usize;
    fn unpack(buf: &[u8]) -> Result<Self, ControlMessageError>;
    fn pack(buf: &mut [u8]) -> Result<(), ControlMessageError>;
    fn try_from_pdu(value: &UnsegmentedControlPDU) -> Result<Self, ControlMessageError> {
        if value.opcode() == Self::OPCODE {
            Self::unpack(value.data())
        } else {
            Err(ControlMessageError::BadOpcode)
        }
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Ack {
    pub obo: bool,
    pub seq_zero: SeqZero,
    pub block_ack: BlockAck,
}
impl ControlMessage for Ack {
    const OPCODE: ControlOpcode = ControlOpcode::Ack;

    fn byte_len(&self) -> usize {
        6
    }

    fn unpack(buf: &[u8]) -> Result<Self, ControlMessageError> {
        if buf.len() != 6 {
            Err(ControlMessageError::BadLength)
        } else {
            let seq = u16::from_bytes_le(&buf[..2]).expect("seq_zero is always here");
            let seq_zero = SeqZero::new((seq >> 2) & SEQ_ZERO_MAX);
            let obo = seq & 0x8000 != 0;
            let block_ack =
                BlockAck(u32::from_bytes_le(&buf[2..6]).expect("block_ack is always here"));
            Ok(Self {
                obo,
                seq_zero,
                block_ack,
            })
        }
    }

    fn pack(_buf: &mut [u8]) -> Result<(), ControlMessageError> {
        unimplemented!()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendPoll {}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendUpdate {}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendRequest {}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendOffer {}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendClear {}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendClearConfirm {}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendSubscriptionListAdd {}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendSubscriptionListRemove {}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendSubscriptionListConfirm {}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Heartbeat {}
