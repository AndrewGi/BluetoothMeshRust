//! Bluetooth Mesh Control Layer.

use crate::bytes::ToFromBytesEndian;
use crate::friend;
use crate::lower::{BlockAck, SeqZero, UnsegmentedControlPDU, SEQ_ZERO_MAX};
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};

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
pub struct ControlPayload<Storage: AsRef<[u8]>> {
    pub opcode: ControlOpcode,
    pub payload: Storage,
}
impl<Storage: AsRef<[u8]> + Clone> Clone for ControlPayload<Storage> {
    fn clone(&self) -> Self {
        ControlPayload {
            opcode: self.opcode,
            payload: self.payload.clone(),
        }
    }
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
impl ControlPDU {
    pub fn try_unpack(opcode: ControlOpcode, payload: &[u8]) -> Result<Self, ControlMessageError> {
        (&ControlPayload { opcode, payload }).try_into()
    }
    pub fn len(&self) -> usize {
        match self {
            ControlPDU::Ack(pdu) => pdu.byte_len(),
            ControlPDU::FriendPoll(pdu) => pdu.byte_len(),
            ControlPDU::FriendUpdate(pdu) => pdu.byte_len(),
            ControlPDU::FriendRequest(pdu) => pdu.byte_len(),
            ControlPDU::FriendOffer(pdu) => pdu.byte_len(),
            ControlPDU::FriendClear(pdu) => pdu.byte_len(),
            ControlPDU::FriendClearConfirm(pdu) => pdu.byte_len(),
            ControlPDU::FriendSubscriptionListAdd(pdu) => pdu.byte_len(),
            ControlPDU::FriendSubscriptionListRemove(pdu) => pdu.byte_len(),
            ControlPDU::FriendSubscriptionListConfirm(pdu) => pdu.byte_len(),
            ControlPDU::Heartbeat(pdu) => pdu.byte_len(),
        }
    }
    pub fn opcode(&self) -> ControlOpcode {
        match self {
            ControlPDU::Ack(_) => Ack::OPCODE,
            ControlPDU::FriendPoll(_) => FriendPoll::OPCODE,
            ControlPDU::FriendUpdate(_) => FriendUpdate::OPCODE,
            ControlPDU::FriendRequest(_) => FriendRequest::OPCODE,
            ControlPDU::FriendOffer(_) => FriendOffer::OPCODE,
            ControlPDU::FriendClear(_) => FriendClear::OPCODE,
            ControlPDU::FriendClearConfirm(_) => FriendClearConfirm::OPCODE,
            ControlPDU::FriendSubscriptionListAdd(_) => FriendSubscriptionListAdd::OPCODE,
            ControlPDU::FriendSubscriptionListRemove(_) => FriendSubscriptionListRemove::OPCODE,
            ControlPDU::FriendSubscriptionListConfirm(_) => FriendSubscriptionListConfirm::OPCODE,
            ControlPDU::Heartbeat(_) => Heartbeat::OPCODE,
        }
    }
    pub fn try_pack<Storage: AsMut<[u8]> + AsRef<[u8]>>(
        &self,
        payload: &mut ControlPayload<Storage>,
    ) -> Result<(), ControlMessageError> {
        match self {
            ControlPDU::Ack(pdu) => pdu.try_pack(payload),
            ControlPDU::FriendPoll(pdu) => pdu.try_pack(payload),
            ControlPDU::FriendUpdate(pdu) => pdu.try_pack(payload),
            ControlPDU::FriendRequest(pdu) => pdu.try_pack(payload),
            ControlPDU::FriendOffer(pdu) => pdu.try_pack(payload),
            ControlPDU::FriendClear(pdu) => pdu.try_pack(payload),
            ControlPDU::FriendClearConfirm(pdu) => pdu.try_pack(payload),
            ControlPDU::FriendSubscriptionListAdd(pdu) => pdu.try_pack(payload),
            ControlPDU::FriendSubscriptionListRemove(pdu) => pdu.try_pack(payload),
            ControlPDU::FriendSubscriptionListConfirm(pdu) => pdu.try_pack(payload),
            ControlPDU::Heartbeat(pdu) => pdu.try_pack(payload),
        }
    }
    pub fn to_vec_payload(&self) -> Result<ControlPayload<Vec<u8>>, ControlMessageError> {
        let mut out = ControlPayload {
            opcode: ControlOpcode::Ack,
            payload: Vec::with_capacity(self.len()),
        };
        out.payload.resize_with(self.len(), u8::default);
        self.try_pack(&mut out)?;
        Ok(out)
    }
}
impl<Storage: AsRef<[u8]>> TryFrom<&ControlPayload<Storage>> for ControlPDU {
    type Error = ControlMessageError;

    fn try_from(value: &ControlPayload<Storage>) -> Result<Self, Self::Error> {
        let buf = value.payload.as_ref();
        Ok(match value.opcode {
            ControlOpcode::Ack => ControlPDU::Ack(Ack::unpack(buf)?),
            ControlOpcode::FriendPoll => ControlPDU::FriendPoll(FriendPoll::unpack(buf)?),
            ControlOpcode::FriendUpdate => ControlPDU::FriendUpdate(FriendUpdate::unpack(buf)?),
            ControlOpcode::FriendRequest => ControlPDU::FriendRequest(FriendRequest::unpack(buf)?),
            ControlOpcode::FriendOffer => ControlPDU::FriendOffer(FriendOffer::unpack(buf)?),
            ControlOpcode::FriendClear => ControlPDU::FriendClear(FriendClear::unpack(buf)?),
            ControlOpcode::FriendClearConfirm => {
                ControlPDU::FriendClearConfirm(FriendClearConfirm::unpack(buf)?)
            }
            ControlOpcode::FriendSubscriptionListAdd => {
                ControlPDU::FriendSubscriptionListAdd(FriendSubscriptionListAdd::unpack(buf)?)
            }
            ControlOpcode::FriendSubscriptionListRemove => {
                ControlPDU::FriendSubscriptionListRemove(FriendSubscriptionListRemove::unpack(buf)?)
            }
            ControlOpcode::FriendSubscriptionListConfirm => {
                ControlPDU::FriendSubscriptionListConfirm(FriendSubscriptionListConfirm::unpack(
                    buf,
                )?)
            }
            ControlOpcode::Heartbeat => ControlPDU::Heartbeat(Heartbeat::unpack(buf)?),
        })
    }
}
impl TryFrom<&UnsegmentedControlPDU> for ControlPDU {
    type Error = ControlMessageError;

    fn try_from(value: &UnsegmentedControlPDU) -> Result<Self, Self::Error> {
        (&ControlPayload {
            opcode: value.opcode(),
            payload: value.data(),
        })
            .try_into()
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
    fn try_pack<Storage: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        payload: &mut ControlPayload<Storage>,
    ) -> Result<(), ControlMessageError> {
        Self::pack(payload.payload.as_mut())?;
        payload.opcode = Self::OPCODE;
        Ok(())
    }
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
pub struct FriendPoll(friend::FriendPoll);
impl ControlMessage for FriendPoll {
    const OPCODE: ControlOpcode = ControlOpcode::FriendPoll;

    fn byte_len(&self) -> usize {
        unimplemented!()
    }

    fn unpack(buf: &[u8]) -> Result<Self, ControlMessageError> {
        unimplemented!()
    }

    fn pack(buf: &mut [u8]) -> Result<(), ControlMessageError> {
        unimplemented!()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendUpdate {}
impl ControlMessage for FriendUpdate {
    const OPCODE: ControlOpcode = ControlOpcode::FriendUpdate;

    fn byte_len(&self) -> usize {
        unimplemented!()
    }

    fn unpack(buf: &[u8]) -> Result<Self, ControlMessageError> {
        unimplemented!()
    }

    fn pack(buf: &mut [u8]) -> Result<(), ControlMessageError> {
        unimplemented!()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendRequest {}
impl ControlMessage for FriendRequest {
    const OPCODE: ControlOpcode = ControlOpcode::FriendRequest;

    fn byte_len(&self) -> usize {
        unimplemented!()
    }

    fn unpack(buf: &[u8]) -> Result<Self, ControlMessageError> {
        unimplemented!()
    }

    fn pack(buf: &mut [u8]) -> Result<(), ControlMessageError> {
        unimplemented!()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendOffer {}
impl ControlMessage for FriendOffer {
    const OPCODE: ControlOpcode = ControlOpcode::FriendOffer;

    fn byte_len(&self) -> usize {
        unimplemented!()
    }

    fn unpack(buf: &[u8]) -> Result<Self, ControlMessageError> {
        unimplemented!()
    }

    fn pack(buf: &mut [u8]) -> Result<(), ControlMessageError> {
        unimplemented!()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendClear {}
impl ControlMessage for FriendClear {
    const OPCODE: ControlOpcode = ControlOpcode::FriendClear;

    fn byte_len(&self) -> usize {
        unimplemented!()
    }

    fn unpack(buf: &[u8]) -> Result<Self, ControlMessageError> {
        unimplemented!()
    }

    fn pack(buf: &mut [u8]) -> Result<(), ControlMessageError> {
        unimplemented!()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendClearConfirm {}
impl ControlMessage for FriendClearConfirm {
    const OPCODE: ControlOpcode = ControlOpcode::FriendClearConfirm;

    fn byte_len(&self) -> usize {
        unimplemented!()
    }

    fn unpack(buf: &[u8]) -> Result<Self, ControlMessageError> {
        unimplemented!()
    }

    fn pack(buf: &mut [u8]) -> Result<(), ControlMessageError> {
        unimplemented!()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendSubscriptionListAdd {}
impl ControlMessage for FriendSubscriptionListAdd {
    const OPCODE: ControlOpcode = ControlOpcode::FriendSubscriptionListAdd;

    fn byte_len(&self) -> usize {
        unimplemented!()
    }

    fn unpack(buf: &[u8]) -> Result<Self, ControlMessageError> {
        unimplemented!()
    }

    fn pack(buf: &mut [u8]) -> Result<(), ControlMessageError> {
        unimplemented!()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendSubscriptionListRemove {}
impl ControlMessage for FriendSubscriptionListRemove {
    const OPCODE: ControlOpcode = ControlOpcode::FriendSubscriptionListRemove;

    fn byte_len(&self) -> usize {
        unimplemented!()
    }

    fn unpack(buf: &[u8]) -> Result<Self, ControlMessageError> {
        unimplemented!()
    }

    fn pack(buf: &mut [u8]) -> Result<(), ControlMessageError> {
        unimplemented!()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct FriendSubscriptionListConfirm {}

impl ControlMessage for FriendSubscriptionListConfirm {
    const OPCODE: ControlOpcode = ControlOpcode::FriendSubscriptionListConfirm;

    fn byte_len(&self) -> usize {
        unimplemented!()
    }

    fn unpack(buf: &[u8]) -> Result<Self, ControlMessageError> {
        unimplemented!()
    }

    fn pack(buf: &mut [u8]) -> Result<(), ControlMessageError> {
        unimplemented!()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Heartbeat {}

impl ControlMessage for Heartbeat {
    const OPCODE: ControlOpcode = ControlOpcode::Heartbeat;

    fn byte_len(&self) -> usize {
        unimplemented!()
    }

    fn unpack(buf: &[u8]) -> Result<Self, ControlMessageError> {
        unimplemented!()
    }

    fn pack(buf: &mut [u8]) -> Result<(), ControlMessageError> {
        unimplemented!()
    }
}
