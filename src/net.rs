//Network Layer is BIG Endian

use crate::address::Address::{Unassigned, Unicast};
use crate::address::{Address, UnicastAddress};
use crate::bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::mesh::{SequenceNumber, CTL, IVI, MIC, NID, TTL};
use crate::serializable::{SerializableError, WireSerializable};
use core::convert::TryFrom;

pub struct Payload {
    transport_pdu: [u8; 16], //FIXME: Give me a proper data type
    transport_length: u8,
    net_mic: MIC,
}
impl Payload {
    pub fn size(&self) -> u8 {
        self.transport_length + self.net_mic.byte_size()
    }
}
impl WireSerializable for Payload {
    type Error = SerializableError;
    fn serialize_to<'a>(&self, buf: &'a mut BytesMut<'a>) -> Result<(), SerializableError> {
        if self.transport_length as usize > self.transport_pdu.len() {
            Err(SerializableError::IncorrectParameter)
        } else if buf.remaining_space() < self.size() as usize {
            Err(SerializableError::OutOfSpace)
        } else {
            buf.push_bytes(self.transport_pdu[..self.transport_length as usize].iter());
            match self.net_mic {
                MIC::Big(b) => buf.push_u32_be(b),
                MIC::Small(s) => buf.push_u16_be(s),
            }
            Ok(())
        }
    }

    fn serialize_from<'a>(buf: &'a mut Bytes<'a>) -> Result<Self, SerializableError> {
        unimplemented!("serialize_from for payload depends on MIC length")
    }
}

pub struct Header {
    ivi: IVI,
    nid: NID,
    ctl: CTL,
    ttl: TTL,
    seq: SequenceNumber,
    src: UnicastAddress,
    dst: Address,
}

const PDU_HEADER_SIZE: u8 = 1 + 1 + 3 + 2 + 2;

impl Header {
    pub fn size(&self) -> u8 {
        PDU_HEADER_SIZE
    }
}

impl WireSerializable for Header {
    type Error = SerializableError;
    fn serialize_to<'a>(&self, buf: &'a mut BytesMut) -> Result<(), SerializableError> {
        if buf.remaining_space() < PDU_HEADER_SIZE as usize {
            Err(SerializableError::OutOfSpace)
        } else if let Address::Unassigned = self.dst {
            // Can't have a PDU destination be unassigned
            Err(SerializableError::IncorrectParameter)
        } else {
            buf.push_u8(self.nid.with_flag(self.ivi.into()));
            buf.push_u8(self.ttl.with_flag(self.ctl.into()));
            buf.push_u24_be(self.seq.value());
            buf.push_u16_be(self.src.into());
            buf.push_u16_be(self.dst.into());
            Ok(())
        }
    }

    fn serialize_from<'a>(buf: &'a mut Bytes) -> Result<Self, SerializableError> {
        if buf.remaining_space() < PDU_HEADER_SIZE as usize {
            Err(SerializableError::IncorrectSize)
        } else {
            let dst = Address::from(buf.pop_u16_be());
            let src = UnicastAddress::try_from(buf.pop_u16_be())
                .map_err(|_| SerializableError::BadBytes)?;
            let seq = SequenceNumber::new(buf.pop_u24_be());
            let (ttl, ctl_b) = TTL::new_with_flag(buf.pop_u8());
            let (nid, ivi_b) = NID::new_with_flag(buf.pop_u8());
            Ok(Header {
                ivi: ivi_b.into(),
                nid,
                ctl: ctl_b.into(),
                ttl,
                seq,
                src,
                dst,
            })
        }
    }
}

pub struct PDU {
    header: Header,
    payload: Payload,
}

impl WireSerializable for PDU {
    type Error = SerializableError;
    fn serialize_to<'a>(&self, buf: &'a mut BytesMut<'a>) -> Result<(), SerializableError> {
        if self.header.size() as usize + self.payload.size() as usize > buf.remaining_space() {
            Err(SerializableError::OutOfSpace)
        } else {
            self.header.serialize_to(buf)?;
            self.payload.serialize_to(buf)?;
            Ok(())
        }
    }

    fn serialize_from(buf: &mut Bytes<'_>) -> Result<Self, SerializableError> {
        unimplemented!()
    }
}
