//! Bluetooth Mesh
//! Network Layer is BIG Endian

use crate::address::Address::{Unassigned, Unicast};
use crate::address::{Address, UnicastAddress};
use crate::bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::mesh::{SequenceNumber, CTL, IVI, MIC, NID, TTL};
use crate::serializable::byte::{ByteSerializable, ByteSerializableError};
use core::convert::TryFrom;

pub struct EncryptedTransportPDU {
    transport_pdu: [u8; 16],
    transport_length: u8,
}
impl EncryptedTransportPDU {
    pub fn len(&self) -> usize {
        self.transport_length as usize
    }
    pub fn data(&self) -> &[u8] {
        let l = self.len();
        debug_assert!(
            l <= self.transport_pdu.len(),
            "transport_length is longer than max transport PDU size {} > {}",
            l,
            self.transport_pdu.len()
        );
        &self.transport_pdu[..l]
    }
    pub fn data_mut(&mut self) -> &mut [u8] {
        let l = self.len();
        debug_assert!(
            l <= self.transport_pdu.len(),
            "transport_length is longer than max transport PDU size {} > {}",
            l,
            self.transport_pdu.len()
        );
        &mut self.transport_pdu[..l]
    }
}
impl AsRef<[u8]> for EncryptedTransportPDU {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}
impl AsMut<[u8]> for EncryptedTransportPDU {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}
impl ByteSerializable for EncryptedTransportPDU {
    type Error = ByteSerializableError;

    fn serialize_to(&self, buf: &mut BytesMut) -> Result<(), Self::Error> {
        unimplemented!()
    }

    fn serialize_from(buf: &mut Bytes) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}
pub struct Payload {
    transport_pdu: EncryptedTransportPDU,
    net_mic: MIC,
}

impl Payload {
    pub fn size(&self) -> usize {
        self.transport_pdu.len() + self.net_mic.byte_size()
    }
}
impl ByteSerializable for Payload {
    type Error = ByteSerializableError;
    fn serialize_to(&self, buf: &mut BytesMut) -> Result<(), ByteSerializableError> {
        let m = Self::map_byte_result;
        if self.size() > self.transport_pdu.len() {
            Err(ByteSerializableError::IncorrectParameter)
        } else if buf.remaining_empty_space() < self.size() as usize {
            Err(ByteSerializableError::OutOfSpace)
        } else {
            m(buf.push_bytes_slice(self.transport_pdu.data()))?;
            match self.net_mic {
                MIC::Big(b) => m(buf.push_be(b))?,
                MIC::Small(s) => m(buf.push_be(s))?,
            }
            Ok(())
        }
    }

    fn serialize_from(buf: &mut Bytes) -> Result<Self, ByteSerializableError> {
        unimplemented!("serialize_from for payload depends on MIC length")
    }
}

/// Mesh Network PDU Header
/// Network layer is Big Endian.
/// From Mesh Core v1.0
/// | Field Name    | Bits  | Notes                                                     |
/// |---------------|-------|-----------------------------------------------------------|
/// | IVI           | 1     | Least significant bit of IV Index                         |
/// | NID           | 7     | Value derived from the NetKey used to encrypt this PDU    |
/// | CTL           | 1     | Network Control                                           |
/// | TTL           | 7     | Time To Live                                              |
/// | SEQ           | 24    | Sequence Number                                           |
/// | SRC           | 16    | Source Unicast Address                                    |
/// | DST           | 16    | Destination Address (Unicast, Group or Virtual            |
/// | Transport PDU | 8-128 | Transport PDU (1-16 Bytes)                                |
/// | NetMIC        | 32,64 | Message Integrity check for Payload (4 or 8 bytes)        |
///
/// NetMIC is 32 bit when CTL == 0
/// NetMIC is 64 bit when CTL == 1
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Header {
    ivi: IVI,
    nid: NID,
    ctl: CTL,
    ttl: TTL,
    seq: SequenceNumber,
    src: UnicastAddress,
    dst: Address,
}

const PDU_HEADER_SIZE: usize = 1 + 1 + 3 + 2 + 2;

impl Header {
    pub fn size(&self) -> usize {
        PDU_HEADER_SIZE
    }
    pub fn big_mic(&self) -> bool {
        self.ctl.into()
    }
}

impl ByteSerializable for Header {
    type Error = ByteSerializableError;
    fn serialize_to(&self, buf: &mut BytesMut) -> Result<(), ByteSerializableError> {
        if buf.remaining_empty_space() < PDU_HEADER_SIZE {
            Err(ByteSerializableError::OutOfSpace)
        } else if let Address::Unassigned = self.dst {
            // Can't have a PDU destination be unassigned
            Err(ByteSerializableError::IncorrectParameter)
        } else {
            debug_assert_eq!(buf.length(), 0, "expecting empty buffer");
            buf.push_be(self.nid.with_flag(self.ivi.into()));
            buf.push_be(self.ttl.with_flag(self.ctl.into()));
            buf.push_be(self.seq);
            buf.push_be(self.src);
            buf.push_be(self.dst);
            debug_assert_eq!(
                buf.length(),
                PDU_HEADER_SIZE,
                "buffer should be filled with header"
            );
            Ok(())
        }
    }

    fn serialize_from(buf: &mut Bytes) -> Result<Self, ByteSerializableError> {
        if buf.remaining_empty_space() < PDU_HEADER_SIZE as usize {
            Err(ByteSerializableError::IncorrectSize)
        } else {
            let dst: Address = buf.pop_be().expect("dst address is infallible");
            let src: UnicastAddress = buf.pop_be().ok_or(ByteSerializableError::BadBytes)?;
            let seq: SequenceNumber = buf.pop_be().expect("sequence number is infallible");
            let (ttl, ctl_b) = TTL::new_with_flag(buf.pop_be().unwrap());
            let (nid, ivi_b) = NID::new_with_flag(buf.pop_be().unwrap());
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

/// Mesh Network PDU Structure
pub struct PDU {
    header: Header,
    payload: Payload,
}

impl ByteSerializable for PDU {
    type Error = ByteSerializableError;
    fn serialize_to(&self, buf: &mut BytesMut) -> Result<(), ByteSerializableError> {
        if self.header.size() as usize + self.payload.size() as usize > buf.remaining_empty_space()
        {
            Err(ByteSerializableError::OutOfSpace)
        } else {
            self.header.serialize_to(buf)?;
            self.payload.serialize_to(buf)?;
            Ok(())
        }
    }

    fn serialize_from(buf: &mut Bytes) -> Result<Self, ByteSerializableError> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::super::random::*;
    use super::*;
    use crate::mesh::U24;

    /// Generates a random Network PDU Header. Helpful for testing.
    pub fn random_header() -> Header {
        Header {
            ivi: random_bool().into(),
            nid: NID::from_masked_u8(random_u8()),
            ctl: random_bool().into(),
            ttl: TTL::from_masked_u8(random_u8()),
            seq: SequenceNumber(U24::new_masked(random_u32())),
            src: UnicastAddress::from_mask_u16(random_u16()),
            dst: random_u16().into(),
        }
    }
    fn test_header_size() {}
    /// Message #1 from Mesh Core v1.0 Sample Data
    fn message_1_header() -> Header {
        unimplemented!();
    }
    #[test]
    fn test_random_headers_to_from_bytes() {
        for i in 0..10 {}
    }
}
