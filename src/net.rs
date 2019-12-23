//! Bluetooth Mesh
//! Network Layer is BIG Endian

use crate::address::{Address, UnicastAddress};
use crate::mesh::{SequenceNumber, CTL, IVI, MIC, NID, TTL};
use crate::serializable::bytes::{Buf, BufError, BufMut, Bytes, BytesMut};
use crate::serializable::ByteSerializable;
use core::convert::{TryFrom, TryInto};
use core::fmt;

const TRANSPORT_PDU_MAX_LENGTH: usize = 16;

pub struct EncryptedTransportPDU {
    transport_pdu: [u8; TRANSPORT_PDU_MAX_LENGTH],
    transport_length: u8,
}
impl TryFrom<&[u8]> for EncryptedTransportPDU {
    type Error = BufError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let l = value.len();
        if l > Self::max_len() {
            Err(BufError::OutOfRange(l))
        } else {
            let mut buf: [u8; TRANSPORT_PDU_MAX_LENGTH] = Default::default();
            buf[..l].copy_from_slice(value);
            Ok(EncryptedTransportPDU {
                transport_pdu: buf,
                transport_length: l as u8,
            })
        }
    }
}
impl EncryptedTransportPDU {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.transport_length as usize
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
    #[must_use]
    pub fn data(&self) -> &[u8] {
        let l = self.len();
        debug_assert!(
            l <= Self::max_len(),
            "transport_length is longer than max transport PDU size {} > {}",
            l,
            Self::max_len()
        );
        &self.transport_pdu[..l]
    }
    #[must_use]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let l = self.len();
        debug_assert!(
            l <= Self::max_len(),
            "transport_length is longer than max transport PDU size {} > {}",
            l,
            Self::max_len()
        );
        &mut self.transport_pdu[..l]
    }
    #[must_use]
    pub const fn max_len() -> usize {
        TRANSPORT_PDU_MAX_LENGTH
    }
}
impl AsRef<[u8]> for EncryptedTransportPDU {
    #[must_use]
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}
impl AsMut<[u8]> for EncryptedTransportPDU {
    #[must_use]
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}
impl ByteSerializable for EncryptedTransportPDU {
    fn serialize_to(&self, buf: &mut BytesMut) -> Result<(), BufError> {
        buf.push_bytes_slice(self.data())?;
        Ok(())
    }

    fn serialize_from(buf: &mut Bytes) -> Result<Self, BufError> {
        if buf.len() > Self::max_len() {
            Err(BufError::OutOfRange(buf.len()))
        } else {
            Ok(buf
                .pop_bytes(buf.len())?
                .try_into()
                .expect("slice should be small enough"))
        }
    }
}

pub struct Payload {
    transport_pdu: EncryptedTransportPDU,
    net_mic: MIC,
}

impl Payload {
    #[must_use]
    pub fn size(&self) -> usize {
        self.transport_pdu.len() + self.net_mic.byte_size()
    }
    #[must_use]
    pub const fn max_size() -> usize {
        EncryptedTransportPDU::max_len() + MIC::max_size()
    }
}
impl ByteSerializable for Payload {
    fn serialize_to(&self, buf: &mut BytesMut) -> Result<(), BufError> {
        if self.size() > Self::max_size() {
            Err(BufError::InvalidInput)
        } else if buf.remaining_empty_space() < self.size() {
            Err(BufError::OutOfSpace(self.size()))
        } else {
            buf.push_bytes_slice(self.transport_pdu.data())?;
            match self.net_mic {
                MIC::Big(b) => buf.push_be(b)?,
                MIC::Small(s) => buf.push_be(s)?,
            };
            Ok(())
        }
    }

    fn serialize_from(_buf: &mut Bytes) -> Result<Self, BufError> {
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
/// `NetMIC` is 32 bit when CTL == 0
/// `NetMIC` is 64 bit when CTL == 1
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Header {
    pub ivi: IVI,
    nid: NID,
    ctl: CTL,
    ttl: TTL,
    seq: SequenceNumber,
    src: UnicastAddress,
    dst: Address,
}
const PDU_HEADER_SIZE: usize = 1 + 1 + 3 + 2 + 2;

impl Header {
    #[must_use]
    pub const fn size() -> usize {
        PDU_HEADER_SIZE
    }
    #[must_use]
    pub fn big_mic(&self) -> bool {
        self.ctl.into()
    }
    #[must_use]
    pub fn mic_size(&self) -> usize {
        if self.big_mic() {
            MIC::big_size()
        } else {
            MIC::small_size()
        }
    }
}

impl ByteSerializable for Header {
    fn serialize_to(&self, buf: &mut BytesMut) -> Result<(), BufError> {
        if buf.remaining_empty_space() < PDU_HEADER_SIZE {
            Err(BufError::OutOfSpace(PDU_HEADER_SIZE))
        } else if let Address::Unassigned = self.dst {
            // Can't have a PDU destination be unassigned
            Err(BufError::InvalidInput)
        } else {
            buf.push_be(self.nid.with_flag(self.ivi.into()))?;
            buf.push_be(self.ttl.with_flag(self.ctl.into()))?;
            buf.push_be(self.seq)?;
            buf.push_be(self.src)?;
            buf.push_be(self.dst)?;
            Ok(())
        }
    }

    fn serialize_from(buf: &mut Bytes) -> Result<Self, BufError> {
        if buf.length() < PDU_HEADER_SIZE {
            Err(BufError::InvalidInput)
        } else {
            let dst: Address = buf.pop_be().expect("dst address is infallible");
            let src: UnicastAddress = buf.pop_be().ok_or(BufError::BadBytes(2))?;
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
impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "(ivi:{} nid:{} ttl:{} ctl:{} seq:{} src:{:?} dst:{:?}",
            self.ivi.0, self.nid, self.ttl, self.ctl.0, self.seq, self.src, self.dst
        )
    }
}
const ENCRYPTED_PDU_MAX_SIZE: usize = TRANSPORT_PDU_MAX_LENGTH + PDU_HEADER_SIZE + 8;
pub struct EncryptedNetworkPDU {
    pdu_buffer: [u8; ENCRYPTED_PDU_MAX_SIZE],
    length: u8,
}
impl EncryptedNetworkPDU {
    /// Wrapped a raw bytes that represent an Encrypted Network PDU
    /// See `ENCRYPTED_PDU_MAX_SIZE` for the max size.
    /// # Panics
    /// Panics if `buf.len() > ENCRYPTED_PDU_MAX_SIZE`
    #[must_use]
    pub fn new(buf: &[u8]) -> EncryptedNetworkPDU {
        assert!(buf.len() <= ENCRYPTED_PDU_MAX_SIZE);
        let mut pdu_buf: [u8; ENCRYPTED_PDU_MAX_SIZE] = [0u8; ENCRYPTED_PDU_MAX_SIZE];
        pdu_buf[..buf.len()].copy_from_slice(buf);
        EncryptedNetworkPDU {
            pdu_buffer: pdu_buf,
            length: buf.len() as u8,
        }
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length as usize
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.pdu_buffer[..self.len()]
    }
    #[must_use]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let l = self.len();
        &mut self.pdu_buffer[..l]
    }
}
impl From<&[u8]> for EncryptedNetworkPDU {
    #[must_use]
    fn from(b: &[u8]) -> Self {
        EncryptedNetworkPDU::new(b)
    }
}
impl AsRef<[u8]> for EncryptedNetworkPDU {
    #[must_use]
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}
impl AsMut<[u8]> for EncryptedNetworkPDU {
    #[must_use]
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}
/// Mesh Network PDU Structure
pub struct PDU {
    header: Header,
    payload: Payload,
}
impl PDU {
    #[must_use]
    pub const fn max_size() -> usize {
        Header::size() + Payload::max_size()
    }
}
impl ByteSerializable for PDU {
    fn serialize_to(&self, buf: &mut BytesMut) -> Result<(), BufError> {
        if Header::size() + self.payload.size() > buf.remaining_empty_space() {
            Err(BufError::OutOfSpace(Header::size() + self.payload.size()))
        } else {
            self.header.serialize_to(buf)?;
            self.payload.serialize_to(buf)?;
            Ok(())
        }
    }

    fn serialize_from(buf: &mut Bytes) -> Result<Self, BufError> {
        if buf.length() > Self::max_size() {
            Err(BufError::OutOfRange(buf.length()))
        } else {
            let header = Header::serialize_from(&mut buf.pop_front_bytes(Header::size())?)?;
            let mic = MIC::try_from_bytes_be(buf.pop_bytes(header.mic_size())?)
                .ok_or(BufError::BadBytes(0))?;
            let encrypted_payload = EncryptedTransportPDU::serialize_from(buf)?;
            let payload = Payload {
                transport_pdu: encrypted_payload,
                net_mic: mic,
            };
            Ok(PDU { header, payload })
        }
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
            ivi: rand_bool().into(),
            nid: NID::from_masked_u8(rand_u8()),
            ctl: rand_bool().into(),
            ttl: TTL::from_masked_u8(rand_u8()),
            seq: SequenceNumber(U24::new_masked(rand_u32())),
            src: UnicastAddress::from_mask_u16(rand_u16()),
            dst: rand_u16().into(),
        }
    }
    fn test_header_size() {}
    /// Message #1 from Mesh Core v1.0 Sample Data
    fn message_1_header() -> Header {
        unimplemented!();
    }
    #[test]
    fn test_random_headers_to_from_bytes() {
        for _i in 0..10 {}
    }
}
