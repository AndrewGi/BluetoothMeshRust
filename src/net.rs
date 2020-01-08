//! Bluetooth Mesh
//! Network Layer is BIG Endian

use crate::address::{Address, UnicastAddress, ADDRESS_LEN};
use crate::crypto::key::PrivacyKey;
use crate::crypto::nonce::{NetworkNonce, NetworkNonceParts};
use crate::crypto::MIC;
use crate::lower;
use crate::mesh::{IVIndex, SequenceNumber, CTL, IVI, NID, TTL};
use crate::serializable::bytes::{Buf, BufError, BufMut, Bytes, BytesMut, ToFromBytesEndian};
use crate::serializable::ByteSerializable;
use core::fmt;

const TRANSPORT_PDU_MAX_LEN: usize = 16;

/// Holds the encrypted destination address, transport PDU and MIC.
pub struct EncryptedPayload {
    data: [u8; TRANSPORT_PDU_MAX_LEN + ADDRESS_LEN],
    length: u8,
    mic: MIC,
}

impl EncryptedPayload {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length as usize
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
    #[must_use]
    pub fn data(&self) -> &[u8] {
        let l = self.len();
        &self.data[..l]
    }
    #[must_use]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let l = self.len();
        &mut self.data[..l]
    }
    #[must_use]
    pub fn mic(&self) -> MIC {
        self.mic
    }
    #[must_use]
    pub const fn max_len() -> usize {
        TRANSPORT_PDU_MAX_LEN + ADDRESS_LEN
    }
}
impl AsRef<[u8]> for EncryptedPayload {
    #[must_use]
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}
impl AsMut<[u8]> for EncryptedPayload {
    #[must_use]
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
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
/// | NetMIC        | 32,64 | -Message Integrity check for Payload (4 or 8 bytes)        |
///
/// `NetMIC` is 32 bit when CTL == 0
/// `NetMIC` is 64 bit when CTL == 1
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Header {
    pub ivi: IVI,
    pub nid: NID,
    pub ctl: CTL,
    pub ttl: TTL,
    pub seq: SequenceNumber,
    pub src: UnicastAddress,
    pub dst: Address,
}
// (IVI + NID) (1) + (CTL + TTL) (1) + Seq (3) + Src (2) + Dst (2)
const PDU_HEADER_LEN: usize = 1 + 1 + 3 + 2 + 2;

impl Header {
    #[must_use]
    pub const fn len() -> usize {
        PDU_HEADER_LEN
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
impl From<&Header> for DeobfuscatedHeader {
    #[must_use]
    fn from(h: &Header) -> Self {
        DeobfuscatedHeader::new(h.ctl, h.ttl, h.seq, h.src)
    }
}

impl ByteSerializable for Header {
    fn serialize_to(&self, buf: &mut BytesMut) -> Result<(), BufError> {
        if buf.remaining_empty_space() < PDU_HEADER_LEN {
            Err(BufError::OutOfSpace(PDU_HEADER_LEN))
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
        if buf.length() < PDU_HEADER_LEN {
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
const ENCRYPTED_PDU_MAX_SIZE: usize = TRANSPORT_PDU_MAX_LEN + PDU_HEADER_LEN + 8;
#[derive(Copy, Clone)]
pub struct EncryptedPDU {
    pdu_buffer: [u8; ENCRYPTED_PDU_MAX_SIZE],
    length: u8,
}
impl EncryptedPDU {
    /// Wrapped a raw bytes that represent an Encrypted Network PDU
    /// See `ENCRYPTED_PDU_MAX_SIZE` for the max size.
    /// # Panics
    /// Panics if `buf.len() > ENCRYPTED_PDU_MAX_SIZE`
    #[must_use]
    pub fn new(buf: &[u8]) -> EncryptedPDU {
        assert!(buf.len() <= ENCRYPTED_PDU_MAX_SIZE);
        let mut pdu_buf: [u8; ENCRYPTED_PDU_MAX_SIZE] = [0_u8; ENCRYPTED_PDU_MAX_SIZE];
        pdu_buf[..buf.len()].copy_from_slice(buf);
        EncryptedPDU {
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
impl From<&[u8]> for EncryptedPDU {
    #[must_use]
    fn from(b: &[u8]) -> Self {
        EncryptedPDU::new(b)
    }
}
impl AsRef<[u8]> for EncryptedPDU {
    #[must_use]
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}
impl AsMut<[u8]> for EncryptedPDU {
    #[must_use]
    fn as_mut(&mut self) -> &mut [u8] {
        self.data_mut()
    }
}
/// Mesh Network PDU Structure
#[derive(Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct PDU {
    header: Header,
    payload: lower::PDU,
}
impl PDU {
    #[must_use]
    pub const fn max_len() -> usize {
        Header::len() + lower::PDU::max_len()
    }
}

const OBFUSCATED_LEN: usize = 6;
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct ObfuscatedHeader([u8; OBFUSCATED_LEN]);

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct DeobfuscatedHeader {
    ctl: CTL,
    ttl: TTL,
    seq: SequenceNumber,
    src: UnicastAddress,
}
impl DeobfuscatedHeader {
    pub fn new(ctl: CTL, ttl: TTL, seq: SequenceNumber, src: UnicastAddress) -> Self {
        Self { ctl, ttl, seq, src }
    }
    pub fn ctl(&self) -> CTL {
        self.ctl
    }
    pub fn seq(&self) -> SequenceNumber {
        self.seq
    }
    pub fn src(&self) -> UnicastAddress {
        self.src
    }
    /// Returns un-obfuscated plaintext header packed into bytes.
    pub fn pack(&self) -> [u8; OBFUSCATED_LEN] {
        let seq = self.seq.to_bytes_be();
        let src = self.src.to_bytes_be();
        [
            self.ttl.with_flag(self.ctl.0),
            seq[2],
            seq[1],
            seq[0],
            src[1],
            src[0],
        ]
    }
    pub fn obfuscate(&self, pecb: PECB) -> ObfuscatedHeader {
        let mut out = self.pack();
        pecb.xor(out.as_mut());
        ObfuscatedHeader(out)
    }
    pub fn nonce(&self, iv_index: IVIndex) -> NetworkNonce {
        NetworkNonceParts::new(self.ctl, self.ttl, self.src, self.seq, iv_index).to_nonce()
    }
}
const PECB_LEN: usize = 6;
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct PECB([u8; PECB_LEN]);
impl PECB {
    pub fn new(bytes: [u8; PECB_LEN]) -> Self {
        Self(bytes)
    }
    /// XOR PECB with `bytes` in-place.
    /// # Panics
    /// Panics if `bytes.len() != PECB_LEN` (6)
    pub fn xor(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), PECB_LEN);
        for (b1, b2) in bytes.iter_mut().zip(self.0.as_ref()) {
            *b1 ^= *b2
        }
    }
}
impl AsRef<[u8]> for PECB {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}
const PRIVACY_RANDOM_LEN: usize = 7;
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct PrivacyRandom([u8; PRIVACY_RANDOM_LEN]);
impl PrivacyRandom {
    pub fn new_bytes(bytes: [u8; PRIVACY_RANDOM_LEN]) -> Self {
        Self(bytes)
    }
    pub fn pack_with_iv(&self, iv_index: IVIndex) -> PackedPrivacy {
        let mut out = [0_u8; PACKED_PRIVACY_LEN];
        out[5..9].copy_from_slice(&iv_index.to_bytes_be());
        out[9..].copy_from_slice(&self.0);
        PackedPrivacy::new_bytes(out)
    }
}

/// 0x00_00_00_00_00 (5) + IV_INDEX (4) + PRIVACY_RANDOM (7)
const PACKED_PRIVACY_LEN: usize = 5 + 4 + PRIVACY_RANDOM_LEN;
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct PackedPrivacy([u8; PACKED_PRIVACY_LEN]);

impl PackedPrivacy {
    pub fn new_bytes(bytes: [u8; PACKED_PRIVACY_LEN]) -> Self {
        Self(bytes)
    }
    pub fn encrypt(self, key: PrivacyKey) -> PECB {
        unimplemented!()
    }
}
impl AsRef<[u8]> for PackedPrivacy {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}
impl From<PackedPrivacy> for [u8; PACKED_PRIVACY_LEN] {
    fn from(p: PackedPrivacy) -> Self {
        p.0
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
