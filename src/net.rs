//! Bluetooth Mesh
//! Network Layer is BIG Endian

use crate::address::{Address, UnicastAddress, ADDRESS_LEN};
use crate::crypto::aes::AESCipher;
use crate::crypto::key::PrivacyKey;
use crate::crypto::materials::NetworkKeys;
use crate::crypto::nonce::{NetworkNonce, NetworkNonceParts};
use crate::crypto::MIC;
use crate::lower;
use crate::mesh::{IVIndex, SequenceNumber, CTL, IVI, NID, TTL};
use crate::serializable::bytes::{Buf, BufError, BufMut, Bytes, BytesMut, ToFromBytesEndian};
use crate::serializable::ByteSerializable;
use core::convert::TryInto;
use core::fmt;

pub struct DecryptedData {
    dst: Address,
    transport_buf: [u8; TRANSPORT_PDU_MAX_LEN],
    transport_len: usize,
    mic: MIC,
}
impl DecryptedData {
    pub fn dst(&self) -> Address {
        self.dst
    }
    pub fn transport_pdu(&self) -> &[u8] {
        &self.transport_buf[..self.transport_len]
    }
    pub fn as_lower_pdu(&self, ctl: CTL) -> Option<lower::PDU> {
        lower::PDU::unpack_from(self.transport_pdu(), ctl)
    }
}

pub enum NetworkDataError {
    InvalidMIC,
    BadIVI,
    BadTransportPDU,
    BadSrc,
    BadDst,
    DifferentNID,
}

const TRANSPORT_PDU_MIN_LEN: usize = 1;
const TRANSPORT_PDU_MAX_LEN: usize = 16;

/// Holds the encrypted destination address, transport PDU and MIC.
pub struct EncryptedData<'a> {
    data: &'a [u8],
    big_mic: bool,
}

const ENCRYPTED_DATA_MIN_LEN: usize = ADDRESS_LEN + MIC::small_size();
const ENCRYPTED_DATA_MAX_LEN: usize = ENCRYPTED_DATA_MIN_LEN + TRANSPORT_PDU_MAX_LEN;
impl EncryptedData<'_> {
    /// # Panics
    /// Panics if `encrypted_data.len() <= ENCRYPTED_DATA_MIN_LEN`
    /// or `encrypted_data.len() > ENCRYPTED_DATA_MAX_LEN`
    pub fn new(encrypted_data: &[u8], big_mic: bool) -> EncryptedData<'_> {
        assert!(encrypted_data.len() > ENCRYPTED_DATA_MIN_LEN);
        assert!(encrypted_data.len() <= ENCRYPTED_DATA_MAX_LEN);
        EncryptedData {
            data: encrypted_data,
            big_mic,
        }
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// encrypted DST and TransportPDU excluding MIC
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len() - self.mic_size()]
    }
    #[must_use]
    pub fn data_len(&self) -> usize {
        self.len() - self.mic_size()
    }
    pub fn entire_data(&self) -> &[u8] {
        &self.data[..]
    }
    pub fn mic_size(&self) -> usize {
        if self.big_mic {
            MIC::big_size()
        } else {
            MIC::small_size()
        }
    }
    #[must_use]
    pub fn mic(&self) -> MIC {
        MIC::try_from_bytes_be(&self.data[self.len() - self.mic_size()..])
            .expect("pdu should always have MIC")
    }
    #[must_use]
    pub const fn max_len() -> usize {
        TRANSPORT_PDU_MAX_LEN + ADDRESS_LEN + MIC::big_size()
    }
    pub fn try_decrypt(
        &self,
        network_keys: &NetworkKeys,
        nonce: &NetworkNonce,
    ) -> Option<DecryptedData> {
        let mut buf = [0_u8; ENCRYPTED_DATA_MAX_LEN];
        let mic = self.mic();
        buf[..self.data_len()].copy_from_slice(self.data());
        AESCipher::new(network_keys.encryption_key().key())
            .ccm_decrypt(nonce.as_ref(), &[], &mut buf[..], mic)
            .ok()?;
        let mut transport_buf = [0_u8; TRANSPORT_PDU_MAX_LEN];
        let transport_len = self.data_len() - ADDRESS_LEN;
        transport_buf[..transport_len]
            .copy_from_slice(&buf[ADDRESS_LEN..ADDRESS_LEN + transport_len]);
        Some(DecryptedData {
            dst: Address::from_bytes_be(&buf[..ADDRESS_LEN]).expect("dst address can be any u16"),
            transport_buf,
            transport_len,
            mic,
        })
    }
}
impl AsRef<[u8]> for EncryptedData<'_> {
    #[must_use]
    fn as_ref(&self) -> &[u8] {
        self.entire_data()
    }
}

/// ## Mesh Network PDU
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
/// | NetMIC        | 32,64 | -Message Integrity check for Payload (4 or 8 bytes)       |
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
    #[must_use]
    pub fn obfuscate(&self, pecb: PECB) -> ObfuscatedHeader {
        DeobfuscatedHeader::from(self).obfuscate(pecb)
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
const MIN_ENCRYPTED_PDU_LEN: usize = PDU_HEADER_LEN + MIC::small_size();
const MAX_ENCRYPTED_PDU_LEN: usize = ENCRYPTED_PDU_MAX_SIZE;
impl EncryptedPDU {
    /// Wrapped a raw bytes that represent an Encrypted Network PDU
    /// See `ENCRYPTED_PDU_MAX_SIZE` for the max size.
    /// Returns `None` if `buf.len() < MIN_ENCRYPTED_PDU_LEN`
    /// or `buf.len() > MAX_ENCRYPTED_PDU_LEN`.
    #[must_use]
    pub fn new(buf: &[u8]) -> Option<EncryptedPDU> {
        if buf.len() < MIN_ENCRYPTED_PDU_LEN || buf.len() > MAX_ENCRYPTED_PDU_LEN {
            return None;
        }
        let mut pdu_buf: [u8; ENCRYPTED_PDU_MAX_SIZE] = [0_u8; ENCRYPTED_PDU_MAX_SIZE];
        pdu_buf[..buf.len()].copy_from_slice(buf);
        Some(EncryptedPDU {
            pdu_buffer: pdu_buf,
            length: buf.len() as u8,
        })
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
    #[must_use]
    pub fn nid(&self) -> NID {
        NID::from_masked_u8(self.pdu_buffer[0])
    }
    #[must_use]
    pub fn ivi(&self) -> IVI {
        IVI(self.pdu_buffer[0] & 0x80 != 0)
    }
    #[must_use]
    pub fn try_decrypt(
        &self,
        keys: &NetworkKeys,
        iv_index: IVIndex,
    ) -> Result<PDU, NetworkDataError> {
        if keys.nid() != self.nid() {
            return Err(NetworkDataError::InvalidMIC);
        }
        let iv_index = iv_index
            .matching_ivi(self.ivi())
            .ok_or(NetworkDataError::BadIVI)?;
        let pecb = PrivacyRandom::from(self)
            .pack_with_iv(iv_index)
            .encrypt_with(keys.privacy_key());
        let deobfuscated = self
            .header()
            .deobfuscate(pecb)
            .ok_or(NetworkDataError::BadSrc)?;
        let nonce = deobfuscated.nonce(iv_index);
        let private_header = deobfuscated.private_header(self.ivi(), self.nid());
        let encrypted_data = self.encrypted_data(private_header.ctl());
        let decrypted_data = encrypted_data
            .try_decrypt(keys, &nonce)
            .ok_or(NetworkDataError::InvalidMIC)?;
        if decrypted_data.dst() == Address::Unassigned {
            return Err(NetworkDataError::BadDst);
        }
        let header = private_header.create_header(decrypted_data.dst);
        let payload = decrypted_data
            .as_lower_pdu(header.ctl)
            .ok_or(NetworkDataError::BadTransportPDU)?;
        Ok(PDU::new(&header, &payload))
    }
    #[must_use]
    pub fn header(&self) -> ObfuscatedHeader {
        ObfuscatedHeader(
            self.pdu_buffer[1..1 + OBFUSCATED_LEN]
                .try_into()
                .expect("obfuscated header should always exist"),
        )
    }
    pub fn encrypted_data(&self, ctl: CTL) -> EncryptedData {
        EncryptedData::new(&self.pdu_buffer[OBFUSCATED_LEN..], ctl.0)
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
    pub fn new(header: &Header, payload: &lower::PDU) -> PDU {
        PDU {
            header: *header,
            payload: *payload,
        }
    }
    #[must_use]
    pub const fn max_len() -> usize {
        Header::len() + lower::PDU::max_len()
    }
    pub fn payload(&self) -> &lower::PDU {
        &self.payload
    }
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn encrypt(&self, keys: &NetworkKeys) -> EncryptedPDU {
        let header = self.header();
        unimplemented!()
    }
}

const OBFUSCATED_LEN: usize = 6;
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct ObfuscatedHeader([u8; OBFUSCATED_LEN]);
impl ObfuscatedHeader {
    /// Will return `None` if `src` is not a `UnicastAddress`
    pub fn deobfuscate(mut self, pecb: PECB) -> Option<DeobfuscatedHeader> {
        pecb.xor(&mut self.0);
        DeobfuscatedHeader::unpack(&self.0)
    }
    /// Packets the Obfuscated Header into the byte buffer.
    /// # Panics
    /// Panics if `buffer.len() < OBFUSCATED_LEN`.
    pub fn pack_into(&self, buffer: &mut [u8]) {
        assert!(buffer.len() >= OBFUSCATED_LEN);
        buffer[..OBFUSCATED_LEN].copy_from_slice(&self.0[..]);
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct PrivateHeader<'a> {
    ivi: IVI,
    nid: NID,
    deobfuscated: &'a DeobfuscatedHeader,
}
impl<'a> PrivateHeader<'a> {
    pub fn new(ivi: IVI, nid: NID, deobfuscated_header: &'a DeobfuscatedHeader) -> PrivateHeader {
        PrivateHeader {
            ivi,
            nid,
            deobfuscated: &deobfuscated_header,
        }
    }
    pub fn deobfuscated(&self) -> &'a DeobfuscatedHeader {
        self.deobfuscated
    }
    pub fn ivi(&self) -> IVI {
        self.ivi
    }
    pub fn nid(&self) -> NID {
        self.nid
    }
    pub fn src(&self) -> UnicastAddress {
        self.deobfuscated.src
    }
    pub fn seq(&self) -> SequenceNumber {
        self.deobfuscated.seq
    }
    pub fn ttl(&self) -> TTL {
        self.deobfuscated.ttl
    }
    pub fn ctl(&self) -> CTL {
        self.deobfuscated.ctl
    }
    pub fn create_header(&self, dst: Address) -> Header {
        Header {
            ivi: self.ivi,
            nid: self.nid,
            ctl: self.ctl(),
            ttl: self.ttl(),
            seq: self.seq(),
            src: self.src(),
            dst,
        }
    }
}
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
    pub fn private_header(&self, ivi: IVI, nid: NID) -> PrivateHeader<'_> {
        PrivateHeader::new(ivi, nid, &self)
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
    pub fn unpack(bytes: &[u8; OBFUSCATED_LEN]) -> Option<DeobfuscatedHeader> {
        let seq =
            SequenceNumber::from_bytes_be(&bytes[1..4]).expect("sequence_number should never fail");
        let src = UnicastAddress::from_bytes_be(&bytes[4..])?;
        let (ttl, ctl) = TTL::new_with_flag(bytes[0]);
        Some(DeobfuscatedHeader::new(CTL(ctl), ttl, seq, src))
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
    pub fn new_bytes(bytes: [u8; PECB_LEN]) -> Self {
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
pub struct PrivacyRandom<'a>(&'a [u8]);
impl PrivacyRandom<'_> {
    /// # Panics
    /// Panics if `bytes.len() != PRIVACY_RANDOM_LEN`
    pub fn new_bytes(bytes: &[u8]) -> PrivacyRandom<'_> {
        assert_eq!(bytes.len(), PRIVACY_RANDOM_LEN);
        PrivacyRandom(bytes)
    }
    pub fn pack_with_iv(&self, iv_index: IVIndex) -> PackedPrivacy {
        let mut out = [0_u8; PACKED_PRIVACY_LEN];
        out[5..9].copy_from_slice(&iv_index.to_bytes_be());
        out[9..].copy_from_slice(&self.0);
        PackedPrivacy::new_bytes(out)
    }
}
impl<'a> From<&'a EncryptedPDU> for PrivacyRandom<'a> {
    fn from(pdu: &'a EncryptedPDU) -> Self {
        PrivacyRandom::new_bytes(&pdu.pdu_buffer[OBFUSCATED_LEN + 1..][..6])
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
    pub fn encrypt_with(mut self, key: PrivacyKey) -> PECB {
        AESCipher::new(key.key()).ecb_encrypt(&mut self.0[..]);
        PECB(
            (&self.0[..PECB_LEN])
                .try_into()
                .expect("slice is sliced to array length"),
        )
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
    use super::Header;

    /*
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
    */
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
