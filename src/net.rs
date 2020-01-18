//! Bluetooth Mesh
//! Network Layer is BIG Endian

use crate::address::{Address, UnicastAddress, ADDRESS_LEN};
use crate::crypto::aes::{AESCipher, MicSize};
use crate::crypto::key::PrivacyKey;
use crate::crypto::materials::NetworkKeys;
use crate::crypto::nonce::{NetworkNonce, NetworkNonceParts};
use crate::crypto::MIC;
use crate::lower;
use crate::mesh::{IVIndex, SequenceNumber, CTL, IVI, NID, TTL};
use crate::serializable::bytes::ToFromBytesEndian;
use core::convert::TryInto;
use core::fmt;

pub struct DecryptedData {
    dst: Address,
    transport_buf: [u8; TRANSPORT_PDU_MAX_LEN],
    transport_len: usize,
    mic: Option<MIC>,
}
impl DecryptedData {
    pub fn dst(&self) -> Address {
        self.dst
    }
    pub fn transport_len(&self) -> usize {
        self.transport_len
    }
    pub fn transport_pdu(&self) -> &[u8] {
        &self.transport_buf[..self.transport_len]
    }
    pub fn as_lower_pdu(&self, ctl: CTL) -> Option<lower::PDU> {
        lower::PDU::unpack_from(self.transport_pdu(), ctl)
    }
    pub fn len(&self) -> usize {
        ADDRESS_LEN + self.transport_len
    }
    pub fn encrypt(
        &self,
        nonce: &NetworkNonce,
        network_keys: &NetworkKeys,
        mic_size: MicSize,
    ) -> OwnedEncryptedData {
        let mut buf = [0_u8; TRANSPORT_PDU_MAX_LEN + ADDRESS_LEN + MIC::max_len()];
        buf[..ADDRESS_LEN].copy_from_slice(&self.dst.to_bytes_be()[..]);
        buf[ADDRESS_LEN..self.len()].copy_from_slice(self.transport_pdu());
        let mic = AESCipher::new(network_keys.encryption_key().key()).ccm_encrypt(
            nonce.as_ref(),
            b"",
            &mut buf[..self.transport_len + ADDRESS_LEN],
            mic_size,
        );
        OwnedEncryptedData::new(&buf[..self.len()], mic)
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

pub struct OwnedEncryptedData {
    buf: [u8; TRANSPORT_PDU_MAX_LEN + ADDRESS_LEN],
    buf_len: usize,
    mic: MIC,
}
impl OwnedEncryptedData {
    /// # Panics
    /// Panics if `encrypted_data.len() <= ENCRYPTED_DATA_MIN_LEN`
    /// or `encrypted_data.len() > ENCRYPTED_DATA_MAX_LEN`
    pub fn new(encrypted_data: &[u8], mic: MIC) -> OwnedEncryptedData {
        assert!(encrypted_data.len() > ENCRYPTED_DATA_MIN_LEN);
        assert!(encrypted_data.len() <= ENCRYPTED_DATA_MAX_LEN);
        let mut buf = [0_u8; TRANSPORT_PDU_MAX_LEN + ADDRESS_LEN];
        buf[..encrypted_data.len()].copy_from_slice(encrypted_data);
        OwnedEncryptedData {
            buf,
            buf_len: encrypted_data.len(),
            mic,
        }
    }
    pub fn data(&self) -> EncryptedData {
        self.into()
    }
}
impl<'a> From<&'a OwnedEncryptedData> for EncryptedData<'a> {
    fn from(data: &'a OwnedEncryptedData) -> Self {
        EncryptedData::new(&data.buf[..data.buf_len], data.mic)
    }
}
const TRANSPORT_PDU_MIN_LEN: usize = 1;
const TRANSPORT_PDU_MAX_LEN: usize = 16;

/// Holds the encrypted destination address, transport PDU and MIC.
pub struct EncryptedData<'a> {
    data: &'a [u8],
    mic: MIC,
}

const ENCRYPTED_DATA_MIN_LEN: usize = ADDRESS_LEN;
const ENCRYPTED_DATA_MAX_LEN: usize = ENCRYPTED_DATA_MIN_LEN + TRANSPORT_PDU_MAX_LEN;
impl EncryptedData<'_> {
    /// # Panics
    /// Panics if `encrypted_data.len() <= ENCRYPTED_DATA_MIN_LEN`
    /// or `encrypted_data.len() > ENCRYPTED_DATA_MAX_LEN`
    pub fn new(encrypted_data: &[u8], mic: MIC) -> EncryptedData<'_> {
        assert!(encrypted_data.len() > ENCRYPTED_DATA_MIN_LEN);
        assert!(encrypted_data.len() <= ENCRYPTED_DATA_MAX_LEN);
        EncryptedData {
            data: encrypted_data,
            mic,
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
        &self.data[..]
    }
    #[must_use]
    pub fn data_len(&self) -> usize {
        self.len() - self.mic_size()
    }
    pub fn mic_size(&self) -> usize {
        self.mic.byte_size()
    }
    #[must_use]
    pub fn mic(&self) -> MIC {
        self.mic
    }
    #[must_use]
    pub fn packed_privacy_random(&self, dst: Address, iv_index: IVIndex) -> PackedPrivacy {
        let mut privacy_random_buf = [0_u8; PRIVACY_RANDOM_LEN + MIC::max_len()];
        privacy_random_buf[..ADDRESS_LEN].copy_from_slice(&dst.value().to_le_bytes());
        privacy_random_buf[ADDRESS_LEN..ADDRESS_LEN + self.data.len()].copy_from_slice(self.data());
        if self.data.len() < PRIVACY_RANDOM_LEN - ADDRESS_LEN {
            self.mic.be_pack_into(
                &mut privacy_random_buf[ADDRESS_LEN + self.data.len()
                    ..ADDRESS_LEN + self.data().len() + self.mic.byte_size()],
            );
        };
        PrivacyRandom(&privacy_random_buf[..PRIVACY_RANDOM_LEN]).pack_with_iv(iv_index)
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
            mic: Some(mic),
        })
    }
    /// # Panics
    /// Panics if `buffer.len() < self.len()`.
    pub fn pack_into(&self, buffer: &mut [u8]) {
        assert!(buffer.len() >= self.len());
        let buffer = &mut buffer[..self.len()];
        buffer[..self.data_len()].copy_from_slice(self.data());
        self.mic
            .be_pack_into(&mut buffer[self.data_len()..self.data_len() + self.mic_size()]);
    }
}
impl AsRef<[u8]> for EncryptedData<'_> {
    #[must_use]
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

/// ## Mesh Network PDU
/// Network layer is Big Endian.
/// From Mesh Core v1.0
///
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
    pub fn with_seq(&self, seq: SequenceNumber) -> Self {
        Self { seq, ..*self }
    }

    #[must_use]
    pub const fn len() -> usize {
        PDU_HEADER_LEN
    }
    #[must_use]
    pub fn big_mic(&self) -> bool {
        self.ctl.into()
    }
    #[must_use]
    pub fn mic_byte_size(&self) -> usize {
        if self.big_mic() {
            MIC::big_size()
        } else {
            MIC::small_size()
        }
    }
    #[must_use]
    pub fn mic_size(&self) -> MicSize {
        if self.big_mic() {
            MicSize::Big
        } else {
            MicSize::Small
        }
    }
    #[must_use]
    pub fn obfuscate(&self, pecb: PECB) -> ObfuscatedHeader {
        DeobfuscatedHeader::from(self).obfuscate(pecb)
    }
    #[must_use]
    pub fn deobfuscated(&self) -> DeobfuscatedHeader {
        self.into()
    }
}
impl From<&Header> for DeobfuscatedHeader {
    #[must_use]
    fn from(h: &Header) -> Self {
        DeobfuscatedHeader::new(h.ctl, h.ttl, h.seq, h.src)
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
pub struct OwnedEncryptedPDU {
    pdu_buffer: [u8; ENCRYPTED_PDU_MAX_SIZE],
    length: usize,
}
impl OwnedEncryptedPDU {
    pub fn new(bytes: &[u8]) -> Option<OwnedEncryptedPDU> {
        if bytes.len() < ENCRYPTED_DATA_MIN_LEN || bytes.len() > ENCRYPTED_DATA_MAX_LEN {
            None
        } else {
            let mut buf = [0_u8; ENCRYPTED_PDU_MAX_SIZE];
            buf[..bytes.len()].copy_from_slice(bytes);
            Some(Self {
                pdu_buffer: buf,
                length: bytes.len(),
            })
        }
    }
    /// # Panics
    /// Panics if `length < ENCRYPTED_PDU_MIN_LEN || length > ENCRYPTED_PDU_MAX_LEN`.
    pub fn new_zeroed(length: usize) -> Self {
        assert!(length <= ENCRYPTED_DATA_MAX_LEN && length > ENCRYPTED_DATA_MIN_LEN);
        OwnedEncryptedPDU {
            pdu_buffer: [0_u8; ENCRYPTED_PDU_MAX_SIZE],
            length,
        }
    }
    #[must_use]
    pub fn new_parts(
        ivi: IVI,
        nid: NID,
        obfuscated: &ObfuscatedHeader,
        encrypted_data: EncryptedData,
    ) -> Self {
        let mut out = Self::new_zeroed(encrypted_data.len() + ObfuscatedHeader::len() + 1);
        let buf = out.as_mut();
        buf[0] = nid.with_flag(ivi.into());
        obfuscated.pack_into(&mut buf[1..1 + ObfuscatedHeader::len()]);
        encrypted_data.pack_into(&mut buf[1 + ObfuscatedHeader::len()..]);
        encrypted_data
            .mic
            .be_pack_into(&mut buf[1 + ObfuscatedHeader::len() + encrypted_data.data_len()..]);
        out
    }

    pub fn as_ref(&self) -> EncryptedPDU {
        EncryptedPDU {
            data: &self.pdu_buffer[..self.length],
        }
    }
}
const MIN_ENCRYPTED_PDU_LEN: usize = PDU_HEADER_LEN + MIC::small_size();
const MAX_ENCRYPTED_PDU_LEN: usize = ENCRYPTED_PDU_MAX_SIZE;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct EncryptedPDU<'a> {
    data: &'a [u8],
}

impl<'a> EncryptedPDU<'a> {
    /// Wrapped a raw bytes that represent an Encrypted Network PDU
    /// See `ENCRYPTED_PDU_MAX_SIZE` for the max size.
    /// Returns `None` if `buf.len() < MIN_ENCRYPTED_PDU_LEN`
    /// or `data.len() > MAX_ENCRYPTED_PDU_LEN`.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Option<EncryptedPDU<'a>> {
        if data.len() < MIN_ENCRYPTED_PDU_LEN || data.len() > MAX_ENCRYPTED_PDU_LEN {
            return None;
        }
        Some(EncryptedPDU { data })
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    #[must_use]
    pub fn nid(&self) -> NID {
        NID::from_masked_u8(self.data[0])
    }
    #[must_use]
    pub fn ivi(&self) -> IVI {
        IVI(self.data[0] & 0x80 != 0)
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
        if iv_index.ivi() != self.ivi() {
            return Err(NetworkDataError::BadIVI);
        }
        let pecb = PrivacyRandom::from(*self)
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
            self.data[1..1 + OBFUSCATED_LEN]
                .try_into()
                .expect("obfuscated header should always exist"),
        )
    }
    pub fn mic(&self, ctl: CTL) -> MIC {
        let mic_size = if bool::from(ctl) { 8 } else { 4 };
        MIC::try_from_bytes_be(&self.data[self.data.len() - mic_size..])
            .expect("every PDU has a MIC")
    }

    pub fn encrypted_data(&self, ctl: CTL) -> EncryptedData {
        let mic = self.mic(ctl);
        EncryptedData::new(
            &self.data[OBFUSCATED_LEN..self.data.len() - mic.byte_size()],
            mic,
        )
    }
    fn to_owned(&self) -> OwnedEncryptedPDU {
        let mut out = OwnedEncryptedPDU::new_zeroed(self.data.len());
        out.as_mut().copy_from_slice(self.data());
        out
    }
}
impl AsRef<[u8]> for OwnedEncryptedPDU {
    #[must_use]
    fn as_ref(&self) -> &[u8] {
        &self.pdu_buffer[..self.length]
    }
}
impl AsMut<[u8]> for OwnedEncryptedPDU {
    #[must_use]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.pdu_buffer[..self.length]
    }
}
/// Mesh Network PDU Structure
#[derive(Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct PDU {
    pub header: Header,
    pub payload: lower::PDU,
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum PDUEncryptError {
    WrongNID,
    WrongIVI,
    BadDst,
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
    #[must_use]
    pub fn payload(&self) -> &lower::PDU {
        &self.payload
    }
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }
    #[must_use]
    pub fn is_segmented(&self) -> bool {
        self.payload.is_seg()
    }
    #[must_use]
    pub fn decrypted_data(&self) -> DecryptedData {
        let mut buf = [0_u8; TRANSPORT_PDU_MAX_LEN];
        self.payload.pack_into(&mut buf[..]);
        DecryptedData {
            dst: self.header.dst,
            transport_buf: buf,
            transport_len: self.payload.len(),
            mic: None,
        }
    }
    /// Encrypts the PDU. Ignores the IVI, NID, and CTL.
    #[must_use]
    pub fn encrypt(
        &self,
        net_keys: &NetworkKeys,
        iv_index: IVIndex,
    ) -> Result<OwnedEncryptedPDU, PDUEncryptError> {
        if !self.header.dst.is_assigned()
            || (self.payload.is_control() && self.header.dst.is_virtual())
        {
            Err(PDUEncryptError::BadDst)
        } else {
            let deobfuscated = self.header.deobfuscated();
            let unencrypted = self.decrypted_data();
            let encrypted = unencrypted.encrypt(
                &deobfuscated.nonce(iv_index),
                net_keys,
                self.header.mic_size(),
            );
            let pecb = encrypted
                .data()
                .packed_privacy_random(self.header.dst, iv_index)
                .encrypt_with(net_keys.privacy_key());
            Ok(OwnedEncryptedPDU::new_parts(
                iv_index.ivi(),
                net_keys.nid(),
                &deobfuscated.obfuscate(pecb),
                encrypted.data(),
            ))
        }
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
    pub const fn len() -> usize {
        OBFUSCATED_LEN
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
impl<'a: 'b, 'b> From<EncryptedPDU<'a>> for PrivacyRandom<'b> {
    fn from(pdu: EncryptedPDU<'a>) -> Self {
        PrivacyRandom::new_bytes(&pdu.data[1 + OBFUSCATED_LEN..][..PRIVACY_RANDOM_LEN])
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
    pub fn encrypt_with(mut self, key: &PrivacyKey) -> PECB {
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
