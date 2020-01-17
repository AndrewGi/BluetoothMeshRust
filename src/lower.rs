//! Lower Transport Layer.
//! Primarily handles 4 types of PDUs.
//!
//! |           | Segmented                 | Unsegmented               |
//! | --------- | ------------------------- | ------------------------- |
//! | Access    | [SegmentedAccessPDU]      | [UnsegmentedAccessPDU]    |
//! | Control   | [SegmentedControlPDU]     | [UnsegmentedControlPDU]   |
use crate::control::ControlOpcode;
use crate::crypto::{AID, AKF, MIC};
use crate::mesh::{SequenceNumber, CTL, U24};
use crate::serializable::bytes::ToFromBytesEndian;
use core::convert::{TryFrom, TryInto};

#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SZMIC(bool);
impl From<SZMIC> for bool {
    fn from(s: SZMIC) -> Self {
        s.0
    }
}
impl From<bool> for SZMIC {
    fn from(b: bool) -> Self {
        SZMIC(b)
    }
}
pub const SEQ_ZERO_MAX: u16 = (1u16 << 13) - 1;
///13 Bits SeqZero. Derived from `SeqAuth`
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SeqZero(u16);
impl SeqZero {
    /// Create a new 13 bit `SeqZero`.
    /// # Panics
    /// Panics if `seq_zero > SEQ_ZERO_MAX` (if you pass it a number longer than 13 bits).
    pub fn new(seq_zero: u16) -> Self {
        assert!(seq_zero <= SEQ_ZERO_MAX);
        SeqZero(seq_zero)
    }
}
impl From<SequenceNumber> for SeqZero {
    fn from(n: SequenceNumber) -> Self {
        SeqZero(
            (n.0.value() & u32::from(SEQ_ZERO_MAX))
                .try_into()
                .expect("masking upper bits"),
        )
    }
}
impl From<SeqZero> for u16 {
    fn from(s: SeqZero) -> Self {
        s.0
    }
}

/// 53-bit Sequence Authentication value.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct SeqAuth(u64);

pub const SEG_MAX: u8 = 0x1F;

/// 5 bit SegO (Segment Offset number)
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SegO(u8);
impl SegO {
    pub fn new(v: u8) -> Self {
        assert!(v <= SEG_MAX);
        Self(v)
    }
}
impl From<SegO> for u8 {
    fn from(s: SegO) -> Self {
        s.0
    }
}
/// 5 bit SegN (Last Segment number)
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SegN(u8);
impl SegN {
    pub fn new(v: u8) -> Self {
        assert!(v <= SEG_MAX);
        Self(v)
    }
    /// Returns the next `SegN` (`SegN + 1`). If `SegN` is at `SEG_MAX`, it'll return it self.
    pub fn next(&self) -> SegN {
        if self.0 >= SEG_MAX {
            *self
        } else {
            SegN(self.0 + 1)
        }
    }
}
impl From<SegN> for u8 {
    fn from(s: SegN) -> Self {
        s.0
    }
}
/// 32-bit BlockAck used for Lower Transport ACKs.
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct BlockAck(pub u32);
impl BlockAck {
    /// Sets the `bit` bit to 1. Does nothing if bit > 32
    pub fn set(&mut self, bit: u8) {
        debug_assert!(bit < 32, "{} index overflow into u32", bit);
        if bit >= 32 {
            return;
        }
        (self.0) |= 1_u32 << u32::from(bit);
    }
    /// Returns the bit status (1 or 0) of the `bit` bit. Returns `False` for bit > 32
    #[must_use]
    pub fn get(self, bit: u8) -> bool {
        debug_assert!(bit < 32, "{} index overflow into u32", bit);
        if bit >= 32 {
            false
        } else {
            (self.0 & (1_u32 << u32::from(bit))) != 0
        }
    }
    /// Returns if the block ack (up to `seg_o` bits) is all 1s. False if otherwise
    #[must_use]
    pub fn all_acked(self, seg_o: SegO) -> bool {
        self.0 == (1_u32 << u32::from(seg_o.0)).wrapping_sub(1)
    }
    /// Returns the max length of BlockAck in bits (32).
    pub const fn max_len() -> usize {
        32
    }
    pub fn count_ones(self) -> u8 {
        self.0
            .count_ones()
            .try_into()
            .expect("count_ones can only return <= 32")
    }
    pub fn seg_left(mut self, seg_o: SegO) -> u8 {
        // Mask Upper bits so we don't underflow
        self = BlockAck(self.0 & ((1 << u32::from(u8::from(seg_o))) - 1));
        u8::from(seg_o) - self.count_ones()
    }
}
/// SEG Flag for signaling segmented PDUs. Unsegmented PDUs have `SEG(false)` while segmented
/// PDUs have `SEG(true)`.
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SEG(bool);
impl SEG {
    /// Creates a SEG by looking at the 7th bit.
    pub fn new_upper_masked(v: u8) -> SEG {
        SEG(v & 0x80 != 0)
    }
}
impl From<SEG> for bool {
    fn from(s: SEG) -> Self {
        s.0
    }
}
impl From<bool> for SEG {
    fn from(b: bool) -> Self {
        SEG(b)
    }
}
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct OBO(bool);
/// Generic Segment Header for both segmented Access and Control PDUs. Flag is usually SZMIC or
/// RFU.
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SegmentHeader {
    flag: bool,
    seq_zero: SeqZero,
    seg_o: SegO,
    seg_n: SegN,
}
impl SegmentHeader {
    /// Creates a new segment header. `flag` is usually `OBO` or `SZMIC`.
    #[must_use]
    pub fn new(flag: bool, seq_zero: SeqZero, seg_o: SegO, seg_n: SegN) -> Self {
        Self {
            flag,
            seq_zero,
            seg_o,
            seg_n,
        }
    }
    #[must_use]
    pub fn pack_into_u24(&self) -> U24 {
        let mut out = 0u32;
        out |= u32::from(u8::from(self.seg_n));
        out |= u32::from(u8::from(self.seg_o) << 5);
        out |= u32::from(u16::from(self.seq_zero) << 10);
        out |= u32::from(self.flag) << 23;
        U24::new(out)
    }
    #[must_use]
    pub fn unpack_from_u24(b: U24) -> Self {
        let bytes = b.to_bytes_be();
        let flag = bytes[0] & 0x80 != 0;
        let seq_high = bytes[0] & 0x7F; //7 upper bits of SeqZero
        let seq_low = (bytes[1] & 0xFC) >> 2; // 6 Lower bits of SeqZero
        let seq_zero = SeqZero::new(u16::from(seq_low) | (u16::from(seq_high) << 6));
        let seg_o_high = bytes[1] & 0x02;
        let seg_n = SegN::new(bytes[2] & SEG_MAX);
        let seg_o_low = (bytes[2] & !SEG_MAX) >> 5;
        let seg_o = SegO::new(seg_o_low | (seg_o_high << 3));
        Self::new(flag, seq_zero, seg_o, seg_n)
    }
}

/// Lower Transport PDU
/// | CTL | SEG | Format				|
/// |  0  |  0  | Unsegmented Access	|
/// |  0  |  1  | Segmented Access		|
/// |  1  |  0  | Unsegmented Control	|
/// |  1  |  1  | Segmented Control		|
///
///
const UNSEGMENTED_ACCESS_PDU_MAX_LEN: usize = 15;
const UNSEGMENTED_ACCESS_PDU_MIN_LEN: usize = 5;
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct UnsegmentedAccessPDU {
    aid: Option<AID>,
    access_pdu_buf: [u8; UNSEGMENTED_ACCESS_PDU_MAX_LEN],
    access_pdu_len: usize,
}
impl UnsegmentedAccessPDU {
    /// # Panics
    /// Panics if `data.len() > UNSEGMENTED_ACCESS_PDU_LEN` (15)
    pub fn new(aid: Option<AID>, data: &[u8]) -> UnsegmentedAccessPDU {
        assert!(data.len() <= UNSEGMENTED_ACCESS_PDU_MAX_LEN);
        assert!(data.len() >= UNSEGMENTED_ACCESS_PDU_MIN_LEN);
        let len = data.len();
        let buf = [0_u8; UNSEGMENTED_ACCESS_PDU_MAX_LEN];
        UnsegmentedAccessPDU {
            aid,
            access_pdu_buf: buf,
            access_pdu_len: len,
        }
    }
    #[must_use]
    pub const fn max_len() -> usize {
        UNSEGMENTED_ACCESS_PDU_MAX_LEN + 1
    }
    #[must_use]
    pub fn upper_pdu_len(&self) -> usize {
        self.access_pdu_len
    }
    #[must_use]
    pub fn len(&self) -> usize {
        1 + self.access_pdu_len
    }
    #[must_use]
    pub fn upper_pdu(&self) -> &[u8] {
        &self.access_pdu_buf[..self.access_pdu_len]
    }
    #[must_use]
    pub fn aid(&self) -> Option<AID> {
        self.aid
    }
    #[must_use]
    pub fn akf(&self) -> AKF {
        self.aid().is_some().into()
    }
    /// Packs the header into a byte buffer.
    /// # Panics
    /// Panics if `data.len() < self.len()`.
    #[must_use]
    pub fn pack_into(&self, bytes: &mut [u8]) {
        assert!(self.len() <= bytes.len());
        bytes[0] = self
            .aid
            .unwrap_or_default()
            .with_flags(self.akf().into(), false);
        bytes[1..self.len()].copy_from_slice(self.upper_pdu());
    }
    #[must_use]
    pub fn unpack_from(bytes: &[u8]) -> Option<Self> {
        if SEG::new_upper_masked(bytes[0]).0
            || bytes.len() > UNSEGMENTED_ACCESS_PDU_MAX_LEN + 1
            || bytes.len() < UNSEGMENTED_ACCESS_PDU_MIN_LEN
        {
            None
        } else {
            let akf = AKF::from(bytes[0] & 0x40 != 0);
            let aid = AID::new_masked(bytes[0]);
            if !bool::from(akf) && u8::from(aid) == 0 {
                // 0 AKF Flag with a non-zero AID.
                return None;
            }
            let aid = if bool::from(akf) { Some(aid) } else { None };
            Some(Self::new(aid, &bytes[1..]))
        }
    }
    #[must_use]
    pub fn mic(&self) -> MIC {
        MIC::try_from_bytes_be(
            &self.access_pdu_buf[self.access_pdu_len - MIC::small_size()..self.access_pdu_len],
        )
        .expect("all access PDUs have small MIC")
    }
}
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct SegmentedAccessPDU {
    aid: Option<AID>,
    segment_header: SegmentHeader,
    segment_buf: [u8; SegmentedAccessPDU::max_seg_len()],
    len: usize,
}

impl SegmentedAccessPDU {
    pub fn new(
        aid: Option<AID>,
        sz_mic: SZMIC,
        seq_zero: SeqZero,
        seg_o: SegO,
        seg_n: SegN,
        data: &[u8],
    ) -> Self {
        assert!(data.len() < Self::max_seg_len());
        let mut buf = [0_u8; SegmentedAccessPDU::max_seg_len()];
        buf[..data.len()].copy_from_slice(data);
        Self {
            aid,
            segment_header: SegmentHeader {
                flag: sz_mic.0,
                seq_zero,
                seg_o,
                seg_n,
            },
            segment_buf: buf,
            len: data.len(),
        }
    }
    pub fn segment_data(&self) -> &[u8] {
        &self.segment_buf[..self.len]
    }
    pub fn segment_len(&self) -> usize {
        self.len
    }
    pub fn len(&self) -> usize {
        self.segment_len() + 4
    }
    #[must_use]
    pub fn akf(&self) -> AKF {
        self.aid.is_some().into()
    }
    #[must_use]
    pub fn aid(&self) -> Option<AID> {
        self.aid
    }
    #[must_use]
    pub const fn min_len() -> usize {
        5
    }
    /// Packs the PDU into a byte buffer.
    /// # Panics
    /// Panics if `buf.len() < self.len()` (if there isn't enough room for the PDU).
    #[must_use]
    pub fn pack_into(&self, buffer: &mut [u8]) {
        assert!(buffer.len() >= self.len());
        let bytes = &mut buffer[..self.len()];
        bytes.as_mut()[0] = self
            .aid()
            .unwrap_or(AID::new(0))
            .with_flags(self.akf().into(), true);
        bytes.as_mut()[1..4].copy_from_slice(&self.segment_header.pack_into_u24().to_bytes_be());
        bytes.as_mut()[4..].copy_from_slice(self.segment_data());
    }
    #[must_use]
    pub fn unpack_from(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::min_len() || bytes.len() > Self::max_seg_len() + 4 {
            return None;
        }
        let (aid, akf, seg) = AID::from_flags(bytes[0]);
        if !seg {
            // Seg is 0 when it should be 1
            return None;
        }
        if !akf && aid != AID::default() {
            // AKF is false but AID isn't zero.
            return None;
        }
        let aid = if akf { None } else { Some(aid) };
        let packed_header = U24::from_bytes_be(&bytes[1..4]).expect("seq_zero should ways exist");
        let segment_header = SegmentHeader::unpack_from_u24(packed_header);
        Some(SegmentedAccessPDU::new(
            aid,
            segment_header.flag.into(),
            segment_header.seq_zero,
            segment_header.seg_o,
            segment_header.seg_n,
            &bytes[4..],
        ))
    }
    pub const fn max_seg_len() -> usize {
        12
    }
}

const UNSEGMENTED_CONTROL_PDU_LEN: usize = 11;
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct UnsegmentedControlPDU {
    parameters_buf: [u8; UNSEGMENTED_CONTROL_PDU_LEN],
    parameters_len: usize,
    opcode: ControlOpcode,
}
impl UnsegmentedControlPDU {
    #[must_use]
    pub fn new(opcode: ControlOpcode, parameters: &[u8]) -> UnsegmentedControlPDU {
        assert!(parameters.len() <= UNSEGMENTED_CONTROL_PDU_LEN);
        let mut buf = [0_u8; UNSEGMENTED_CONTROL_PDU_LEN];
        buf[..parameters.len()].copy_from_slice(parameters);
        UnsegmentedControlPDU {
            parameters_buf: buf,
            parameters_len: parameters.len(),
            opcode,
        }
    }
    #[must_use]
    pub const fn parameters_len(&self) -> usize {
        self.parameters_len
    }
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.parameters_buf[..self.parameters_len()]
    }
    #[must_use]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let l = self.parameters_len();
        &mut self.parameters_buf[..l]
    }
    #[must_use]
    pub const fn min_parameters_size() -> usize {
        0 // 0-88 Bits
    }
    #[must_use]
    pub const fn max_parameters_size() -> usize {
        UNSEGMENTED_CONTROL_PDU_LEN // 0-88 Bits
    }
    pub fn len(&self) -> usize {
        self.parameters_len() + 1
    }
    /// Packs the PDU into a byte buffer.
    /// # Panics
    /// Panics if `buffer.len() < self.len()` (if there isn't enough room for the PDU).
    #[must_use]
    pub fn pack_into(&self, buffer: &mut [u8]) {
        assert!(buffer.len() >= self.len());
        buffer[0] = self.opcode.into();
        buffer[0] &= !0x80; //Make sure Seg = 0
        buffer[1..self.len()].copy_from_slice(self.data());
    }
    #[must_use]
    pub fn unpack_from(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 1 || bytes.len() > Self::max_parameters_size() + 1 {
            return None;
        }
        if bytes[0] & 0x80 != 0 {
            //Segmented PDU
            return None;
        }
        let opcode = ControlOpcode::new(bytes[0] & 0x7F)?;
        Some(Self::new(opcode, &bytes[1..]))
    }
}
const MAX_SEGMENTED_CONTROL_PDU_LEN: usize = 8;

/// Segmented Control PDU Lengths
///
/// | # Packets  | PDU Size |
/// | ---------- | -------- |
/// |      1     |     8    |
/// |      2     |    16    |
/// |      3     |    24    |
/// |      n     |    n*8   |
/// |     32     |    256   |
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct SegmentedControlPDU {
    opcode: ControlOpcode,
    segment_header: SegmentHeader,
    segment_buf: [u8; MAX_SEGMENTED_CONTROL_PDU_LEN],
    segment_buf_len: usize,
}
impl SegmentedControlPDU {
    /// # Panic
    /// Panics if `data.len() > MAX_SEGMENTED_CONTROL_PDU_LEN` (8)
    #[must_use]
    pub fn new(opcode: ControlOpcode, header: SegmentHeader, data: &[u8]) -> SegmentedControlPDU {
        assert!(
            data.len() < MAX_SEGMENTED_CONTROL_PDU_LEN,
            "segment overflow ({} > {})",
            data.len(),
            MAX_SEGMENTED_CONTROL_PDU_LEN
        );
        let mut buf = [0_u8; MAX_SEGMENTED_CONTROL_PDU_LEN];
        buf[..data.len()].copy_from_slice(data);
        SegmentedControlPDU {
            opcode,
            segment_header: header,
            segment_buf: buf,
            segment_buf_len: data.len(),
        }
    }
    #[must_use]
    pub const fn max_len() -> usize {
        4 + MAX_SEGMENTED_CONTROL_PDU_LEN
    }
    #[must_use]
    pub const fn min_len() -> usize {
        4 + 1
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.segment_buf_len + 4
    }
    #[must_use]
    pub fn segment_len(&self) -> usize {
        self.segment_buf_len
    }
    #[must_use]
    pub fn segment_data(&self) -> &[u8] {
        &self.segment_buf[..self.segment_len()]
    }
    #[must_use]
    pub fn segment_data_mut(&mut self) -> &mut [u8] {
        let l = self.segment_len();
        &mut self.segment_buf[..l]
    }
    #[must_use]
    pub const fn opcode(&self) -> ControlOpcode {
        self.opcode
    }
    #[must_use]
    pub const fn header(&self) -> &SegmentHeader {
        &self.segment_header
    }
    #[must_use]
    pub fn pack_into(&self, buffer: &mut [u8]) {
        assert!(buffer.len() >= self.len());
        let buffer = &mut buffer[..self.len()];
        buffer[0] = self.opcode.into();
        buffer[0] |= 0x80;
        buffer[1..4].copy_from_slice(&self.segment_header.pack_into_u24().to_bytes_be());
        buffer[4..].copy_from_slice(self.segment_data());
    }
    #[must_use]
    pub fn unpack_from(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::min_len() || bytes.len() > Self::max_len() {
            return None;
        }
        if bytes[0] & 0x80 == 0 {
            // Unsegmented PDU
            return None;
        }
        let opcode = ControlOpcode::new(bytes[0] & 0x7F)?;
        let packed_header =
            U24::from_bytes_be(&bytes[1..4]).expect("packed header should always be here");
        let segment_header = SegmentHeader::unpack_from_u24(packed_header);
        Some(Self::new(opcode, segment_header, &bytes[4..]))
    }
    #[must_use]
    pub const fn max_seg_len() -> usize {
        MAX_SEGMENTED_CONTROL_PDU_LEN
    }
}
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct SegmentAckPDU {
    seq_zero: SeqZero,
    block_ack: BlockAck,
    obo: OBO,
}
impl SegmentAckPDU {
    #[must_use]
    pub const fn opcode() -> ControlOpcode {
        ControlOpcode::Ack
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub enum PDU {
    UnsegmentedAccess(UnsegmentedAccessPDU),
    SegmentedAccess(SegmentedAccessPDU),
    UnsegmentedControl(UnsegmentedControlPDU),
    SegmentedControl(SegmentedControlPDU),
}
impl PDU {
    #[must_use]
    pub fn is_seg(&self) -> bool {
        match self {
            PDU::UnsegmentedAccess(_) | PDU::UnsegmentedControl(_) => false,
            PDU::SegmentedAccess(_) | PDU::SegmentedControl(_) => true,
        }
    }
    #[must_use]
    pub fn is_control(&self) -> bool {
        match self {
            PDU::UnsegmentedAccess(_) | PDU::SegmentedAccess(_) => false,
            PDU::UnsegmentedControl(_) | PDU::SegmentedControl(_) => true,
        }
    }
    pub fn len(&self) -> usize {
        match self {
            PDU::UnsegmentedAccess(p) => p.len(),
            PDU::SegmentedAccess(p) => p.len(),
            PDU::UnsegmentedControl(p) => p.len(),
            PDU::SegmentedControl(p) => p.len(),
        }
    }
    /// Number of bytes required to hold any serialized `Lower::PDU` in a byte buffer.
    pub const fn max_len() -> usize {
        16
    }
    /// Packs the Lower Transport PDU into a buffer.
    /// # Panics
    /// Panics if `buffer.len() < self.len()`.
    pub fn pack_into(&self, buffer: &mut [u8]) {
        match self {
            PDU::UnsegmentedAccess(p) => p.pack_into(buffer),
            PDU::SegmentedAccess(p) => p.pack_into(buffer),
            PDU::UnsegmentedControl(p) => p.pack_into(buffer),
            PDU::SegmentedControl(p) => p.pack_into(buffer),
        }
    }
    pub fn unpack_from(bytes: &[u8], ctl: CTL) -> Option<Self> {
        Some(match (bool::from(ctl), SEG::new_upper_masked(bytes[0]).0) {
            (true, true) => PDU::SegmentedControl(SegmentedControlPDU::unpack_from(bytes)?),
            (true, false) => PDU::UnsegmentedControl(UnsegmentedControlPDU::unpack_from(bytes)?),
            (false, false) => PDU::UnsegmentedAccess(UnsegmentedAccessPDU::unpack_from(bytes)?),
            (false, true) => PDU::SegmentedAccess(SegmentedAccessPDU::unpack_from(bytes)?),
        })
    }
}
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct PDUBytes {
    buf: [u8; PDU::max_len()],
    buf_len: usize,
}
impl PDUBytes {
    /// Creates a new `PDUBytes` from a byte buffer.
    /// # Panics
    /// Panics if `buffer.len() == 0 || buffer.len() > PDU::max_len()`.
    pub fn new(buffer: &[u8]) -> PDUBytes {
        buffer.try_into().expect("bad buffer length")
    }
    pub fn new_zeroed(len: usize) -> PDUBytes {
        PDUBytes {
            buf: [0_u8; PDU::max_len()],
            buf_len: len,
        }
    }
    pub fn len(&self) -> usize {
        self.buf_len
    }
    pub fn is_empty(&self) -> bool {
        self.buf_len == 0
    }
    pub fn seg(&self) -> SEG {
        debug_assert!(!self.is_empty());
        SEG(self.buf[0] & 0x80 != 0)
    }
}
impl AsRef<[u8]> for PDUBytes {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.buf_len]
    }
}
impl AsMut<[u8]> for PDUBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.buf_len]
    }
}
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct PDUBytesError;
impl TryFrom<&[u8]> for PDUBytes {
    type Error = PDUBytesError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let l = value.len();
        if l == 0 || l > PDU::max_len() {
            Err(PDUBytesError)
        } else {
            let mut buf = [0_u8; PDU::max_len()];
            buf[..l].copy_from_slice(value);
            Ok(Self { buf, buf_len: l })
        }
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum SegmentedPDU {
    Access(SegmentedAccessPDU),
    Control(SegmentedControlPDU),
}
impl From<&SegmentedPDU> for PDU {
    fn from(pdu: &SegmentedPDU) -> Self {
        match pdu {
            SegmentedPDU::Access(pdu) => PDU::SegmentedAccess(*pdu),
            SegmentedPDU::Control(pdu) => PDU::SegmentedControl(*pdu),
        }
    }
}
impl From<SegmentedPDU> for PDU {
    fn from(pdu: SegmentedPDU) -> Self {
        (&pdu).into()
    }
}
