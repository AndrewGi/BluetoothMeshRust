use super::bearer_control;
use core::convert::TryFrom;

/// 6 bit Segment Number
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct SegmentIndex(u8);
const SEGMENT_INDEX_MAX: u8 = (1_u8 << 6) - 1;
impl SegmentIndex {
    /// Creates a new 6 bit Segment Index from a u8.
    /// # Panics
    /// Panics if `index` is greater than 6 bits (`index` > `SEGMENT_INDEX_MAX`).
    pub fn new(index: u8) -> SegmentIndex {
        assert!(index < SEGMENT_INDEX_MAX);
        Self(index)
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct FCS(u8);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct MTU(u8);

#[repr(u8)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum GPCF {
    TransactionStart = 0b00,
    TransactionAcknowledgment = 0b01,
    TransactionContinuation = 0b10,
    BearerControl = 0b11,
}
impl GPCF {
    pub fn pack_with(self, six_bits: u8) -> u8 {
        // Mask u8 into a u6.
        let bits = six_bits & 0x3F;
        (bits << 2) | (self as u8)
    }
    pub fn from_masked_u2(u2: u8) -> Self {
        match u2 & 0b11 {
            0b00 => GPCF::TransactionStart,
            0b01 => GPCF::TransactionAcknowledgment,
            0b10 => GPCF::TransactionContinuation,
            0b11 => GPCF::BearerControl,
            _ => unreachable!("only the above 4 GPCF should exist"),
        }
    }
    pub fn unpack_with(byte: u8) -> (Self, u8) {
        (Self::from_masked_u2(byte), (byte & 0xFC) >> 2)
    }
}
impl From<GPCF> for u8 {
    fn from(g: GPCF) -> Self {
        g as u8
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default)]
pub struct TransactionAcknowledgmentPDU {}
impl TransactionAcknowledgmentPDU {
    pub const fn new() -> Self {
        Self {}
    }
    pub const fn as_u8(self) -> u8 {
        GPCF::TransactionAcknowledgment as u8
    }
    pub const fn is_transaction_ack(b: u8) -> bool {
        Self::new().as_u8() == b
    }
}
impl From<TransactionAcknowledgmentPDU> for u8 {
    fn from(pdu: TransactionAcknowledgmentPDU) -> Self {
        pdu.as_u8()
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct TransactionStartPDU {
    seg_n: SegmentIndex,
    total_length: u16,
    fcs: FCS,
}
/// FCS 3GPP TS 27.010
/// Polynomial x^8 x^2 + x + 1
const FCS_TABLE: [u8; 256] = [
    0x00, 0x91, 0xe3, 0x72, 0x07, 0x96, 0xe4, 0x75, 0x0e, 0x9f, 0xed, 0x7c, 0x09, 0x98, 0xea, 0x7b,
    0x1c, 0x8d, 0xff, 0x6e, 0x1b, 0x8a, 0xf8, 0x69, 0x12, 0x83, 0xf1, 0x60, 0x15, 0x84, 0xf6, 0x67,
    0x38, 0xa9, 0xdb, 0x4a, 0x3f, 0xae, 0xdc, 0x4d, 0x36, 0xa7, 0xd5, 0x44, 0x31, 0xa0, 0xd2, 0x43,
    0x24, 0xb5, 0xc7, 0x56, 0x23, 0xb2, 0xc0, 0x51, 0x2a, 0xbb, 0xc9, 0x58, 0x2d, 0xbc, 0xce, 0x5f,
    0x70, 0xe1, 0x93, 0x02, 0x77, 0xe6, 0x94, 0x05, 0x7e, 0xef, 0x9d, 0x0c, 0x79, 0xe8, 0x9a, 0x0b,
    0x6c, 0xfd, 0x8f, 0x1e, 0x6b, 0xfa, 0x88, 0x19, 0x62, 0xf3, 0x81, 0x10, 0x65, 0xf4, 0x86, 0x17,
    0x48, 0xd9, 0xab, 0x3a, 0x4f, 0xde, 0xac, 0x3d, 0x46, 0xd7, 0xa5, 0x34, 0x41, 0xd0, 0xa2, 0x33,
    0x54, 0xc5, 0xb7, 0x26, 0x53, 0xc2, 0xb0, 0x21, 0x5a, 0xcb, 0xb9, 0x28, 0x5d, 0xcc, 0xbe, 0x2f,
    0xe0, 0x71, 0x03, 0x92, 0xe7, 0x76, 0x04, 0x95, 0xee, 0x7f, 0x0d, 0x9c, 0xe9, 0x78, 0x0a, 0x9b,
    0xfc, 0x6d, 0x1f, 0x8e, 0xfb, 0x6a, 0x18, 0x89, 0xf2, 0x63, 0x11, 0x80, 0xf5, 0x64, 0x16, 0x87,
    0xd8, 0x49, 0x3b, 0xaa, 0xdf, 0x4e, 0x3c, 0xad, 0xd6, 0x47, 0x35, 0xa4, 0xd1, 0x40, 0x32, 0xa3,
    0xc4, 0x55, 0x27, 0xb6, 0xc3, 0x52, 0x20, 0xb1, 0xca, 0x5b, 0x29, 0xb8, 0xcd, 0x5c, 0x2e, 0xbf,
    0x90, 0x01, 0x73, 0xe2, 0x97, 0x06, 0x74, 0xe5, 0x9e, 0x0f, 0x7d, 0xec, 0x99, 0x08, 0x7a, 0xeb,
    0x8c, 0x1d, 0x6f, 0xfe, 0x8b, 0x1a, 0x68, 0xf9, 0x82, 0x13, 0x61, 0xf0, 0x85, 0x14, 0x66, 0xf7,
    0xa8, 0x39, 0x4b, 0xda, 0xaf, 0x3e, 0x4c, 0xdd, 0xa6, 0x37, 0x45, 0xd4, 0xa1, 0x30, 0x42, 0xd3,
    0xb4, 0x25, 0x57, 0xc6, 0xb3, 0x22, 0x50, 0xc1, 0xba, 0x2b, 0x59, 0xc8, 0xbd, 0x2c, 0x5e, 0xcf,
];

pub fn fcs_calc(data: &[u8]) -> FCS {
    let mut fcs = 0xFF;
    for &b in data {
        fcs = FCS_TABLE[usize::from(fcs ^ b)]
    }
    FCS(fcs)
}
pub fn fcs_check(fcs: FCS, data: &[u8]) -> bool {
    let mut fcs_check = 0xFF;
    for &b in data {
        fcs_check = FCS_TABLE[usize::from(fcs_check ^ b)]
    }
    FCS_TABLE[usize::from(fcs_check ^ fcs.0)] == 0xCF
}
const START_PDU_HEADER_SIZE: u16 = 4;
const ACK_PDU_HEADER_SIZE: u16 = 1;
const CONTINUATION_PDU_SIZE: u16 = 1;
impl TransactionStartPDU {
    pub fn calculate_seg_n(data_len: u16, max_mtu: MTU) -> SegmentIndex {
        let mtu = u16::from(max_mtu.0);
        let total_len = data_len + START_PDU_HEADER_SIZE + ACK_PDU_HEADER_SIZE;
        let mut seg_i = total_len / mtu;
        if seg_i * mtu < total_len {
            seg_i += 1;
        }
        SegmentIndex::new(u8::try_from(seg_i).expect("segment index overflow"))
    }
    pub fn new(seg_n: SegmentIndex, length: u16, fcs: FCS) -> Self {
        Self {
            seg_n,
            total_length: length,
            fcs,
        }
    }
    /// Calculates fcs and total length on the `data`. Uses `max_mtu` to calculate `seg_n`.
    /// The returned PDU !DOES NOT! have any data attached to it. Data is contained in the
    /// `Payload` field of `PDU`.
    pub fn from_data(data: &[u8], max_mtu: MTU) -> TransactionStartPDU {
        let data_len = u16::try_from(data.len()).expect("data.len() must fit in a u16");

        Self::new(
            Self::calculate_seg_n(data_len, max_mtu),
            data_len,
            fcs_calc(data),
        )
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub struct TransactionContinuationPDU {
    pub seg_i: SegmentIndex,
}
impl TransactionContinuationPDU {
    pub fn new(seg_i: SegmentIndex) -> Self {
        Self { seg_i }
    }
    pub fn as_u8(&self) -> u8 {
        GPCF::TransactionContinuation.pack_with(self.seg_i.0)
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub enum Control {
    TransactionStart(TransactionStartPDU),
    TransactionContinuation(TransactionContinuationPDU),
    TransactionAcknowledgement(TransactionAcknowledgmentPDU),
    BearerControl(bearer_control::PDU),
}
pub struct PDU<Storage: AsRef<[u8]>> {
    control: Control,
    payload: Option<Storage>,
}
impl<Storage: AsRef<[u8]> + Clone> Clone for PDU<Storage> {
    fn clone(&self) -> Self {
        Self {
            control: self.control,
            payload: self.payload.clone(),
        }
    }
}
pub struct SegmentGenerator<'a> {
    data: &'a [u8],
    fcs: FCS,
}
