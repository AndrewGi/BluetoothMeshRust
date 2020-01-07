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
pub struct TransactionStartPDU {
    seg_n: SegmentIndex,
    total_length: u16,
    fcs: FCS,
}
/// FCS 3GPP TS 27.010
/// Polynomial x^8 x^2 + x +1
pub fn fcs(data: &[u8]) -> FCS {
    todo!("implement fcs with polynomial x^8 + x^2 + x + 1")
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
    /// The returned PDU !DOES NOT! have any data attachted to it. Data is contained in the
    /// `Payload` field of `PDU`.
    pub fn from_data(data: &[u8], max_mtu: MTU) -> TransactionStartPDU {
        let data_len = u16::try_from(data.len()).expect("data.len() must fit in a u16");

        Self::new(
            Self::calculate_seg_n(data_len, max_mtu),
            data_len,
            fcs(data),
        )
    }
}
pub struct TransactionContinuationPDU {
    seg_i: SegmentIndex,
}
impl TransactionContinuationPDU {
    pub fn new(seg_i: SegmentIndex) -> Self {
        Self { seg_i }
    }
    pub fn as_u8(&self) -> u8 {
        GPCF::TransactionContinuation.pack_with(self.seg_i.0)
    }
}

pub enum Control {
    TransactionStart(TransactionStartPDU),
    TransactionContinuation(TransactionContinuationPDU),
    TransactionAcknowledgement(TransactionAcknowledgmentPDU),
    BearerControl(bearer_control::PDU),
}
pub struct Payload {}
pub struct PDU {
    control: Control,
    payload: Payload,
}
