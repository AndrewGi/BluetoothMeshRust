use super::bearer_control;
/// 6 bit Segment Number
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct SegmentIndex(u8);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct FCS(u8);

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
    unimplemented!("implement fcs with polynomial x^8 + x^2 + x + 1")
}
impl TransactionStartPDU {
    pub fn new(seg_n: SegmentIndex, length: u16, fcs: FCS) -> Self {
        Self {
            seg_n,
            total_length: length,
            fcs,
        }
    }
    pub fn from_data(data: &[u8]) -> TransactionStartPDU {
        unimplemented!()
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
