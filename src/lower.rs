use crate::crypto::{AID, AKF};
use crate::mesh::{CTL, U24};
use core::convert::TryFrom;

#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SZMIC(bool);
//13 Bits SeqZero
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SeqZero(u16);
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SegO(u8);
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SegN(u8);
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct BlockAck(u32);
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
    /// Returns if the block ack (up to `seg_n` bits) is all 1s. False if otherwise
    #[must_use]
    pub fn all_acked(self, seg_n: SegN) -> bool {
        self.0 == (1_u32 << u32::from(seg_n.0)).wrapping_sub(1)
    }
}
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SEG(bool);
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
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SegmentHeader {
    flag: bool,
    seq_zero: SeqZero,
    seg_o: SegO,
    seg_n: SegN,
}
impl SegmentHeader {
    #[must_use]
    pub fn pack_into_u24(self) -> U24 {
        unimplemented!();
    }
}
/// 7 Bit Control Opcode
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[repr(u8)]
pub enum ControlOpcode {
    SegmentAck = 0x00,
}
impl ControlOpcode {}
/// Lower Transport PDU
/// | CTL | SEG | Format				|
/// |  0  |  0  | Unsegmented Access	|
/// |  0  |  1  | Segmented Access		|
/// |  1  |  0  | Unsegmented Control	|
/// |  1  |  1  | Segmented Control		|
///
///
const UNSEGMENTED_ACCESS_PDU_LEN: usize = 15;
pub struct UnsegmentedAccessPDU {
    akf: AKF,
    aid: AID,
    access_pdu_buf: [u8; UNSEGMENTED_ACCESS_PDU_LEN],
    access_pdu_len: u8,
}
impl UnsegmentedAccessPDU {
    /// # Panics
    /// Panics if `data.len() > UNSEGMENTED_ACCESS_PDU_LEN` (15)
    pub fn new(akf: AKF, aid: AID, data: &[u8]) -> UnsegmentedAccessPDU {
        assert!(data.len() <= UNSEGMENTED_ACCESS_PDU_LEN);
        // If the assert passes, data.len() should fit in a u8.
        let len = u8::try_from(data.len()).unwrap();
        let buf = [0_u8; UNSEGMENTED_ACCESS_PDU_LEN];
        UnsegmentedAccessPDU {
            akf,
            aid,
            access_pdu_buf: buf,
            access_pdu_len: len,
        }
    }
    #[must_use]
    pub fn to_bytes(&self) -> PDUBytes {
        unimplemented!()
    }
    #[must_use]
    pub fn from_bytes(bytes: PDUBytes) -> Self {
        unimplemented!()
    }
}
pub struct SegmentedAccessPDU {}

impl SegmentedAccessPDU {
    #[must_use]
    pub fn to_bytes(&self) -> PDUBytes {
        unimplemented!()
    }
    #[must_use]
    pub fn from_bytes(bytes: PDUBytes) -> Self {
        unimplemented!()
    }
}

const UNSEGMENTED_CONTROL_PDU_LEN: usize = 11;
pub struct UnsegmentedControlPDU {
    parameters_buf: [u8; UNSEGMENTED_CONTROL_PDU_LEN],
    parameters_len: u8,
    opcode: ControlOpcode,
}
impl UnsegmentedControlPDU {
    #[must_use]
    pub fn new(opcode: ControlOpcode, parameters: &[u8]) -> UnsegmentedControlPDU {
        assert!(
            parameters.len() <= UNSEGMENTED_CONTROL_PDU_LEN,
            "parameter overflow ({} > {})",
            parameters.len(),
            UNSEGMENTED_CONTROL_PDU_LEN
        );
        let mut buf = [0_u8; UNSEGMENTED_CONTROL_PDU_LEN];
        buf[..parameters.len()].copy_from_slice(parameters);
        UnsegmentedControlPDU {
            parameters_buf: buf,
            parameters_len: parameters.len() as u8,
            opcode,
        }
    }
    #[must_use]
    pub const fn parameters_len(&self) -> usize {
        self.parameters_len as usize
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
    #[must_use]
    pub fn to_bytes(&self) -> PDUBytes {
        unimplemented!()
    }
    #[must_use]
    pub fn from_bytes(bytes: PDUBytes) -> Self {
        unimplemented!()
    }
}
/// Segmented Control PDU Lengths
/// | # Packets  | PDU Size |
/// |      1     |     8    |
/// |      2     |    16    |
/// |      3     |    24    |
/// |      n     |    n*8   |
/// |     32     |    256   |
const MAX_SEGMENTED_CONTROL_PDU_LEN: usize = 8;
pub struct SegmentedControlPDU {
    opcode: ControlOpcode,
    segment_header: SegmentHeader,
    segment_buf: [u8; MAX_SEGMENTED_CONTROL_PDU_LEN],
    segment_buf_len: u8,
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
            segment_buf_len: data.len() as u8,
        }
    }
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.segment_buf_len)
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    #[must_use]
    pub fn segment_data(&self) -> &[u8] {
        &self.segment_buf[..self.len()]
    }
    #[must_use]
    pub fn segment_data_mut(&mut self) -> &mut [u8] {
        let l = self.len();
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
    pub fn to_bytes(&self) -> PDUBytes {
        unimplemented!()
    }
    #[must_use]
    pub fn from_bytes(bytes: PDUBytes) -> Self {
        unimplemented!()
    }
}
pub struct SegmentAckPDU {
    seq_zero: SeqZero,
    block_ack: BlockAck,
    obo: OBO,
}
impl SegmentAckPDU {
    #[must_use]
    pub const fn opcode() -> ControlOpcode {
        ControlOpcode::SegmentAck
    }
}
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
    /// Number of bytes required to hold any serialized `Lower::PDU` in a byte buffer.
    pub const fn max_len() -> usize {
        16
    }
    pub fn to_bytes(&self) -> PDUBytes {
        match self {
            PDU::UnsegmentedAccess(p) => p.to_bytes(),
            PDU::SegmentedAccess(p) => p.to_bytes(),
            PDU::UnsegmentedControl(p) => p.to_bytes(),
            PDU::SegmentedControl(p) => p.to_bytes(),
        }
    }
    pub fn from_bytes(bytes: PDUBytes, ctl: CTL) -> Self {
        match (bool::from(ctl), bool::from(bytes.seg())) {
            (true, true) => PDU::SegmentedControl(SegmentedControlPDU::from_bytes(bytes)),
            (true, false) => PDU::UnsegmentedControl(UnsegmentedControlPDU::from_bytes(bytes)),
            (false, false) => PDU::UnsegmentedAccess(UnsegmentedAccessPDU::from_bytes(bytes)),
            (false, true) => PDU::SegmentedAccess(SegmentedAccessPDU::from_bytes(bytes)),
        }
    }
}
pub struct PDUBytes {
    buf: [u8; PDU::max_len()],
    buf_len: usize,
}
impl PDUBytes {
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
