use crate::mesh::{MIC, U24};

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
        (self.0) |= 1u32 << bit as u32;
    }
    /// Returns the bit status (1 or 0) of the `bit` bit. Returns `False` for bit > 32
    pub fn get(self, bit: u8) -> bool {
        debug_assert!(bit < 32, "{} index overflow into u32", bit);
        if bit >= 32 {
            false
        } else {
            (self.0 & (1u32 << bit as u32)) != 0
        }
    }
    /// Returns if the block ack (up to `seg_n` bits) is all 1s. False if otherwise
    pub fn all_acked(self, seg_n: SegN) -> bool {
        self.0 == (1u32 << (seg_n.0 as u32)).wrapping_sub(1)
    }
}
#[derive(Copy, Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SEG(bool);
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
    pub fn pack_into_u24(self) -> U24 {
        unimplemented!()
    }
}
/// 7 Bit Control Opcode
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

pub struct UnsegmentedAccessPDU {}
pub struct SegmentedAccessPDU {}
pub struct UnsegmentedControlPDU {
    parameters_buf: [u8; 11],
    parameters_len: u8,
    opcode: ControlOpcode,
}
impl UnsegmentedControlPDU {
    pub fn parameters_len(&self) -> usize {
        self.parameters_len as usize
    }
    pub fn data(&self) -> &[u8] {
        &self.parameters_buf[..self.parameters_len()]
    }
    pub fn data_mut(&mut self) -> &mut [u8] {
        let l = self.parameters_len();
        &mut self.parameters_buf[..l]
    }
    pub fn max_parameters_size() -> usize {
        11 // 0-88 Bits
    }
}
pub struct SegmentedControlPDU {
    opcode: ControlOpcode,
    segment_header: SegmentHeader,
}
pub struct SegmentAckPDU {
    seq_zero: SeqZero,
    block_ack: BlockAck,
    obo: OBO,
}
impl SegmentAckPDU {
    pub fn opcode() -> ControlOpcode {
        ControlOpcode::SegmentAck
    }
}
pub enum LowerPDU {
    UnsegmentedAccess(UnsegmentedAccessPDU),
    SegmentedAccess(SegmentedAccessPDU),
    UnsegmentedControl(UnsegmentedControlPDU),
    SegmentedControl(SegmentedControlPDU),
}
impl LowerPDU {
    pub fn is_seg(&self) -> bool {
        match self {
            LowerPDU::UnsegmentedAccess(_) => false,
            LowerPDU::SegmentedAccess(_) => true,
            LowerPDU::UnsegmentedControl(_) => false,
            LowerPDU::SegmentedControl(_) => true,
        }
    }
    pub fn is_control(&self) -> bool {
        match self {
            LowerPDU::UnsegmentedAccess(_) => false,
            LowerPDU::SegmentedAccess(_) => false,
            LowerPDU::UnsegmentedControl(_) => true,
            LowerPDU::SegmentedControl(_) => true,
        }
    }
}
pub struct UpperTransportPDU<'a> {
    encrypted_payload: &'a [u8],
    mic: MIC,
}
