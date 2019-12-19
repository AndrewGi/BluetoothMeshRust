use crate::mesh::{MIC, U24};

pub struct SZMIC(bool);
pub struct SeqZero(u16);
pub struct SegO(u8);
pub struct SegN(u8);
pub struct BlockAck(u32);
pub struct SEG(bool);
pub struct OBO(bool);
pub struct SegmentHeader {
    flag: bool,
    seq_zero: SeqZero,
    seg_o: SegO,
    seg_n: SegN,
}
impl SegmentHeader {
    pub fn pack_into_u24(&self) -> U24 {
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
