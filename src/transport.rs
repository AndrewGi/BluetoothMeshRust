use crate::mesh::U24;

pub struct SZMIC(bool);
pub struct SeqZero(u16);
pub struct SegO(u8);
pub struct SegN(u8);

pub struct SEG(bool);

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

/// Lower Transport PDU
/// | CTL | SEG | Format				|
/// |  0  |  0  | Unsegmented Access	|
/// |  0  |  1  | Segmented Access		|
/// |  1  |  0  | Unsegmented Control	|
/// |  1  |  1  | Segmented Control		|
///
pub struct PDU {}

pub struct UnsegmentedAccessPDU {}
pub struct SegmentedAccessPDU {}
pub struct UnsegmentedControlPDU {}
pub struct SegmentedControlPDU {}
pub enum UpperPDU {
    UnsegmentedAccess(UnsegmentedAccessPDU),
    SegmentedAccess(SegmentedAccessPDU),
    UnsegmentedControl(UnsegmentedControlPDU),
    SegmentedControl(SegmentedControlPDU),
}
