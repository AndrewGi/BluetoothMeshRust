use crate::address::Address;
use crate::crypto::MIC;
use crate::lower::{BlockAck, SegN, SegO, SegmentHeader, SegmentedAccessPDU, SeqZero};
use crate::mesh::{IVIndex, NetKeyIndex, SequenceNumber, TTL};
use crate::{lower, upper};
use alloc::boxed::Box;
use core::cmp::min;

pub(crate) struct Segmenter<Storage: AsRef<[u8]>> {
    pub upper_pdu: upper::UpperPDU<Storage>,
    seg_o: SegO,
    seq_zero: SeqZero,
}
impl<Storage: AsRef<[u8]>> Segmenter<Storage> {
    pub fn new(upper_pdu: upper::UpperPDU<Storage>, seq_zero: SeqZero) -> Self {
        Self {
            seg_o: upper_pdu.seg_o(),
            upper_pdu,
            seq_zero,
        }
    }
    pub fn iter(&self, block_ack: BlockAck) -> SegmentIterator<Storage> {
        SegmentIterator {
            block_ack,
            segmenter: self,
            seg_n: 0,
        }
    }
    pub fn seg_count(&self) -> u8 {
        u8::from(self.seg_o) + 1
    }
}
pub struct SegmentIterator<'a, Storage: AsRef<[u8]>> {
    block_ack: BlockAck,
    segmenter: &'a Segmenter<Storage>,
    seg_n: u8,
}
impl<'a, Storage: AsRef<[u8]>> SegmentIterator<'a, Storage> {
    pub fn segment_header(&self) -> SegmentHeader {
        let flag = self
            .segmenter
            .upper_pdu
            .mic
            .map(|mic| mic.is_big())
            .unwrap_or(false);
        SegmentHeader::new(
            flag,
            self.segmenter.seq_zero,
            self.segmenter.seg_o,
            SegN::new(self.seg_n),
        )
    }
}
impl<'a, Storage: AsRef<[u8]>> Iterator for SegmentIterator<'a, Storage> {
    type Item = lower::SegmentedPDU;

    fn next(&mut self) -> Option<Self::Item> {
        // Skip acked segments.
        while self.block_ack.get(self.seg_n) && self.seg_n < u8::from(self.segmenter.seg_o) {
            self.seg_n += 1;
        }
        if self.seg_n > u8::from(self.segmenter.seg_o) {
            None
        } else {
            let seg_n_out = SegN::new(self.seg_n);
            let segment_data = self.segmenter.upper_pdu.seg_n_data(seg_n_out);
            let header = self.segment_header();
            match self.segmenter.upper_pdu.opcode {
                Some(opcode) => {
                    // ControlPDU
                    let out = lower::SegmentedControlPDU::new(opcode, header, segment_data);
                    self.seg_n += 1;
                    Some(lower::SegmentedPDU::Control(out))
                }
                None => {
                    if segment_data.len() != SegmentedAccessPDU::max_seg_len() {
                        let mic = self
                            .segmenter
                            .upper_pdu
                            .mic
                            .expect("all access PDUs have MIC");
                        let seg_len = segment_data.len();
                        let mut buf = [0_u8; SegmentedAccessPDU::max_seg_len() + MIC::big_size()];
                        buf[..seg_len].copy_from_slice(segment_data);
                        mic.be_pack_into(&mut buf[seg_len..seg_len + mic.byte_size()]);
                        let out = lower::SegmentedAccessPDU::new(
                            self.segmenter.upper_pdu.aid,
                            self.segmenter.upper_pdu.szmic().into(),
                            self.segmenter.seq_zero,
                            self.segmenter.seg_o,
                            seg_n_out,
                            &buf[..min(
                                seg_len + mic.byte_size(),
                                SegmentedAccessPDU::max_seg_len(),
                            )],
                        );
                        self.seg_n += 1;
                        Some(lower::SegmentedPDU::Access(out))
                    } else {
                        let out = lower::SegmentedAccessPDU::new(
                            self.segmenter.upper_pdu.aid,
                            self.segmenter.upper_pdu.szmic().into(),
                            self.segmenter.seq_zero,
                            self.segmenter.seg_o,
                            seg_n_out,
                            segment_data,
                        );
                        self.seg_n += 1;
                        Some(lower::SegmentedPDU::Access(out))
                    }
                }
            }
        }
    }
}
