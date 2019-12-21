use crate::transport::{BlockAck, SegN};

pub struct SegmentsContext {
    is_control: bool,
    seg_n: SegN,
    block_ack: BlockAck,
}
impl SegmentsContext {
    pub fn all_acked(&self) -> bool {
        self.block_ack.all_acked(self.seg_n)
    }
    pub fn is_control(&self) -> bool {
        self.is_control
    }
    pub fn is_access(&self) -> bool {
        !self.is_control
    }
    pub fn seg_n(&self) -> SegN {
        self.seg_n
    }
    pub fn block_ack(&self) -> BlockAck {
        self.block_ack
    }
}
