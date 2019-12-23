use crate::transport::{BlockAck, SegN};

pub struct SegmentsContext {
    is_control: bool,
    seg_n: SegN,
    block_ack: BlockAck,
}
impl SegmentsContext {
    #[must_use]
    pub fn all_acked(&self) -> bool {
        self.block_ack.all_acked(self.seg_n)
    }
    #[must_use]
    pub const fn is_control(&self) -> bool {
        self.is_control
    }
    #[must_use]
    pub const fn is_access(&self) -> bool {
        !self.is_control
    }
    #[must_use]
    pub const fn seg_n(&self) -> SegN {
        self.seg_n
    }
    #[must_use]
    pub const fn block_ack(&self) -> BlockAck {
        self.block_ack
    }
}
