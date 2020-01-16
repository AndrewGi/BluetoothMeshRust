//! Transport Layer Reassembler.
use crate::lower::{BlockAck, SegO};
use alloc::boxed::Box;

pub struct ContextHeader {
    is_control: bool,
    seg_n: SegO,
    block_ack: BlockAck,
}
impl ContextHeader {
    pub fn new(seg_n: SegO, is_control: bool) -> Self {
        Self {
            is_control,
            seg_n,
            block_ack: Default::default(),
        }
    }
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
    pub const fn seg_n(&self) -> SegO {
        self.seg_n
    }
    #[must_use]
    pub const fn block_ack(&self) -> BlockAck {
        self.block_ack
    }
}
pub struct Context {
    storage: Box<[u8]>,
    header: ContextHeader,
}
impl Context {
    pub fn new(header: ContextHeader) -> Self {
        Self {
            storage: Box::new([]),
            header,
        }
    }
}
impl Context {
    pub fn data(&self) -> &[u8] {
        self.storage.as_ref()
    }
    pub fn is_ready(&self) -> bool {
        self.header.all_acked()
    }
}
