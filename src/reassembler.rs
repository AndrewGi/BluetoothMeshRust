//! Transport Layer Reassembler.
use crate::crypto::aes::MicSize;
use crate::crypto::MIC;
use crate::lower::{BlockAck, SegN, SegO, SegmentedAccessPDU, SegmentedControlPDU};

use alloc::vec::Vec;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum ReassembleError {
    SegmentAlreadyInserted,
    DataTooLong,
    SegmentOutOfBounds,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct ContextHeader {
    szmic: Option<bool>,
    seg_o: SegO,
    block_ack: BlockAck,
}
impl ContextHeader {
    pub fn new(seg_o: SegO, szmic: Option<bool>) -> Self {
        Self {
            seg_o,
            szmic,
            block_ack: Default::default(),
        }
    }
    #[must_use]
    pub fn all_acked(&self) -> bool {
        self.block_ack.all_acked(self.seg_o)
    }
    #[must_use]
    pub fn is_control(&self) -> bool {
        self.szmic.is_none()
    }
    #[must_use]
    pub fn is_access(&self) -> bool {
        self.szmic.is_some()
    }
    #[must_use]
    pub fn seg_o(&self) -> SegO {
        self.seg_o
    }
    #[must_use]
    pub fn seg_count(&self) -> usize {
        usize::from(u8::from(self.seg_o)) + 1usize
    }
    #[must_use]
    pub const fn block_ack(&self) -> BlockAck {
        self.block_ack
    }
    #[must_use]
    pub fn max_seg_len(&self) -> usize {
        if self.is_control() {
            SegmentedControlPDU::max_seg_len()
        } else {
            SegmentedAccessPDU::max_seg_len()
        }
    }
    #[must_use]
    pub fn seg_pos(&self, seg_n: SegN) -> Option<usize> {
        let pos = usize::from(u8::from(seg_n)) * self.max_seg_len();
        if pos > self.max_len() {
            None
        } else {
            Some(pos)
        }
    }
    #[must_use]
    pub fn max_len(&self) -> usize {
        self.max_seg_len() * self.seg_count()
    }
    #[must_use]
    pub fn mic_size(&self) -> Option<MicSize> {
        if self.szmic? {
            Some(MicSize::Big)
        } else {
            Some(MicSize::Small)
        }
    }
    #[must_use]
    pub fn mic_size_bytes(&self) -> usize {
        self.mic_size().map(MicSize::byte_size).unwrap_or(0)
    }
}
pub struct Context {
    storage: Vec<u8>,
    data_len: usize,
    header: ContextHeader,
}
impl Context {
    pub fn new(header: ContextHeader) -> Self {
        let mut storage = Vec::with_capacity(header.max_len());
        storage.resize_with(header.max_len(), u8::default);
        Self {
            storage,
            data_len: 0,
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
    pub fn header(&self) -> ContextHeader {
        self.header
    }
    pub fn mic_size(&self) -> Option<MicSize> {
        if self.header.szmic? {
            Some(MicSize::Big)
        } else {
            Some(MicSize::Small)
        }
    }
    pub fn mic(&self) -> Option<MIC> {
        if !self.is_ready() {
            None
        } else {
            Some(
                MIC::try_from_bytes_le(
                    &self.data()[self.data_len..][..self.mic_size()?.byte_size()],
                )
                .expect("MIC should be here"),
            )
        }
    }
    pub fn insert_data(&mut self, seg_n: SegN, data: &[u8]) -> Result<(), ReassembleError> {
        if data.len() > self.header.max_seg_len() {
            Err(ReassembleError::DataTooLong)
        } else {
            let pos = self
                .header
                .seg_pos(seg_n)
                .ok_or(ReassembleError::SegmentOutOfBounds)?;
            self.storage[pos..pos + data.len()].copy_from_slice(data);
            self.header.block_ack.set(seg_n.into());
            if u8::from(seg_n) == u8::from(self.header.seg_o) {
                // Last Seg
                self.data_len = pos + data.len() - self.header.mic_size_bytes();
            }
            Ok(())
        }
    }
}
