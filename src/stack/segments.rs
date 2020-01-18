use crate::address::Address;
use crate::{segmenter, timestamp};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;

pub struct OutgoingSegments {
    segments: segmenter::UpperSegmenter<Box<[u8]>>,
    last_ack: timestamp::Timestamp,
}
pub struct IncomingSegments {}
pub struct Segments {
    outgoing: BTreeMap<Address, OutgoingSegments>,
    incoming: BTreeMap<Address, IncomingSegments>,
}
