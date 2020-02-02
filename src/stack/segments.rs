use crate::address::{Address, UnicastAddress};
use crate::control::ControlMessage;
use crate::lower::SeqZero;
use crate::mesh::{IVIndex, NetKeyIndex};
use crate::stack::messages::IncomingNetworkPDU;
use crate::{control, lower, reassembler, segmenter, timestamp};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use core::convert::{TryFrom, TryInto};
use std::sync::mpsc;

#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Hash, Debug)]
pub struct SegmentsConversionError(());

pub struct OutgoingSegments {
    segments: segmenter::UpperSegmenter<Box<[u8]>>,
    last_ack: timestamp::Timestamp,
    src: UnicastAddress,
    dst: Address,
}

pub struct IncomingSegments {
    context: reassembler::Context,
    iv_index: IVIndex,
    net_key_index: NetKeyIndex,
}

impl TryFrom<&IncomingNetworkPDU> for IncomingPDU<lower::SegmentedPDU> {
    type Error = SegmentsConversionError;

    fn try_from(pdu: &IncomingNetworkPDU) -> Result<Self, Self::Error> {
        match pdu.pdu.payload.segmented() {
            None => Err(SegmentsConversionError(())),
            Some(seg) => Ok(IncomingPDU {
                pdu: seg,
                iv_index: pdu.iv_index,
                src: pdu.pdu.header.src,
                dst: pdu.pdu.header.dst,
                net_key_index: pdu.net_key_index,
            }),
        }
    }
}
impl TryFrom<&IncomingNetworkPDU> for IncomingPDU<control::Ack> {
    type Error = SegmentsConversionError;

    fn try_from(pdu: &IncomingNetworkPDU) -> Result<Self, Self::Error> {
        match &pdu.pdu.payload {
            lower::PDU::UnsegmentedControl(control) => Ok(IncomingPDU {
                pdu: control::Ack::try_from_pdu(control)
                    .ok()
                    .ok_or(SegmentsConversionError(()))?,
                iv_index: pdu.iv_index,
                src: pdu.pdu.header.src,
                dst: pdu.pdu.header.dst,
                net_key_index: pdu.net_key_index,
            }),

            _ => Err(SegmentsConversionError(())),
        }
    }
}
impl TryFrom<&IncomingNetworkPDU> for SegmentEvent {
    type Error = SegmentsConversionError;

    fn try_from(pdu: &IncomingNetworkPDU) -> Result<Self, Self::Error> {
        if let Ok(lower) = IncomingPDU::try_from(pdu) {
            Ok(SegmentEvent::IncomingSegment(lower))
        } else {
            Ok(SegmentEvent::IncomingSegment(pdu.try_into()?))
        }
    }
}
#[derive(Copy, Clone)]
pub struct IncomingPDU<PDU: Copy + Clone> {
    pub pdu: PDU,
    pub iv_index: IVIndex,
    pub net_key_index: NetKeyIndex,
    pub src: UnicastAddress,
    pub dst: Address,
}
pub enum SegmentEvent {
    IncomingSegment(IncomingPDU<lower::SegmentedPDU>),
    IncomingAck(IncomingPDU<control::Ack>),
}
pub struct Segments {
    incoming_events_sink: mpsc::Sender<SegmentEvent>,
    incoming_events: mpsc::Receiver<SegmentEvent>,
    outgoing: VecDeque<OutgoingSegments>,
    incoming: BTreeMap<(UnicastAddress, SeqZero), IncomingSegments>,
}
impl Segments {
    pub fn feed_event(&self, event: SegmentEvent) {
        self.incoming_events_sink
            .send(event)
            .expect("segmenter feed failed")
    }
    pub fn handle_ack(&mut self, _ack: IncomingPDU<control::Ack>) {}
    pub fn handle_segment(&mut self, _segment: IncomingPDU<lower::SegmentedPDU>) {}
    pub fn handle_event(&mut self, event: SegmentEvent) {
        match event {
            SegmentEvent::IncomingSegment(seg) => self.handle_segment(seg),
            SegmentEvent::IncomingAck(ack) => self.handle_ack(ack),
        }
    }
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            incoming_events_sink: tx,
            incoming_events: rx,
            outgoing: Default::default(),
            incoming: Default::default(),
        }
    }
}
