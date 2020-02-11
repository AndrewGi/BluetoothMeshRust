use crate::address::{Address, UnicastAddress};
use crate::control::ControlMessage;
use crate::lower::{SegmentedPDU, SeqZero};
use crate::mesh::{IVIndex, NetKeyIndex, SequenceNumber};
use crate::reassembler::LowerHeader;
use crate::stack::messages::{IncomingNetworkPDU, IncomingTransportPDU};
use crate::{control, lower, reassembler, segmenter, timestamp};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use core::convert::{TryFrom, TryInto};
use core::time::Duration;
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
    src: UnicastAddress,
    dst: Address,
    iv_index: IVIndex,
    net_key_index: NetKeyIndex,
}
impl IncomingSegments {
    pub fn new(first_seg: IncomingPDU<lower::SegmentedPDU>) -> Option<Self> {
        let seg_header = first_seg.pdu.segment_header();
        if u8::from(seg_header.seg_n) != 0 {
            None
        } else {
            let lower_header = match first_seg.pdu {
                SegmentedPDU::Access(a) => LowerHeader::AID(a.aid()),
                SegmentedPDU::Control(c) => LowerHeader::ControlOpcode(c.opcode()),
            };
            Some(IncomingSegments {
                context: reassembler::Context::new(reassembler::ContextHeader::new(
                    lower_header,
                    seg_header.seg_o,
                    first_seg.pdu.szmic().unwrap_or(false),
                )),
                src: first_seg.src,
                dst: first_seg.dst,
                iv_index: first_seg.iv_index,
                net_key_index: first_seg.net_key_index,
            })
        }
    }
    pub const fn recv_timeout(&self) -> Duration {
        // As Per the Bluetooth Mesh Spec.
        Duration::from_secs(10)
    }
    pub fn is_control(&self) -> bool {
        !self.is_access()
    }
    pub fn is_access(&self) -> bool {
        self.context.header().lower_header().is_access()
    }
    pub fn is_ready(&self) -> bool {
        self.context.is_ready()
    }
    pub fn seq(&self) -> SequenceNumber {
        unimplemented!()
    }
    pub fn finish(self) -> Result<IncomingTransportPDU<Box<[u8]>>, Self> {
        if !self.is_ready() {
            Err(self)
        } else {
            let seq = self.seq();
            Ok(IncomingTransportPDU {
                upper_pdu: self.context.finish().expect("context is ensured ready"),
                iv_index: self.iv_index,
                seg_count: 0,
                seq,
                net_key_index: self.net_key_index,
                ttl: None,
                rssi: None,
                src: self.src,
                dst: self.dst,
            })
        }
    }
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

mod async_segs {
    use crate::address::UnicastAddress;
    use crate::lower;
    use crate::lower::SeqZero;
    use crate::reassembler;
    use crate::stack::messages::IncomingTransportPDU;
    use crate::stack::segments::{IncomingPDU, IncomingSegments};
    use alloc::collections::BTreeMap;
    use std::collections::btree_map::Entry;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;

    pub struct ReassemblerContext {
        sender: mpsc::Sender<IncomingPDU<lower::SegmentedPDU>>,
    }
    pub struct ReassemblerHandle {
        pub src: UnicastAddress,
        pub seq_zero: SeqZero,
        pub sender: mpsc::Sender<IncomingPDU<lower::SegmentedPDU>>,
        pub handle: JoinHandle<Result<IncomingTransportPDU<Box<[u8]>>, ReassemblyError>>,
    }
    pub struct Reassembler {
        incoming_channels: BTreeMap<(UnicastAddress, lower::SeqZero), ReassemblerContext>,
    }
    pub enum ReassemblyError {
        Timeout,
        InvalidFirstSegment,
        ChannelClosed,
        Reassemble(reassembler::ReassembleError),
    }
    pub const REASSEMBLER_CHANNEL_LEN: usize = 8;
    impl Reassembler {
        pub fn new() -> Self {
            Self {
                incoming_channels: BTreeMap::new(),
            }
        }
        pub fn reassemble(
            &mut self,
            first_seg: IncomingPDU<lower::SegmentedPDU>,
        ) -> Option<ReassemblerHandle> {
            let src = (first_seg.src, first_seg.pdu.seq_zero());
            let entry = self.incoming_channels.entry(src);
            match entry {
                Entry::Vacant(v) => {
                    let (tx, rx) = mpsc::channel(REASSEMBLER_CHANNEL_LEN);
                    let handle = tokio::spawn(Self::reassemble_segs(first_seg, rx));
                    v.insert(ReassemblerContext { sender: tx.clone() });
                    Some(ReassemblerHandle {
                        src: src.0,
                        seq_zero: src.1,
                        sender: tx,
                        handle,
                    })
                }
                Entry::Occupied(_) => None,
            }
        }
        async fn reassemble_segs(
            first_seg: IncomingPDU<lower::SegmentedPDU>,
            mut rx: mpsc::Receiver<IncomingPDU<lower::SegmentedPDU>>,
        ) -> Result<IncomingTransportPDU<Box<[u8]>>, ReassemblyError> {
            let mut segments =
                IncomingSegments::new(first_seg).ok_or(ReassemblyError::InvalidFirstSegment)?;
            while !segments.is_ready() {
                let next = tokio::time::timeout(segments.recv_timeout(), rx.recv())
                    .await
                    .map_err(|_| ReassemblyError::Timeout)?
                    .ok_or(ReassemblyError::ChannelClosed)?;
                let seg_header = next.pdu.segment_header();
                segments
                    .context
                    .insert_data(seg_header.seg_n, next.pdu.seg_data())
                    .map_err(ReassemblyError::Reassemble)?;
            }
            match segments.finish() {
                Ok(msg) => Ok(msg),
                Err(_) => unreachable!("segments is ensured to be is_ready() by the loop above"),
            }
        }
    }
}
