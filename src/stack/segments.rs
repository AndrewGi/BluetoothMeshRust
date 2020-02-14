use crate::address::{Address, UnicastAddress};
use crate::control::ControlMessage;
use crate::lower::{BlockAck, SegmentedPDU, SeqAuth, SeqZero};
use crate::mesh::{IVIndex, NetKeyIndex, SequenceNumber, TTL};
use crate::reassembler;
use crate::reassembler::LowerHeader;
use crate::stack::messages::{IncomingNetworkPDU, IncomingTransportPDU, OutgoingTransportMessage};
use crate::{control, lower, segmenter, timestamp};
use alloc::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::fmt::{Debug, Error, Formatter};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

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
    seq_auth: SeqAuth,
    src: UnicastAddress,
    dst: Address,
    net_key_index: NetKeyIndex,
    ack_ttl: Option<TTL>,
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
                seq_auth: SeqAuth::from_seq_zero(
                    first_seg.pdu.seq_zero(),
                    first_seg.seq,
                    first_seg.iv_index,
                ),
                net_key_index: first_seg.net_key_index,
                ack_ttl: if u8::from(first_seg.ttl) == 0u8 {
                    Some(TTL::new(0))
                } else {
                    None
                },
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

    pub fn seq_auth(&self) -> SeqAuth {
        self.seq_auth
    }
    pub fn finish(self) -> Result<IncomingTransportPDU<Box<[u8]>>, Self> {
        if !self.is_ready() {
            Err(self)
        } else {
            let seq_auth = self.seq_auth();
            Ok(IncomingTransportPDU {
                upper_pdu: self.context.finish().expect("context is ensured ready"),
                iv_index: seq_auth.iv_index,
                seg_count: 0,
                seq: seq_auth.first_seq,
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
                seq: pdu.pdu.header.seq,
                iv_index: pdu.iv_index,
                src: pdu.pdu.header.src,
                dst: pdu.pdu.header.dst,
                net_key_index: pdu.net_key_index,
                ttl: pdu.pdu.header.ttl,
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
                ttl: pdu.pdu.header.ttl,
                seq: pdu.pdu.header.seq,
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
    pub seq: SequenceNumber,
    pub iv_index: IVIndex,
    pub net_key_index: NetKeyIndex,
    pub src: UnicastAddress,
    pub dst: Address,
    pub ttl: TTL,
}
impl<PDU: Copy + Clone + Debug> Debug for &IncomingPDU<PDU> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.debug_struct("IncomingPDU")
            .field("pdu", &self.pdu)
            .field("iv_index", &self.iv_index)
            .field("net_key_index", &self.net_key_index)
            .field("src", &self.src)
            .field("dst", &self.dst)
            .finish()
    }
}
#[derive(Copy, Clone, Debug)]
pub enum SegmentEvent {
    IncomingSegment(IncomingPDU<lower::SegmentedPDU>),
    IncomingAck(IncomingPDU<control::Ack>),
}
pub struct Segments {
    outgoing_pdus: mpsc::Sender<OutgoingTransportMessage>,
    finished_pdus: mpsc::Sender<IncomingTransportPDU<Box<[u8]>>>,
    incoming_events_rx: mpsc::Receiver<SegmentEvent>,
    incoming_events_tx: mpsc::Sender<SegmentEvent>,
    outgoing: VecDeque<OutgoingSegments>,
    reassembler: Reassembler,
}
impl Segments {
    pub async fn feed_event(&mut self, event: SegmentEvent) {
        self.incoming_events_tx
            .send(event)
            .await
            .expect("channel closed")
    }
    pub fn incoming_events(&self) -> &mpsc::Sender<SegmentEvent> {
        &self.incoming_events_tx
    }
    pub async fn handle_ack(
        &mut self,
        _ack: IncomingPDU<control::Ack>,
    ) -> Result<(), ReassemblyError> {
        unimplemented!()
    }
    pub async fn handle_segment(
        &mut self,
        segment: IncomingPDU<lower::SegmentedPDU>,
    ) -> Result<(), ReassemblyError> {
        let _maybe_new_message = self.reassembler.feed_pdu(segment).await?;
        Ok(())
    }
    pub async fn handle_event(&mut self, event: SegmentEvent) -> Result<(), ReassemblyError> {
        match event {
            SegmentEvent::IncomingSegment(seg) => self.handle_segment(seg).await,
            SegmentEvent::IncomingAck(ack) => self.handle_ack(ack).await,
        }
    }
    pub fn new(
        channel_capacity: usize,
        outgoing_pdus: mpsc::Sender<OutgoingTransportMessage>,
        finished_pdus: mpsc::Sender<IncomingTransportPDU<Box<[u8]>>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(channel_capacity);
        Self {
            outgoing_pdus: outgoing_pdus.clone(),
            finished_pdus,
            incoming_events_tx: tx,
            incoming_events_rx: rx,
            outgoing: VecDeque::default(),
            reassembler: Reassembler::new(outgoing_pdus),
        }
    }
}

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
    outgoing_pdus: mpsc::Sender<OutgoingTransportMessage>,
}
pub enum ReassemblyError {
    Canceled,
    Timeout,
    InvalidFirstSegment,
    ChannelClosed,
    Reassemble(reassembler::ReassembleError),
}
pub const REASSEMBLER_CHANNEL_LEN: usize = 8;
impl Reassembler {
    pub fn new(outgoing_pdus: mpsc::Sender<OutgoingTransportMessage>) -> Self {
        Self {
            incoming_channels: BTreeMap::new(),
            outgoing_pdus,
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
                let handle = tokio::spawn(Self::reassemble_segs(
                    first_seg,
                    self.outgoing_pdus.clone(),
                    rx,
                ));
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
    pub async fn feed_pdu(
        &mut self,
        pdu: IncomingPDU<lower::SegmentedPDU>,
    ) -> Result<Option<ReassemblerHandle>, ReassemblyError> {
        match self
            .incoming_channels
            .get_mut(&(pdu.src, pdu.pdu.seq_zero()))
        {
            Some(context) => match context.sender.send(pdu).await {
                Ok(_) => Ok(None),
                Err(_) => Err(ReassemblyError::ChannelClosed),
            },
            None => Ok(Some(
                self.reassemble(pdu)
                    .expect("guaranteed for the handle to not exists yet"),
            )),
        }
    }
    async fn send_ack(
        segs: &IncomingSegments,
        outgoing: &mut mpsc::Sender<OutgoingTransportMessage>,
        ack: BlockAck,
    ) -> Result<(), ReassemblyError> {
        outgoing
            .send(OutgoingTransportMessage {
                pdu: lower::PDU::UnsegmentedControl(
                    control::Ack {
                        obo: false,
                        seq_zero: segs.seq_auth.first_seq.into(),
                        block_ack: ack,
                    }
                    .try_to_unseg()
                    .expect("correctly formatted PDU"),
                ),
                src: segs.src,
                dst: segs.dst,
                ttl: segs.ack_ttl,
                seq: None,
                iv_index: segs.seq_auth.iv_index,
                net_key_index: segs.net_key_index,
            })
            .await
            .ok()
            .ok_or(ReassemblyError::ChannelClosed)
    }
    async fn cancel_ack(
        segs: &IncomingSegments,
        outgoing: &mut mpsc::Sender<OutgoingTransportMessage>,
    ) -> Result<(), ReassemblyError> {
        Self::send_ack(segs, outgoing, BlockAck::cancel()).await
    }
    async fn reassemble_segs(
        first_seg: IncomingPDU<lower::SegmentedPDU>,
        mut outgoing: mpsc::Sender<OutgoingTransportMessage>,
        mut rx: mpsc::Receiver<IncomingPDU<lower::SegmentedPDU>>,
    ) -> Result<IncomingTransportPDU<Box<[u8]>>, ReassemblyError> {
        let mut segments =
            IncomingSegments::new(first_seg).ok_or(ReassemblyError::InvalidFirstSegment)?;

        while !segments.is_ready() {
            let next = tokio::time::timeout(segments.recv_timeout(), rx.recv())
                .await
                .map_err(|_| ReassemblyError::Timeout)?
                .ok_or(ReassemblyError::ChannelClosed)?;
            if !segments.seq_auth.valid_seq(next.seq) {
                // cancel
                Self::cancel_ack(&segments, &mut outgoing).await?;
                return Err(ReassemblyError::Canceled);
            }
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
