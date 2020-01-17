use crate::address::{Address, UnicastAddress};
use crate::device_state::{SeqCounter, SeqRange};
use crate::lower::{BlockAck, SegO, SeqZero};
use crate::mesh::{IVIndex, NetKeyIndex, SequenceNumber, NID, TTL};
use crate::segmenter::SegmentIterator;
use crate::stack::StackInternals;
use crate::{lower, net, segmenter};
use alloc::boxed::Box;

pub struct Segments {
    upper_pdu: segmenter::Segmenter<Box<[u8]>>,
    seg_o: SegO,
    nid: NID,
    net_key_index: NetKeyIndex,
    iv_index: IVIndex,
    seq_zero: SequenceNumber,
    src: UnicastAddress,
    dst: Address,
    ttl: TTL,
    remote_block_ack: BlockAck,
}
impl Segments {
    pub fn network_header(&self, seq: SequenceNumber) -> net::Header {
        net::Header {
            ivi: self.iv_index.ivi(),
            nid: self.nid,
            ctl: self.upper_pdu.upper_pdu.is_control().into(),
            ttl: self.ttl,
            seq,
            src: self.src,
            dst: self.dst,
        }
    }
    /*
    pub fn network_pdu_iter<'a>(&self, seq: SeqRange) -> Option<NetworkPDUIterator<'a, Box<[u8]>>> {
        if seq.seqs_lefts() < u32::from(self.remote_block_ack.seg_left(self.seg_o)) {
            None
        } else {
            Some(NetworkPDUIterator {
                iter: self.upper_pdu.iter(self.remote_block_ack),
                segments: self,
                seq,
            })
        }
    }
    */
    /*
    pub fn encrypted_network_pdu_iter(
        &self,
        mut seq: SequenceNumber,
        stack_internals: &StackInternals,
    ) -> impl Iterator<Item = net::EncryptedPDU> {
    }
    */
}
pub struct NetworkPDUIterator<'a, Storage: AsRef<[u8]>> {
    iter: SegmentIterator<'a, Storage>,
    segments: &'a Segments,
    seq: SeqRange,
}
impl<'a, Storage: AsRef<[u8]>> Iterator for NetworkPDUIterator<'a, Storage> {
    type Item = net::PDU;

    fn next(&mut self) -> Option<Self::Item> {
        let lower: lower::SegmentedPDU = self.iter.next()?;
        Some(net::PDU {
            header: self.segments.network_header(
                self.seq
                    .next()
                    .expect("should always have enough seq numbers"),
            ),
            payload: lower.into(),
        })
    }
}
pub struct EncryptedNetworkPDUIterator<'a, Storage: AsRef<[u8]>> {
    segments: NetworkPDUIterator<'a, Storage>,
    stack_internals: &'a StackInternals,
}
