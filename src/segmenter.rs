use crate::crypto::MIC;
use crate::lower::{BlockAck, SegN, SegO, SegmentHeader, SegmentedAccessPDU, SeqAuth};

use crate::crypto::materials::NetworkKeys;
use crate::device_state::SeqRange;
use crate::mesh::{IVIndex, NetKeyIndex, SequenceNumber, CTL, NID};
use crate::net::OwnedEncryptedPDU;
use crate::stack::NetworkHeader;
use crate::{lower, net, upper};

use core::cmp::min;

pub struct UpperSegmenter<Storage: AsRef<[u8]>> {
    upper_pdu: upper::PDU<Storage>,
    seg_o: SegO,
    seq_auth: SeqAuth,
}
impl<Storage: Clone + AsRef<[u8]>> Clone for UpperSegmenter<Storage> {
    fn clone(&self) -> Self {
        Self {
            upper_pdu: self.upper_pdu.clone(),
            seg_o: self.seg_o,
            seq_auth: self.seq_auth,
        }
    }
}
impl<Storage: AsRef<[u8]>> UpperSegmenter<Storage> {
    pub fn new(upper_pdu: upper::PDU<Storage>, seq_auth: SeqAuth) -> Self {
        Self {
            seg_o: upper_pdu.seg_o(),
            upper_pdu,
            seq_auth,
        }
    }
    pub fn iter(&self, block_ack: BlockAck) -> SegmentIterator<Storage> {
        SegmentIterator {
            block_ack,
            segmenter: self,
            seg_n: 0,
        }
    }
    pub fn upper_pdu(&self) -> &upper::PDU<Storage> {
        &self.upper_pdu
    }
    pub fn seg_o(&self) -> SegO {
        self.seg_o
    }
    pub fn seq_auth(&self) -> SeqAuth {
        self.seq_auth
    }
    pub fn seg_count(&self) -> u8 {
        u8::from(self.seg_o) + 1
    }
}

pub struct SegmentIterator<'a, Storage: AsRef<[u8]>> {
    block_ack: BlockAck,
    segmenter: &'a UpperSegmenter<Storage>,
    seg_n: u8,
}
impl<'a, Storage: AsRef<[u8]>> SegmentIterator<'a, Storage> {
    pub fn segment_header(&self) -> SegmentHeader {
        let flag = self
            .segmenter
            .upper_pdu
            .mic()
            .map(|mic| mic.is_big())
            .unwrap_or(false);
        SegmentHeader::new(
            flag,
            self.segmenter.seq_auth.seq_zero(),
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
            match &self.segmenter.upper_pdu {
                upper::PDU::Control(control) => {
                    // ControlPDU
                    let out = lower::SegmentedControlPDU::new(control.opcode, header, segment_data);
                    self.seg_n += 1;
                    Some(lower::SegmentedPDU::Control(out))
                }
                upper::PDU::Access(access) => {
                    if segment_data.len() != SegmentedAccessPDU::max_seg_len() {
                        let mic = access.mic();
                        let seg_len = segment_data.len();
                        let mut buf = [0_u8; SegmentedAccessPDU::max_seg_len() + MIC::big_size()];
                        buf[..seg_len].copy_from_slice(segment_data);
                        mic.be_pack_into(&mut buf[seg_len..seg_len + mic.byte_size()]);
                        let out = lower::SegmentedAccessPDU::new(
                            access.aid(),
                            mic.is_big().into(),
                            self.segmenter.seq_auth.first_seq.into(),
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
                            access.aid(),
                            access.mic().is_big().into(),
                            self.segmenter.seq_auth.seq_zero(),
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

pub struct NetworkSegments<Storage: AsRef<[u8]>> {
    upper_pdu: UpperSegmenter<Storage>,
    seg_o: SegO,
    net_key_index: NetKeyIndex,
    seq_zero: SequenceNumber,
    header: NetworkHeader,
    remote_block_ack: BlockAck,
}
impl<Storage: AsRef<[u8]>> NetworkSegments<Storage> {
    pub fn segs_left(&self) -> u32 {
        self.remote_block_ack.seg_left(self.seg_o).into()
    }
    /// Returns an Iterator generating all the Unacked Segmented PDUs. `seq` should have enough
    /// `SequenceNumbers` to encrypt all the PDUs.
    pub fn network_pdu_iter(
        &self,
        seq: SeqRange,
        nid: NID,
        ctl: CTL,
    ) -> Option<NetworkPDUIterator<Storage>> {
        if seq.seqs_lefts() < self.segs_left() {
            None
        } else {
            Some(NetworkPDUIterator {
                iter: self.upper_pdu.iter(self.remote_block_ack),
                header: self.header,
                nid,
                ctl,
                seq,
            })
        }
    }
    /// Returns an Iterator generating all the Encrypted Unacked Segmented PDUs. `seq` should have enough
    /// `SequenceNumbers` to encrypt all the PDUs.
    pub fn encrypted_network_pdu_iter<'a>(
        &self,
        seq: SeqRange,
        net_keys: &'a NetworkKeys,
    ) -> Option<EncryptedNetworkPDUIterator<'a, NetworkPDUIterator<Storage>>> {
        Some(EncryptedNetworkPDUIterator {
            // NID and CTL get updated with the PDUs are encrypted
            pdus: self.network_pdu_iter(seq, NID::new(0), CTL(false))?,
            iv_index: self.header.iv_index,
            net_keys,
        })
    }
}
impl<Storage: Clone + AsRef<[u8]>> Clone for NetworkSegments<Storage> {
    fn clone(&self) -> Self {
        Self {
            upper_pdu: self.upper_pdu.clone(),
            seg_o: self.seg_o,
            net_key_index: self.net_key_index,
            seq_zero: self.seq_zero,
            header: self.header,
            remote_block_ack: self.remote_block_ack,
        }
    }
}
pub struct NetworkPDUIterator<'a, Storage: AsRef<[u8]>> {
    iter: SegmentIterator<'a, Storage>,
    header: NetworkHeader,
    nid: NID,
    ctl: CTL,
    seq: SeqRange,
}
impl<'a, Storage: AsRef<[u8]>> Iterator for NetworkPDUIterator<'a, Storage> {
    type Item = net::PDU;

    fn next(&mut self) -> Option<Self::Item> {
        let lower: lower::SegmentedPDU = self.iter.next()?;

        Some(net::PDU {
            header: net::Header {
                ivi: self.header.iv_index.ivi(),
                nid: self.nid,
                ctl: self.ctl,
                ttl: self.header.ttl,
                seq: self
                    .seq
                    .next()
                    .expect("should always have enough seq numbers"),
                src: self.header.src,
                dst: self.header.dst,
            },

            payload: lower.into(),
        })
    }
}
pub struct EncryptedNetworkPDUIterator<'a, PDUIter: Iterator<Item = net::PDU>> {
    pub pdus: PDUIter,
    pub iv_index: IVIndex,
    pub net_keys: &'a NetworkKeys,
}
impl<'a, PDUIter: Iterator<Item = net::PDU>> EncryptedNetworkPDUIterator<'a, PDUIter> {
    pub fn new(pdus: PDUIter, iv_index: IVIndex, net_keys: &'a NetworkKeys) -> Self {
        Self {
            pdus,
            iv_index,
            net_keys,
        }
    }
}
impl<'a, PDUIter: Iterator<Item = net::PDU>> Iterator for EncryptedNetworkPDUIterator<'a, PDUIter> {
    type Item = OwnedEncryptedPDU;

    fn next(&mut self) -> Option<Self::Item> {
        Some(
            self.pdus
                .next()?
                .encrypt(self.net_keys, self.iv_index)
                .expect("header wasn't correct"),
        )
    }
}
