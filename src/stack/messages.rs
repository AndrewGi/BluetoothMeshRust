//! Appliation layer.

use crate::address::{Address, UnicastAddress};
use crate::ble::RSSI;
use crate::crypto::aes::MicSize;
use crate::device_state::SeqRange;
use crate::lower::SegO;
use crate::mesh::{AppKeyIndex, ElementIndex, IVIndex, NetKeyIndex, SequenceNumber, TTL};
use crate::upper::{AppPayload, EncryptedAppPayload};
use crate::{control, lower, net, upper};

pub enum MessageKeys {
    Device(NetKeyIndex),
    App(AppKeyIndex),
}

pub struct OutgoingMessage<Storage: AsRef<[u8]> + AsMut<[u8]>> {
    pub app_payload: AppPayload<Storage>,
    pub mic_size: MicSize,
    pub force_segment: bool,
    pub encryption_key: MessageKeys,
    pub iv_index: IVIndex,
    pub source_element_index: ElementIndex,
    pub dst: Address,
    pub ttl: Option<TTL>,
}
impl<Storage: AsRef<[u8]> + AsMut<[u8]>> OutgoingMessage<Storage> {
    pub fn data_with_mic_len(&self) -> usize {
        self.app_payload.0.as_ref().len() + self.mic_size.byte_size()
    }
    pub fn should_segment(&self) -> bool {
        self.force_segment || self.app_payload.should_segment(self.mic_size)
    }
    pub fn seg_o(&self) -> Option<SegO> {
        if !self.should_segment() {
            None
        } else {
            Some(upper::calculate_seg_o(
                self.data_with_mic_len(),
                lower::SegmentedAccessPDU::max_seg_len(),
            ))
        }
    }
}
pub struct EncryptedOutgoingMessage<Storage: AsRef<[u8]> + AsMut<[u8]>> {
    pub(crate) encrypted_app_payload: EncryptedAppPayload<Storage>,
    pub(crate) seq: SeqRange,
    pub(crate) seg_count: SegO,
    pub(crate) net_key_index: NetKeyIndex,
    pub(crate) dst: Address,
    pub(crate) ttl: TTL,
}
pub struct EncryptedIncomingMessage<Storage: AsRef<[u8]> + AsMut<[u8]>> {
    pub(crate) encrypted_app_payload: EncryptedAppPayload<Storage>,
    pub(crate) seq: SeqRange,
    pub(crate) seg_count: u8,
    pub(crate) net_key_index: NetKeyIndex,
    pub(crate) dst: Address,
    pub(crate) src: UnicastAddress,
    pub(crate) ttl: Option<TTL>,
    pub(crate) rssi: Option<RSSI>,
}
pub struct IncomingControlMessage {
    pub control_pdu: control::ControlPDU,
    pub src: UnicastAddress,
    pub rssi: Option<RSSI>,
    pub ttl: Option<TTL>,
}
pub struct IncomingMessage<Storage: AsRef<[u8]> + AsMut<[u8]>> {
    pub app_payload: Storage,
    pub src: UnicastAddress,
    pub dst: Address,
    pub net_key_index: NetKeyIndex,
    pub app_key_index: Option<AppKeyIndex>,
    pub ttl: TTL,
    pub rssi: Option<RSSI>,
}
pub struct IncomingNetworkPDU {
    pub pdu: net::PDU,
    pub net_key_index: NetKeyIndex,
    pub iv_index: IVIndex,
    pub rssi: Option<RSSI>,
}
pub struct IncomingTransportPDU<Storage: AsRef<[u8]> + AsMut<[u8]>> {
    pub upper_pdu: upper::PDU<Storage>,
    pub seq: SequenceNumber,
    pub ttl: TTL,
    pub src: UnicastAddress,
    pub dst: Address,
}
