//! Appliation layer.

use crate::address::{Address, UnicastAddress};
use crate::ble::RSSI;
use crate::crypto::aes::MicSize;
use crate::crypto::materials::NetworkSecurityMaterials;
use crate::crypto::AID;
use crate::mesh::{AppKeyIndex, IVIndex, NetKeyIndex, TTL};
use crate::upper::{AppPayload, EncryptedAppPayload};

pub enum MessageKeys {
    Device(NetKeyIndex),
    App(AppKeyIndex),
}

pub struct OutgoingMessage<Storage: AsRef<[u8]> + AsMut<[u8]>> {
    pub app_payload: AppPayload<Storage>,
    pub mic_size: MicSize,
    pub encryption_key: MessageKeys,
    pub iv_index: IVIndex,
    pub source_element_index: u8,
    pub dst: Address,
    pub ttl: Option<TTL>,
}
impl<Storage: AsRef<[u8]> + AsMut<[u8]>> OutgoingMessage<Storage> {
    pub fn should_segment(&self) -> bool {
        unimplemented!()
    }
}
pub struct EncryptedOutgoingMessage<'a, Storage: AsRef<[u8]> + AsMut<[u8]>> {
    pub encrypted_app_payload: EncryptedAppPayload<Storage>,
    pub net_sm: &'a NetworkSecurityMaterials,
    pub dst: Address,
    pub ttl: TTL,
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
