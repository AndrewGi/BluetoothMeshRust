//! Appliation layer.

use crate::address::{Address, UnicastAddress};
use crate::ble::RSSI;
use crate::crypto::NetKeyIndex;
use crate::mesh::{AppKeyIndex, TTL};

pub enum MessageKeys {
    Device(NetKeyIndex),
    App(AppKeyIndex),
}

pub struct OutgoingMessage<Storage: AsRef<[u8]> + AsMut<[u8]>> {
    app_payload: Storage,
    encryption_key: MessageKeys,
    dst: Address,
    ttl: Option<TTL>,
}

pub struct IncomingMessage<Storage: AsRef<[u8]> + AsMut<[u8]>> {
    app_payload: Storage,
    src: UnicastAddress,
    dst: Address,
    net_key_index: NetKeyIndex,
    app_key_index: Option<AppKeyIndex>,
    ttl: TTL,
    rssi: Option<RSSI>,
}
