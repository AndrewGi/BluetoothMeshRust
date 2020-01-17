//! Optional Relay Feature
use crate::mesh::{IVIndex, NetKeyIndex};
use crate::net;

pub struct RelayPDU {
    pub pdu: net::PDU,
    pub iv_index: IVIndex,
    pub net_key_index: NetKeyIndex,
}
