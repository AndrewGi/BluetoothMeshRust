//! Bluetooth Mesh Stack that connects all the layers together.
use crate::ble::RSSI;
use crate::crypto::materials::NetKeyMap;
use crate::crypto::NetKeyIndex;
use crate::mesh::IVIndex;
use crate::mesh_io::IOBearer;
use crate::{device_state, lower, net, replay};
use alloc::boxed::Box;

/// Full Bluetooth Mesh Stack for
/// Layers:
/// - Access
/// - Control
/// - Upper Transport
/// - Lower Transport
/// - Network
/// - Bearer/IO
/// This stack acts as glue between the Mesh layers.
pub struct Stack {
    device_state: device_state::State,
    replay_cache: replay::Cache,
    io_bearer: Box<dyn IOBearer>,
}

pub enum IncomingPDU {
    EncryptedNet {
        pdu: net::EncryptedPDU,
        rssi: Option<RSSI>,
    },
    DecryptedNet {
        net_key_index: NetKeyIndex,
        rssi: Option<RSSI>,
        pdu: net::PDU,
    },
}
impl Stack {
    pub fn new(io_bearer: Box<dyn IOBearer>, device_state: device_state::State) -> Self {
        Self {
            io_bearer,
            replay_cache: replay::Cache::default(),
            device_state,
        }
    }
    pub fn net_keys(&self) -> &NetKeyMap {
        &self.device_state.security_materials().net_key_map
    }
    pub fn replay_cache(&self) -> &replay::Cache {
        &self.replay_cache
    }
    pub fn iv_index(&self) -> IVIndex {
        self.device_state.iv_index()
    }
    pub fn handle_lower_transport_pdu(&mut self, _pdu: &lower::PDU) {
        unimplemented!()
    }
    pub fn handle_encrypted_network_pdu(&mut self, _pdu: &net::EncryptedPDU) {
        unimplemented!()
    }
    /// Tries to find the matching `NetworkSecurityMaterials` from the device state manager. Once
    /// it finds a `NetworkSecurityMaterials` with a matching `NID`, it tries to decrypt the PDU.
    /// If the MIC is authenticated (the materials match), it'll return the decrypted PDU.
    /// If no security materials match, it'll return `None`
    pub fn decrypt_network_pdu(&self, pdu: &net::EncryptedPDU) -> Option<(NetKeyIndex, net::PDU)> {
        let iv_index = self.iv_index();
        for (index, sm) in self.net_keys().matching_nid(pdu.nid()) {
            if let Ok(decrypted_pdu) = pdu.try_decrypt(sm.network_keys(), iv_index) {
                return Some((index, decrypted_pdu));
            }
        }

        None
    }
}
