//! Bluetooth Mesh Stack that connects all the layers together.

pub mod element;
#[cfg(std)]
pub mod full;
pub mod messages;
pub mod model;

use crate::address::{Address, UnicastAddress, VirtualAddress};
use crate::ble::RSSI;
use crate::crypto::materials::{
    ApplicationSecurityMaterials, KeyPhase, NetKeyMap, NetworkSecurityMaterials,
};
use crate::crypto::nonce::{AppNonce, AppNonceParts, DeviceNonceParts};
use crate::device_state::{DeviceState, SeqCounter};
use crate::lower::SegO;
use crate::mesh::{AppKeyIndex, IVIndex, NetKeyIndex, SequenceNumber, TTL};
use crate::stack::messages::{EncryptedOutgoingMessage, MessageKeys, OutgoingMessage};
use crate::upper;
use crate::{device_state, lower, net, replay};
use alloc::boxed::Box;

/// Bluetooth Mesh Stack Internals for
/// Layers:
/// - Access
/// - Control
/// - Upper Transport
/// - Lower Transport
/// - Network
/// - Bearer/IO
/// This stack acts as glue between the Mesh layers.
/// This stack is inherently single threaded which Bluetooth Mesh requires some type of scheduling.
/// The scheduling and input/output queues are handled by `FullStack`.
pub struct StackInternals {
    device_state: device_state::DeviceState,
    replay_cache: replay::Cache,
    seq_counter: SeqCounter,
}
pub enum SendError {
    InvalidAppKeyIndex,
    InvalidNetKeyIndex,
    InvalidDestination,
    InvalidSourceElement,
    OutOfSeq,
}
impl StackInternals {
    pub fn new(device_state: device_state::DeviceState) -> Self {
        Self {
            replay_cache: replay::Cache::default(),
            device_state,
            seq_counter: SeqCounter::default(),
        }
    }
    /// Encrypts and Assigns a Sequence Numbe
    pub fn app_encrypt<Storage: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        msg: OutgoingMessage<Storage>,
    ) -> Result<EncryptedOutgoingMessage<Storage>, (SendError, OutgoingMessage<Storage>)> {
        // If DST is a VirtualAddress, it must have the full Label UUID.
        let dst = msg.dst;
        match &dst {
            Address::VirtualHash(_) | Address::Unassigned => {
                return Err((SendError::InvalidDestination, msg))
            }
            _ => (),
        }
        let iv_index = self.device_state.tx_iv_index();
        let src = match self.device_state.element_address(msg.source_element_index) {
            None => return Err((SendError::InvalidSourceElement, msg)),
            Some(address) => address,
        };
        let aszmic = msg.should_segment();
        let seg_count = u8::from(msg.seg_o().unwrap_or(SegO::new(1)));
        let (sm, net_sm, seq) = match msg.encryption_key {
            MessageKeys::Device(net_key_index) => {
                // Check for a valid net_key
                let net_sm = match self
                    .device_state
                    .security_materials
                    .net_key_map
                    .get_keys(net_key_index)
                {
                    None => return Err((SendError::InvalidNetKeyIndex, msg)),
                    Some(phase) => phase.tx_key(),
                };
                let seq = match self.seq_counter.inc_seq(seg_count.into()) {
                    None => return Err((SendError::OutOfSeq, msg)),
                    Some(seq) => seq,
                };
                (
                    upper::SecurityMaterials::Device(
                        DeviceNonceParts {
                            aszmic,
                            seq,
                            src,
                            dst,
                            iv_index,
                        }
                        .to_nonce(),
                        self.device_state.device_key(),
                    ),
                    net_sm,
                    seq,
                )
            }
            MessageKeys::App(app_key_index) => {
                let app_sm = match self
                    .device_state
                    .security_materials
                    .app_key_map
                    .get_key(app_key_index)
                {
                    None => return Err((SendError::InvalidAppKeyIndex, msg)),
                    Some(app_sm) => app_sm,
                };
                let net_key_index = app_sm.net_key_index;
                // Check for a valid net_key
                let net_sm = match self
                    .device_state
                    .security_materials
                    .net_key_map
                    .get_keys(net_key_index)
                {
                    None => return Err((SendError::InvalidNetKeyIndex, msg)),
                    Some(phase) => phase.tx_key(),
                };
                let seq = match self.seq_counter.inc_seq(seg_count.into()) {
                    None => return Err((SendError::OutOfSeq, msg)),
                    Some(seq) => seq,
                };
                let nonce = AppNonceParts {
                    aszmic,
                    seq,
                    src,
                    dst,
                    iv_index,
                }
                .to_nonce();
                (
                    match &msg.dst {
                        Address::VirtualHash(_) => {
                            return Err((SendError::InvalidDestination, msg))
                        }
                        Address::Virtual(va) => upper::SecurityMaterials::VirtualAddress(
                            nonce,
                            &app_sm.app_key,
                            app_sm.aid,
                            va,
                        ),
                        _ => upper::SecurityMaterials::App(nonce, &app_sm.app_key, app_sm.aid),
                    },
                    net_sm,
                    seq,
                )
            }
        };
        let ttl = msg.ttl.unwrap_or(self.default_ttl());
        let encrypted = msg.app_payload.encrypt(&sm, msg.mic_size);
        Ok(EncryptedOutgoingMessage {
            encrypted_app_payload: encrypted,
            seq,
            seg_count: SegO::new(seg_count),
            net_sm,
            dst,
            ttl,
        })
    }
    pub fn default_ttl(&self) -> TTL {
        unimplemented!()
    }
    pub fn get_app_key(&self, app_key_index: AppKeyIndex) -> Option<&ApplicationSecurityMaterials> {
        self.device_state
            .security_materials()
            .app_key_map
            .get_key(app_key_index)
    }
    pub fn net_keys(&self) -> &NetKeyMap {
        &self.device_state.security_materials().net_key_map
    }
    pub fn replay_cache(&self) -> &replay::Cache {
        &self.replay_cache
    }
    pub fn replay_cache_mut(&mut self) -> &mut replay::Cache {
        &mut self.replay_cache
    }
    pub fn device_state_mut(&mut self) -> &mut DeviceState {
        &mut self.device_state
    }
    pub fn device_state(&self) -> &DeviceState {
        &self.device_state
    }
    /// Tries to find the matching `NetworkSecurityMaterials` from the device state manager. Once
    /// it finds a `NetworkSecurityMaterials` with a matching `NID`, it tries to decrypt the PDU.
    /// If the MIC is authenticated (the materials match), it'll return the decrypted PDU.
    /// If no security materials match, it'll return `None`
    pub fn decrypt_network_pdu(&self, pdu: &net::EncryptedPDU) -> Option<(NetKeyIndex, net::PDU)> {
        let iv_index = self.device_state.rx_iv_index(pdu.ivi())?;
        for (index, sm) in self.net_keys().matching_nid(pdu.nid()) {
            if let Ok(decrypted_pdu) = pdu.try_decrypt(sm.network_keys(), iv_index) {
                return Some((index, decrypted_pdu));
            }
        }

        None
    }
}
