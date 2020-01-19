//! Bluetooth Mesh Stack that connects all the layers together.

pub mod element;
#[cfg(feature = "std")]
pub mod full;
pub mod messages;
pub mod model;
#[cfg(feature = "std")]
pub mod segments;

use crate::address::{Address, UnicastAddress};
use crate::bearer::BearerError;

use crate::crypto::materials::{ApplicationSecurityMaterials, NetKeyMap};
use crate::crypto::nonce::{AppNonceParts, DeviceNonceParts};
use crate::device_state::{DeviceState, SeqCounter};
use crate::lower::SegO;
use crate::mesh::{AppKeyIndex, IVIndex, NetKeyIndex, TTL};
use crate::stack::messages::{EncryptedOutgoingMessage, MessageKeys, OutgoingMessage};
use crate::upper;
use crate::{device_state, net};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct NetworkHeader {
    pub src: UnicastAddress,
    pub dst: Address,
    pub ttl: TTL,
    pub iv_index: IVIndex,
}

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
    seq_counter: SeqCounter,
}
pub enum SendError {
    InvalidAppKeyIndex,
    InvalidNetKeyIndex,
    InvalidDestination,
    InvalidSourceElement,
    OutOfSeq,
    BearerError(BearerError),
}
impl StackInternals {
    pub fn new(device_state: device_state::DeviceState) -> Self {
        Self {
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
        let (sm, net_key_index, seq) = match msg.encryption_key {
            MessageKeys::Device(net_key_index) => {
                // Check for a valid net_key
                match self
                    .device_state
                    .security_materials()
                    .net_key_map
                    .get_keys(net_key_index)
                {
                    None => return Err((SendError::InvalidNetKeyIndex, msg)),
                    Some(_) => (),
                };
                let seq_range = match self.seq_counter.inc_seq(seg_count.into()) {
                    None => return Err((SendError::OutOfSeq, msg)),
                    Some(seq) => seq,
                };
                let seq = seq_range.start();
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
                    net_key_index,
                    seq_range,
                )
            }
            MessageKeys::App(app_key_index) => {
                let app_sm = match self
                    .device_state
                    .security_materials()
                    .app_key_map
                    .get_key(app_key_index)
                {
                    None => return Err((SendError::InvalidAppKeyIndex, msg)),
                    Some(app_sm) => app_sm,
                };
                let net_key_index = app_sm.net_key_index;
                // Check for a valid net_key
                match self
                    .device_state
                    .security_materials()
                    .net_key_map
                    .get_keys(net_key_index)
                {
                    None => return Err((SendError::InvalidNetKeyIndex, msg)),
                    Some(_) => (),
                };
                let seq_range = match self.seq_counter.inc_seq(seg_count.into()) {
                    None => return Err((SendError::OutOfSeq, msg)),
                    Some(seq) => seq,
                };
                let seq = seq_range.start();
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
                    net_key_index,
                    seq_range,
                )
            }
        };
        let ttl = msg.ttl.unwrap_or(self.default_ttl());
        let encrypted = msg.app_payload.encrypt(&sm, msg.mic_size);
        Ok(EncryptedOutgoingMessage {
            encrypted_app_payload: encrypted,
            seq,
            seg_count: SegO::new(seg_count),
            net_key_index,
            dst,
            ttl,
        })
    }
    pub fn default_ttl(&self) -> TTL {
        self.device_state.default_ttl()
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
    pub fn decrypt_network_pdu(
        &self,
        pdu: net::EncryptedPDU,
    ) -> Option<(NetKeyIndex, IVIndex, net::PDU)> {
        let iv_index = self.device_state.rx_iv_index(pdu.ivi())?;
        for (index, sm) in self.net_keys().matching_nid(pdu.nid()) {
            if let Ok(decrypted_pdu) = pdu.try_decrypt(sm.network_keys(), iv_index) {
                return Some((index, iv_index, decrypted_pdu));
            }
        }

        None
    }
    pub fn encrypted_network_pdu(
        &self,
        _network_pdu: net::PDU,
        _net_key_index: NetKeyIndex,
        _iv_index: IVIndex,
    ) -> Result<net::PDU, SendError> {
        unimplemented!()
    }
}
