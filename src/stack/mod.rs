//! Bluetooth Mesh Stack that connects all the layers together.

pub mod element;
#[cfg(feature = "full")]
pub mod full;
#[cfg(feature = "full")]
pub mod incoming;
pub mod messages;
pub mod model;
#[cfg(feature = "full")]
pub mod outgoing;
#[cfg(feature = "std")]
pub mod segments;

use crate::address::{Address, UnicastAddress, VirtualAddress, VirtualAddressHash};
use crate::bearer::BearerError;

use crate::crypto::materials::{ApplicationSecurityMaterials, NetKeyMap};
use crate::crypto::nonce::{AppNonceParts, DeviceNonceParts};
use crate::device_state::{DeviceState, SeqCounter};
use crate::lower::SegO;
use crate::mesh::{
    AppKeyIndex, ElementCount, ElementIndex, IVIndex, IVUpdateFlag, NetKeyIndex, TTL,
};
use crate::segmenter::EncryptedNetworkPDUIterator;
use crate::stack::element::ElementRef;
use crate::stack::messages::{
    EncryptedIncomingMessage, IncomingMessage, MessageKeys, OutgoingMessage,
    OutgoingUpperTransportMessage,
};
use crate::upper;
use crate::upper::{AppPayload, SecurityMaterials, SecurityMaterialsIterator};
use crate::{device_state, net};
use core::convert::TryFrom;

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
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum SendError {
    InvalidAppKeyIndex,
    InvalidIVIndex,
    InvalidNetKeyIndex,
    InvalidDestination,
    InvalidSourceElement,
    OutOfSeq,
    BearerError(BearerError),
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum RecvError {
    NoMatchingNetKey,
    NoMatchingAppKey,
    InvalidDeviceKey,
    InvalidDestination,
    MalformedNetworkPDU,
    MalformedControlPDU,
    OldSeq,
    ChannelClosed,
    OldSeqZero,
}
impl StackInternals {
    /// Wraps a `device_state::DeviceState` and lets you perform encrypt and decryption with it.
    pub fn new(device_state: device_state::DeviceState) -> Self {
        Self { device_state }
    }
    /// Returns a reference to the Atomic `SeqCounter` pertaining to the given element.
    /// # Panics
    /// Panics if `element_index >= element_count`.
    pub fn seq_counter(&self, element_index: ElementIndex) -> &SeqCounter {
        self.device_state.seq_counter(element_index)
    }
    pub fn matching_virtual_addresses(
        &self,
        _h: VirtualAddressHash,
    ) -> impl Iterator<Item = &'_ VirtualAddress> + Clone {
        Option::<&'_ VirtualAddress>::None.into_iter()
    }

    fn app_decrypt<Storage: AsRef<[u8]> + AsMut<[u8]> + Clone>(
        &self,
        msg: EncryptedIncomingMessage<Storage>,
    ) -> Result<IncomingMessage<Storage>, RecvError> {
        match msg.encrypted_app_payload.aid() {
            Some(aid) => {
                // Application Key
                let matching_aid = self
                    .device_state
                    .security_materials()
                    .app_key_map
                    .matching_aid(aid);
                let mut sm_iter = match msg.dst {
                    Address::VirtualHash(h) => SecurityMaterialsIterator::new_virtual(
                        msg.app_nonce(),
                        matching_aid,
                        self.matching_virtual_addresses(h),
                    ),
                    Address::Virtual(v) => {
                        let h = v.hash();
                        SecurityMaterialsIterator::new_virtual(
                            msg.app_nonce(),
                            matching_aid,
                            self.matching_virtual_addresses(h),
                        )
                    }
                    Address::Unassigned => return Err(RecvError::InvalidDestination),
                    Address::Group(_) | Address::Unicast(_) => {
                        //Regular Address
                        SecurityMaterialsIterator::new_app(msg.app_nonce(), matching_aid)
                    }
                };
                let mic = msg.encrypted_app_payload.mic();
                let mut storage: Storage = msg.encrypted_app_payload.into_storage();
                if let Some((index, sm)) = sm_iter.decrypt_with(&mut storage, mic) {
                    let dst = sm
                        .virtual_address()
                        .map(Address::Virtual)
                        .unwrap_or(msg.dst);
                    Ok(IncomingMessage {
                        payload: storage,
                        src: msg.src,
                        dst,
                        seq: msg.seq,
                        iv_index: msg.iv_index,
                        net_key_index: msg.net_key_index,
                        app_key_index: Some(index),
                        ttl: msg.ttl,
                        rssi: msg.rssi,
                    })
                } else {
                    Err(RecvError::NoMatchingNetKey)
                }
            }
            None => match msg.dst {
                Address::Unicast(unicast) => {
                    if let Some(element_index) = self.owns_unicast_address(unicast) {
                        if !element_index.is_primary() {
                            return Err(RecvError::InvalidDestination);
                        }
                        let nonce = msg.device_nonce();
                        let mic = msg.encrypted_app_payload.mic();
                        let mut storage: Storage = msg.encrypted_app_payload.into_storage();
                        if let Ok(_) =
                            SecurityMaterials::Device(nonce, self.device_state.device_key())
                                .decrypt(&mut storage.as_mut()[..], mic)
                        {
                            Ok(IncomingMessage {
                                payload: storage,
                                src: msg.src,
                                dst: Address::Unicast(unicast),
                                seq: msg.seq,
                                iv_index: msg.iv_index,
                                net_key_index: msg.net_key_index,
                                app_key_index: None,
                                ttl: msg.ttl,
                                rssi: msg.rssi,
                            })
                        } else {
                            Err(RecvError::InvalidDeviceKey)
                        }
                    } else {
                        Err(RecvError::InvalidDestination)
                    }
                }
                _ => Err(RecvError::InvalidDestination),
            },
        }
    }
    /// Encrypts and Assigns a Sequence Numbers to `EncryptedOutgoingMessage`
    pub fn app_encrypt<Storage: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        msg: OutgoingMessage<Storage>,
    ) -> Result<OutgoingUpperTransportMessage<Storage>, (SendError, OutgoingMessage<Storage>)> {
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
        let seg_count = u8::from(msg.seg_o().unwrap_or(SegO::new(0))) + 1;
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
                let seq_range = match self
                    .seq_counter(msg.source_element_index)
                    .inc_seq(seg_count.into())
                {
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
                let seq_range = match self
                    .seq_counter(msg.source_element_index)
                    .inc_seq(seg_count.into())
                {
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
        Ok(OutgoingUpperTransportMessage {
            encrypted_app_payload: encrypted,
            seq,
            seg_count: SegO::new(seg_count),
            net_key_index,
            dst,
            ttl,
        })
    }
    /// Check if the given `unicast_address` is owned by this node. Ex: If this node has 5 elements
    /// and its primary unicast address is `0x0002`, then it owns the range `[0x0002..0x0007]`.
    /// If `unicast_address` is not in that range, this returns `None`.
    pub fn owns_unicast_address(&self, unicast_address: UnicastAddress) -> Option<ElementIndex> {
        let range = self.device_state.unicast_range();
        if range.contains(&unicast_address) {
            Some(ElementIndex(
                u8::try_from(u16::from(range.start) - u16::from(unicast_address))
                    .expect("too many elements"),
            ))
        } else {
            None
        }
    }
    /// Returns the default `TTL`.
    pub fn default_ttl(&self) -> TTL {
        self.device_state.default_ttl()
    }
    /// Returns the `ApplicationSecurityMaterials` pertaining to the given `app_key_index`. If no
    /// key exists under the given `AppKeyIndex`, `None` will be returned
    pub fn get_app_key(&self, app_key_index: AppKeyIndex) -> Option<&ApplicationSecurityMaterials> {
        self.device_state
            .security_materials()
            .app_key_map
            .get_key(app_key_index)
    }
    pub fn net_keys(&self) -> &NetKeyMap {
        &self.device_state.security_materials().net_key_map
    }
    /// Returns a mutable reference to `device_state::DeviceState`. If you take a mutable reference,
    /// you essential lock out the rest of the stack from using `device_state::DeviceState` to
    /// encrypt and decrypt messages.
    pub fn device_state_mut(&mut self) -> &mut DeviceState {
        &mut self.device_state
    }
    /// Returns an immutable reference to `device_state::DeviceState`.
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
    fn is_valid_iv_index(&self, iv_index: IVIndex) -> bool {
        self.device_state
            .rx_iv_index(iv_index.ivi())
            .map(|iv| iv == iv_index)
            .unwrap_or(false)
    }
    fn encrypted_network_pdus<I: Iterator<Item = net::PDU>>(
        &self,
        network_pdus: I,
        net_key_index: NetKeyIndex,
        iv_index: IVIndex,
    ) -> Result<EncryptedNetworkPDUIterator<I>, SendError> {
        if !self.is_valid_iv_index(iv_index) {
            return Err(SendError::InvalidIVIndex);
        }
        let net_sm = self
            .net_keys()
            .get_keys(net_key_index)
            .ok_or(SendError::InvalidNetKeyIndex)?
            .tx_key();
        Ok(EncryptedNetworkPDUIterator {
            pdus: network_pdus,
            iv_index,
            net_keys: net_sm.network_keys(),
        })
    }
}

pub trait Stack: Sized {
    fn iv_index(&self) -> (IVIndex, IVUpdateFlag);
    fn primary_address(&self) -> UnicastAddress;
    fn element_ref(&self, element_index: ElementIndex) -> ElementRef<Self, &Self> {
        ElementRef::new(&self, element_index)
    }
    fn element_count(&self) -> ElementCount;
    fn send_message<Storage: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        source_element: ElementIndex,
        app_index: AppKeyIndex,
        dst: Address,
        payload: AppPayload<Storage>,
    ) -> Result<(), SendError>;
}
