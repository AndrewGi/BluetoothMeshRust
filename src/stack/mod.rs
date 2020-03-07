//! Bluetooth Mesh Stack that connects all the layers together.
//! See ['StackInternals'] for more.

#[cfg(feature = "bearer")]
pub mod bearer;
#[cfg(feature = "bearer")]
pub mod bearers;
pub mod element;
#[cfg(feature = "full_stack")]
pub mod full;
#[cfg(feature = "full_stack")]
pub mod incoming;
pub mod messages;
pub mod model;
#[cfg(feature = "full_stack")]
pub mod outgoing;
#[cfg(feature = "std")]
pub mod segments;

use crate::address::{Address, UnicastAddress, VirtualAddress, VirtualAddressHash};

use crate::crypto::materials::{ApplicationSecurityMaterials, NetKeyMap, NetworkSecurityMaterials};
use crate::crypto::nonce::{AppNonceParts, DeviceNonceParts};
use crate::device_state::{DeviceState, SeqCounter};
use crate::lower::SegO;
use crate::mesh::{
    AppKeyIndex, ElementCount, ElementIndex, IVIndex, IVUpdateFlag, NetKeyIndex, TTL,
};
use crate::net::OwnedEncryptedPDU;
use crate::segmenter::EncryptedNetworkPDUIterator;
use crate::stack::element::ElementRef;
use crate::stack::messages::{
    EncryptedIncomingMessage, IncomingMessage, MessageKeys, OutgoingLowerTransportMessage,
    OutgoingMessage, OutgoingUpperTransportMessage,
};
use crate::stack::segments::ReassemblyError;
use crate::upper;
use crate::upper::{AppPayload, SecurityMaterials, SecurityMaterialsIterator};
use crate::{device_state, net};
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct NetworkHeader {
    pub src: UnicastAddress,
    pub dst: Address,
    pub ttl: TTL,
    pub iv_index: IVIndex,
}

/// Bluetooth Mesh Stack Internals for generic Stack operations. Provides foundational building
/// blocks for building your own stack.
///
/// Layers:
/// - Access
/// - Control
/// - Upper Transport
/// - Lower Transport
/// - Network
/// - Bearer/IO
///
/// This stack acts as glue between the Mesh layers.
/// This stack is inherently single threaded which Bluetooth Mesh requires some type of scheduling.
/// The scheduling and input/output queues are handled by `FullStack`.
pub struct StackInternals {
    device_state: device_state::DeviceState,
}
/// Returned when an outgoing message can't be sent for some reason.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum SendError {
    ChannelClosed,
    InvalidAppKeyIndex,
    InvalidIVIndex,
    InvalidNetKeyIndex,
    InvalidDestination,
    InvalidSourceElement,
    NetEncryptError,
    OutOfSeq,
    AckTimeout,
}
/// Returned when an incoming message can't be received for some reason.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum RecvError {
    ReassemblerError(ReassemblyError),
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
    /// Returns all the virtual addresses owned by the stack with a hash matching `hash`.
    pub fn matching_virtual_addresses(
        &self,
        _h: VirtualAddressHash,
    ) -> impl Iterator<Item = &'_ VirtualAddress> + Clone {
        Option::<&'_ VirtualAddress>::None.into_iter()
    }
    /// Attempts to decrypt the application `msg`. Multiple keys may be used to try to decrypt the
    /// message so it will have to be cloned once so any decryption can be undone if the key wasn't
    /// correct. No matter matter what, this function will only call `Clone` at most ONCE.
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
                    if let Some(element_index) = self.device_state().element_index(unicast) {
                        if !element_index.is_primary() {
                            return Err(RecvError::InvalidDestination);
                        }
                        let nonce = msg.device_nonce();
                        let mic = msg.encrypted_app_payload.mic();
                        let mut storage: Storage = msg.encrypted_app_payload.into_storage();
                        if let Ok(_) = SecurityMaterials::Device(
                            nonce,
                            &self.device_state.security_materials().dev_key,
                        )
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
                        &self.device_state.security_materials().dev_key,
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
            upper_pdu: upper::PDU::Access(encrypted),
            seq,
            seg_count: SegO::new(seg_count),
            net_key_index,
            src,
            dst,
            ttl: Some(ttl),
            iv_index,
        })
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
    /// Returns if the given `IVIndex` is a valid `IVIndex` (Based on IVI).
    fn is_valid_iv_index(&self, iv_index: IVIndex) -> bool {
        self.device_state
            .rx_iv_index(iv_index.ivi())
            .map(|iv| iv == iv_index)
            .unwrap_or(false)
    }
    /// Encrypts a chain of Network PDUs. Useful for encrypting Lower Segmented PDUs all at once.
    pub fn encrypted_network_pdus<I: Iterator<Item = net::PDU>>(
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
    pub fn lower_to_net(
        &self,
        msg: &OutgoingLowerTransportMessage,
    ) -> Result<(net::PDU, &NetworkSecurityMaterials), SendError> {
        if !self.is_valid_iv_index(msg.iv_index) {
            return Err(SendError::InvalidIVIndex);
        }
        let index = self
            .device_state
            .element_index(msg.src)
            .ok_or(SendError::InvalidSourceElement)?;
        let net_sm = self
            .net_keys()
            .get_keys(msg.net_key_index)
            .ok_or(SendError::InvalidNetKeyIndex)?
            .tx_key();
        let seq = match msg.seq {
            Some(seq) => seq,
            None => self
                .device_state()
                .seq_counter(index)
                .inc_seq(1)
                .ok_or(SendError::OutOfSeq)?
                .start(),
        };
        Ok((
            msg.net_pdu(
                net_sm.network_keys().nid(),
                seq,
                msg.ttl.unwrap_or(self.device_state.default_ttl()),
            ),
            net_sm,
        ))
    }
    /// Encrypt a single [`net::PDU`]. Use `Self::encrypted_network_pdus` instead if you have
    /// more than one Network PDU.
    pub fn encrypt_network_pdu(
        &self,
        pdu: net::PDU,
        net_key_index: NetKeyIndex,
        iv_index: IVIndex,
    ) -> Result<OwnedEncryptedPDU, SendError> {
        if !self.is_valid_iv_index(iv_index) {
            return Err(SendError::InvalidIVIndex);
        }
        pdu.encrypt(
            self.net_keys()
                .get_keys(net_key_index)
                .ok_or(SendError::InvalidNetKeyIndex)?
                .tx_key()
                .network_keys(),
            iv_index,
        )
        .map_err(|_| SendError::NetEncryptError)
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
