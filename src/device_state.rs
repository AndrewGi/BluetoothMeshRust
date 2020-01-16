//! Device State Manager used to storing device state and having an config client control it.
use crate::access::ModelIdentifier;
use crate::address::UnicastAddress;
use crate::crypto::key::DevKey;
use crate::crypto::materials::{AppKeyMap, NetKeyMap, SecurityMaterials};
use crate::foundation::publication::ModelPublishInfo;
use crate::foundation::state::{
    DefaultTTLState, GATTProxyState, NetworkTransmit, RelayState, SecureNetworkBeaconState,
};
use crate::mesh::{
    AppKeyIndex, IVIndex, IVUpdateFlag, SequenceNumber, TransmitCount, TransmitInterval,
    TransmitSteps, IVI, U24,
};
use crate::random::Randomizable;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::Cell;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct ModelInfo {
    pub publish: Option<ModelPublishInfo>,
    pub app_key: Vec<AppKeyIndex>,
}
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default)]
pub struct Models(BTreeMap<ModelIdentifier, ModelInfo>);

pub struct DeviceState {
    element_address: UnicastAddress,
    element_count: u8,
    pub seq_counter: SeqCounter,
    relay_state: RelayState,
    gatt_proxy_state: GATTProxyState,
    secure_network_beacon_state: SecureNetworkBeaconState,

    models: Models,

    default_ttl: DefaultTTLState,
    network_transmit: NetworkTransmit,

    iv_update_flag: IVUpdateFlag,
    iv_index: IVIndex,
    pub security_materials: SecurityMaterials,
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Default, Hash, Debug)]
pub struct SeqCounter(SequenceNumber);
impl SeqCounter {
    /// Allocates a SequenceNumber and increments the internal counter.
    /// Returns `None` if `SequenceNumber` is at its max.
    pub fn inc_seq(&mut self) -> Option<SequenceNumber> {
        if (self.0).0 == U24::max_value() {
            None
        } else {
            let out = self.0;
            *self = SeqCounter(SequenceNumber(U24::new(out.0.value() + 1)));
            Some(out)
        }
    }
}
impl DeviceState {
    /// Generates a new `DeviceState`. `SecurityMaterials` will be new random keys.
    pub fn new(element_count: u8) -> Self {
        Self {
            element_count: element_count,
            element_address: UnicastAddress::from_mask_u16(1u16),
            seq_counter: SeqCounter::default(),
            relay_state: RelayState::Disabled,
            gatt_proxy_state: GATTProxyState::Disabled,
            secure_network_beacon_state: SecureNetworkBeaconState::NotBroadcasting,
            models: Models::default(),
            default_ttl: DefaultTTLState::new(0x4),
            network_transmit: NetworkTransmit(TransmitInterval {
                count: TransmitCount::new(0x3),
                steps: TransmitSteps::new(3),
            }),
            iv_update_flag: IVUpdateFlag(false),
            iv_index: IVIndex(0),
            security_materials: SecurityMaterials {
                dev_key: DevKey::random_secure(),
                net_key_map: NetKeyMap::new(),
                app_key_map: AppKeyMap::new(),
            },
        }
    }
    pub fn element_address(&self, element_index: u8) -> Option<UnicastAddress> {
        if element_index >= self.element_count {
            None
        } else {
            Some(UnicastAddress::from_mask_u16(
                u16::from(self.element_address) + u16::from(element_index),
            ))
        }
    }
    /// IVIndex used for transmitting.
    pub fn tx_iv_index(&self) -> IVIndex {
        self.iv_index
    }
    /// IVIndex used for receiving. Will return `None` if no matching `IVIndex` can be found.
    /// See [`IVIndex::matching_flags`] for more.
    pub fn rx_iv_index(&self, ivi: IVI) -> Option<IVIndex> {
        self.iv_index.matching_flags(ivi, self.iv_update_flag)
    }
    pub fn iv_index(&self) -> IVIndex {
        self.iv_index
    }
    pub fn security_materials(&self) -> &SecurityMaterials {
        &self.security_materials
    }
    pub fn device_key(&self) -> &DevKey {
        &self.security_materials.dev_key
    }
}
