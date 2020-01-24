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
    AppKeyIndex, ElementCount, ElementIndex, IVIndex, IVUpdateFlag, SequenceNumber, TransmitCount,
    TransmitInterval, TransmitSteps, IVI, TTL, U24,
};
use crate::random::Randomizable;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::ops::Range;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ModelInfo {
    pub publish: Option<ModelPublishInfo>,
    pub app_key: Vec<AppKeyIndex>,
}
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Models(BTreeMap<ModelIdentifier, ModelInfo>);

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeviceState {
    element_address: UnicastAddress,
    element_count: ElementCount,
    relay_state: RelayState,
    gatt_proxy_state: GATTProxyState,
    secure_network_beacon_state: SecureNetworkBeaconState,

    models: Models,

    default_ttl: DefaultTTLState,
    network_transmit: NetworkTransmit,

    iv_update_flag: IVUpdateFlag,
    iv_index: IVIndex,
    security_materials: SecurityMaterials,
}
pub struct SeqRange(pub core::ops::Range<u32>);
impl SeqRange {
    pub fn start(&self) -> SequenceNumber {
        SequenceNumber(U24::new(self.0.start))
    }
    pub fn seqs_lefts(&self) -> u32 {
        (self.0.end - self.0.start)
    }
    pub fn is_empty(&self) -> bool {
        self.0.start >= self.0.end
    }
}
impl From<SequenceNumber> for SeqRange {
    fn from(seq: SequenceNumber) -> Self {
        Self(seq.0.value()..seq.0.value() + 1)
    }
}
impl Iterator for SeqRange {
    type Item = SequenceNumber;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_empty() {
            None
        } else {
            let out = self.0.start;
            self.0.start = out + 1;
            Some(SequenceNumber(U24::new(out)))
        }
    }
}
/// Atomic SeqCounter so no PDUs get the same SeqNumber. Sequence Numbers are a finite resource
/// (only 24-bits) that only get reset every IVIndex update. Also segmented PDUs require sequential
#[derive(Default, Debug)]
pub struct SeqCounter(core::sync::atomic::AtomicU32);
impl SeqCounter {
    /// Allocates a or some SequenceNumbers and increments the internal counter by amount. Allocating
    /// `amount` Sequence Numbers is useful for Segmented Transport PDUs.
    /// Returns `None` if `SequenceNumber` is at its max.
    pub fn inc_seq(&self, amount: u32) -> Option<SeqRange> {
        let next = self
            .0
            .fetch_add(amount, core::sync::atomic::Ordering::SeqCst);
        if next >= U24::max_value().value() {
            // Overflow of Seq Number
            self.0.store(
                U24::max_value().value(),
                core::sync::atomic::Ordering::SeqCst,
            );
            None
        } else {
            Some(SeqRange(next..next + amount))
        }
    }
}
impl DeviceState {
    /// Generates a new `DeviceState`. `SecurityMaterials` will be new random keys.
    /// # Panics
    /// Panics if `element_count == 0 || (primary_address + eleent_count).is_not_unicast()`
    pub fn new(primary_address: UnicastAddress, element_count: ElementCount) -> Self {
        assert!(element_count.0 != 0, "zero element_count given");
        assert!(
            UnicastAddress::try_from(u16::from(primary_address) + u16::from(element_count.0))
                .is_ok(),
            "primary_address + element_count is non-unicast"
        );
        Self {
            element_count,
            element_address: primary_address,
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
    pub fn unicast_range(&self) -> Range<UnicastAddress> {
        Range {
            start: self.element_address,
            end: UnicastAddress::new(
                u16::from(self.element_address) + u16::from(self.element_count.0),
            ),
        }
    }
    pub fn element_count(&self) -> ElementCount {
        self.element_count
    }
    pub fn element_address(&self, element_index: ElementIndex) -> Option<UnicastAddress> {
        if element_index.0 >= self.element_count.0 {
            None
        } else {
            Some(UnicastAddress::from_mask_u16(
                u16::from(self.element_address) + u16::from(element_index.0),
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
    pub fn default_ttl(&self) -> TTL {
        TTL::new(self.default_ttl.into())
    }
    pub fn relay_state(&self) -> RelayState {
        self.relay_state
    }
}
