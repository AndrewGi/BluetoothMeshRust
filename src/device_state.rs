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
    AppKeyIndex, ElementCount, ElementIndex, IVIndex, IVUpdateFlag, SequenceNumber, IVI, TTL, U24,
};
use crate::random::Randomizable;

use crate::lower::SegO;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::ops::Range;
use core::sync::atomic::Ordering;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde-1", derive(serde::Serialize, serde::Deserialize))]
pub struct ModelInfo {
    pub publish: Option<ModelPublishInfo>,
    pub app_key: Vec<AppKeyIndex>,
}
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default)]
#[cfg_attr(feature = "serde-1", derive(serde::Serialize, serde::Deserialize))]
pub struct Models(BTreeMap<ModelIdentifier, ModelInfo>);

#[derive(Default, Debug)]
#[cfg_attr(feature = "serde-1", derive(serde::Serialize, serde::Deserialize))]
pub struct ConfigStates {
    pub relay_state: RelayState,
    pub gatt_proxy_state: GATTProxyState,
    pub secure_network_beacon_state: SecureNetworkBeaconState,
    pub default_ttl: DefaultTTLState,
    pub network_transmit: NetworkTransmit,
}

/// Contains all the persistant Bluetooth Mesh device data. This struct needs to be serialized/saved
/// somehow when the program shuts down or you will lose all your crypto keys. Normal operations
/// should use just immutable functions (including increasing SequenceNumbers) but config clients and others will
/// use mutable references to configure the node.
#[cfg_attr(feature = "serde-1", derive(serde::Serialize, serde::Deserialize))]
pub struct DeviceState {
    element_address: UnicastAddress,
    element_count: ElementCount,

    seq_counters: Vec<SeqCounter>,
    models: Models,

    config_states: ConfigStates,

    security_materials: SecurityMaterials,
}

impl DeviceState {
    /// Generates a new `DeviceState`. `SecurityMaterials` will be new random keys.
    /// # Panics
    /// Panics if `element_count == 0 || (primary_address + element_count).is_not_unicast()`
    pub fn new(primary_address: UnicastAddress, element_count: ElementCount) -> Self {
        assert_ne!(element_count.0, 0, "zero element_count given");
        assert!(
            UnicastAddress::try_from(u16::from(primary_address) + u16::from(element_count.0))
                .is_ok(),
            "primary_address + element_count is non-unicast"
        );
        Self {
            element_count,
            element_address: primary_address,
            seq_counters: core::iter::repeat(SeqCounter::default())
                .take(element_count.0.into())
                .collect(),
            config_states: ConfigStates::default(),
            models: Models::default(),

            security_materials: SecurityMaterials {
                iv_update_flag: IVUpdateFlag(false),
                iv_index: IVIndex(0),
                dev_key: DevKey::random_secure(),
                net_key_map: NetKeyMap::new(),
                app_key_map: AppKeyMap::new(),
            },
        }
    }
    /// Returns the assigned unicast address range.
    pub fn unicast_range(&self) -> Range<UnicastAddress> {
        Range {
            start: self.element_address,
            end: UnicastAddress::new(
                u16::from(self.element_address) + u16::from(self.element_count.0),
            ),
        }
    }
    /// Returns the numbers of elements.
    pub fn element_count(&self) -> ElementCount {
        self.element_count
    }
    /// Returns the unicast address of the element at the given `element_index` or `None` if `element_index>=element_count`.
    pub fn element_address(&self, element_index: ElementIndex) -> Option<UnicastAddress> {
        if element_index.0 >= self.element_count.0 {
            None
        } else {
            Some(UnicastAddress::from_mask_u16(
                u16::from(self.element_address) + u16::from(element_index.0),
            ))
        }
    }
    /// Check if the given `unicast_address` is owned by this node. Ex: If this node has 5 elements
    /// and its primary unicast address is `0x0002`, then it owns the range `[0x0002..0x0007]`.
    /// If `unicast_address` is not in that range, this returns `None`.
    pub fn element_index(&self, unicast_address: UnicastAddress) -> Option<ElementIndex> {
        let range = self.unicast_range();
        if range.contains(&unicast_address) {
            Some(ElementIndex(
                u8::try_from(u16::from(range.start) - u16::from(unicast_address))
                    .expect("too many elements"),
            ))
        } else {
            None
        }
    }
    /// IVIndex used for transmitting.
    pub fn tx_iv_index(&self) -> IVIndex {
        self.security_materials.iv_index
    }
    /// IVIndex used for receiving. Will return `None` if no matching `IVIndex` can be found.
    /// See [`IVIndex::matching_flags`] for more.
    pub fn rx_iv_index(&self, ivi: IVI) -> Option<IVIndex> {
        self.security_materials
            .iv_index
            .matching_flags(ivi, self.security_materials.iv_update_flag)
    }
    pub fn iv_index(&self) -> IVIndex {
        self.security_materials.iv_index
    }
    pub fn iv_index_mut(&mut self) -> &mut IVIndex {
        &mut self.security_materials.iv_index
    }
    pub fn iv_update_flag(&self) -> IVUpdateFlag {
        self.security_materials.iv_update_flag
    }
    pub fn iv_update_flag_mut(&mut self) -> &mut IVUpdateFlag {
        &mut self.security_materials.iv_update_flag
    }
    /// The security materials that contains all the required crypto materials for encrypting and
    /// decrypting messages/PDU. Normal operation only requires an immutable reference.
    pub fn security_materials(&self) -> &SecurityMaterials {
        &self.security_materials
    }
    /// The security materials that contains all the required crypto materials for encrypting and
    /// decrypting messages/PDU. A mutable reference is used by the Config Client or other
    /// configuration utilities.
    pub fn security_materials_mut(&mut self) -> &mut SecurityMaterials {
        &mut self.security_materials
    }
    /// Each element has their own `SeqCounter` which is an atomic monotonically increasing
    /// `SequenceNumber` counter.
    /// # Panics
    /// Panics if `element_index >= element_count`.
    pub fn seq_counter(&self, element_index: ElementIndex) -> &SeqCounter {
        self.seq_counters
            .get(usize::from(element_index.0))
            .expect("element_index out of bounds")
    }

    /// # Panics
    /// Panics if `element_index >= element_count`.
    pub fn seq_counter_mut(&mut self, element_index: ElementIndex) -> &mut SeqCounter {
        self.seq_counters
            .get_mut(usize::from(element_index.0))
            .expect("element_index out of bounds")
    }
    pub fn config_states(&self) -> &ConfigStates {
        &self.config_states
    }
    pub fn config_states_mut(&mut self) -> &mut ConfigStates {
        &mut self.config_states
    }
    pub fn default_ttl(&self) -> TTL {
        TTL::new(self.config_states.default_ttl.into())
    }
}

#[derive(Default)]
pub struct DeviceStateBuilder {
    pub element_address: Option<UnicastAddress>,
    pub element_count: Option<ElementCount>,
    pub seq_counters: Option<Vec<SeqCounter>>,
    pub models: Option<Models>,
    pub config_states: Option<ConfigStates>,
    pub security_materials: Option<SecurityMaterials>,
}
impl DeviceStateBuilder {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn new_provisioner() -> Self {
        Self {
            element_address: Some(UnicastAddress::new(1)),
            element_count: Some(ElementCount(1)),
            seq_counters: Some(vec![SeqCounter::default()]),
            models: None,
            config_states: None,
            security_materials: None,
        }
    }
    pub fn element_count(mut self, element_count: ElementCount) -> Self {
        self.element_count = Some(element_count);
        self
    }
    pub fn element_address(mut self, element_address: UnicastAddress) -> Self {
        self.element_address = Some(element_address);
        self
    }
    pub fn config_states(mut self, config_states: ConfigStates) -> Self {
        self.config_states = Some(config_states);
        self
    }
    pub fn finish(self) -> Option<DeviceState> {
        Some(DeviceState {
            element_address: self.element_address?,
            element_count: self.element_count?,
            seq_counters: self.seq_counters?,
            models: self.models?,
            config_states: self.config_states?,
            security_materials: self.security_materials?,
        })
    }
}
//#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct SeqRange(pub core::ops::Range<u32>);
impl SeqRange {
    pub fn new(start: SequenceNumber, end: SequenceNumber) -> Self {
        assert!(start <= end);
        Self(core::ops::Range {
            start: start.0.into(),
            end: end.0.into(),
        })
    }
    pub fn new_segs(start: SequenceNumber, seg_o: SegO) -> Self {
        Self::new(
            start,
            SequenceNumber(U24::new(
                u32::from(start.0) + u32::from(u8::from(seg_o) + 1_u8),
            )),
        )
    }
    pub fn start(&self) -> SequenceNumber {
        SequenceNumber(U24::new(self.0.start))
    }
    pub fn end(&self) -> SequenceNumber {
        SequenceNumber(U24::new(self.0.end))
    }
    pub fn seqs_lefts(&self) -> u32 {
        self.0.end - self.0.start
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
/// Sequence Number.
#[derive(Default, Debug)]
#[cfg_attr(feature = "serde-1", derive(serde::Serialize, serde::Deserialize))]
pub struct SeqCounter(core::sync::atomic::AtomicU32);
impl SeqCounter {
    pub fn new(start_seq: SequenceNumber) -> Self {
        Self(core::sync::atomic::AtomicU32::new(start_seq.0.value()))
    }
    /// Allocates a or some SequenceNumbers and increments the internal counter by amount. Allocating
    /// `amount` Sequence Numbers is useful for Segmented Transport PDUs.
    /// Returns `None` if `SequenceNumber` is at its max or will overflow.
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
    /// Set the atomic sequence number. This should only really be called when initally setuping up
    /// the `SeqCounter` or reseting it. Setting `SeqCounter` to an older value may cause PDUs to be
    /// dropped by message recipients.
    pub fn set_seq(&mut self, new_seq: SequenceNumber) {
        *self.0.get_mut() = new_seq.0.value()
    }
    pub fn check(&self) -> SequenceNumber {
        SequenceNumber(U24::new(self.0.load(Ordering::SeqCst)))
    }
}
impl Clone for SeqCounter {
    fn clone(&self) -> Self {
        SeqCounter(core::sync::atomic::AtomicU32::new(
            self.0.load(Ordering::SeqCst),
        ))
    }
}
