//! Collection of security materials (Keys, NID, AID, etc) used for encryption and decryption.
use crate::crypto::key::{
    AppKey, BeaconKey, DevKey, EncryptionKey, IdentityKey, NetKey, PrivacyKey,
};
use crate::crypto::{k2, KeyRefreshPhases, NetworkID, AID};
use crate::mesh::{AppKeyIndex, NetKeyIndex, NID};
use alloc::collections::btree_map;
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct NetworkKeys {
    nid: NID,
    encryption: EncryptionKey,
    privacy: PrivacyKey,
}

impl NetworkKeys {
    pub fn new(nid: NID, encryption: EncryptionKey, privacy: PrivacyKey) -> Self {
        Self {
            nid,
            encryption,
            privacy,
        }
    }
    pub fn nid(&self) -> NID {
        self.nid
    }
    pub fn encryption_key(&self) -> &EncryptionKey {
        &self.encryption
    }
    pub fn privacy_key(&self) -> &PrivacyKey {
        &self.privacy
    }
}
impl From<&NetKey> for NetworkKeys {
    fn from(k: &NetKey) -> Self {
        let (nid, encryption, privacy) = k2(k.key(), b"\x00");
        Self::new(nid, encryption, privacy)
    }
}
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct NetworkSecurityMaterials {
    net_key: NetKey,
    network_keys: NetworkKeys,
    network_id: NetworkID,
    identity_key: IdentityKey,
    beacon_key: BeaconKey,
}
impl NetworkSecurityMaterials {
    pub fn net_key(&self) -> &NetKey {
        &self.net_key
    }
    pub fn network_keys(&self) -> &NetworkKeys {
        &self.network_keys
    }
    pub fn network_id(&self) -> NetworkID {
        self.network_id
    }
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }
    pub fn beacon_key(&self) -> &BeaconKey {
        &self.beacon_key
    }
}
impl NetworkSecurityMaterials {}
impl From<&NetKey> for NetworkSecurityMaterials {
    fn from(k: &NetKey) -> Self {
        Self {
            net_key: *k,
            network_keys: k.into(),
            network_id: k.into(),
            identity_key: k.into(),
            beacon_key: k.into(),
        }
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct KeyPair<K: Clone + Copy + Eq + PartialEq> {
    pub new: K,
    pub old: K,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum KeyPhase<K: Clone + Copy + Eq + PartialEq> {
    Normal(K),
    Phase1(KeyPair<K>),
    Phase2(KeyPair<K>),
}
impl<K: Clone + Copy + Eq> KeyPhase<K> {
    pub fn phase(&self) -> KeyRefreshPhases {
        match self {
            KeyPhase::Normal(_) => KeyRefreshPhases::Normal,
            KeyPhase::Phase1(_) => KeyRefreshPhases::First,
            KeyPhase::Phase2(_) => KeyRefreshPhases::Second,
        }
    }
    pub fn tx_key(&self) -> &K {
        match self {
            KeyPhase::Normal(k) => k,
            KeyPhase::Phase1(p) => &p.old,
            KeyPhase::Phase2(p) => &p.new,
        }
    }
    pub fn rx_keys(&self) -> (&K, Option<&K>) {
        match self {
            KeyPhase::Normal(k) => (k, None),
            KeyPhase::Phase1(p) => (&p.old, Some(&p.new)),
            KeyPhase::Phase2(p) => (&p.new, Some(&p.old)),
        }
    }
    pub fn key_pair(&self) -> Option<&KeyPair<K>> {
        match self {
            KeyPhase::Normal(_) => None,
            KeyPhase::Phase1(p) => Some(p),
            KeyPhase::Phase2(p) => Some(p),
        }
    }
}

pub struct NetKeyMap {
    map: btree_map::BTreeMap<NetKeyIndex, KeyPhase<NetworkSecurityMaterials>>,
}
impl NetKeyMap {
    pub fn new() -> Self {
        Self {
            map: btree_map::BTreeMap::new(),
        }
    }

    /// Returns all `NetworkSecurityMaterials` matching `nid_to_match`. Because `NID` is a 7-bit value,
    /// one `NID` can match multiple different networks. For this reason, this functions returns an
    /// iterator that yields each matching network security materials. Only attempting to decrypt
    /// the Network PDU (and it failing/succeeding) will tell you if the `NID` and `NetworkKeys` match.
    pub fn matching_nid(
        &self,
        nid_to_match: NID,
    ) -> impl Iterator<Item = (NetKeyIndex, &'_ NetworkSecurityMaterials)> {
        self.map.iter().filter_map(move |(&index, phase)| {
            let keys = phase.rx_keys();
            if keys.0.network_keys.nid == nid_to_match {
                Some((index, keys.0))
            } else {
                match keys.1 {
                    Some(sm) if sm.network_keys.nid == nid_to_match => Some((index, sm)),
                    _ => None,
                }
            }
        })
    }
    pub fn get_keys(&self, index: NetKeyIndex) -> Option<&KeyPhase<NetworkSecurityMaterials>> {
        self.map.get(&index)
    }
    pub fn get_keys_mut(
        &mut self,
        index: NetKeyIndex,
    ) -> Option<&mut KeyPhase<NetworkSecurityMaterials>> {
        self.map.get_mut(&index)
    }
    pub fn remove_keys(
        &mut self,
        index: NetKeyIndex,
    ) -> Option<KeyPhase<NetworkSecurityMaterials>> {
        self.map.remove(&index)
    }
}
pub struct ApplicationSecurityMaterials {
    pub app_key: AppKey,
    pub aid: AID,
    pub net_key_index: NetKeyIndex,
}
impl ApplicationSecurityMaterials {
    pub fn new(app_key: AppKey, net_key_index: NetKeyIndex) -> Self {
        Self {
            app_key,
            aid: app_key.aid(),
            net_key_index,
        }
    }
}
pub struct AppKeyMap {
    map: btree_map::BTreeMap<AppKeyIndex, ApplicationSecurityMaterials>,
}
impl AppKeyMap {
    pub fn new() -> Self {
        Self {
            map: btree_map::BTreeMap::new(),
        }
    }

    pub fn get_key(&self, index: AppKeyIndex) -> Option<&ApplicationSecurityMaterials> {
        self.map.get(&index)
    }
    pub fn get_key_mut(&mut self, index: AppKeyIndex) -> Option<&mut ApplicationSecurityMaterials> {
        self.map.get_mut(&index)
    }
    pub fn remove_key(&mut self, index: AppKeyIndex) -> Option<ApplicationSecurityMaterials> {
        self.map.remove(&index)
    }
}

pub struct SecurityMaterials {
    pub dev_key: DevKey,
    pub net_key_map: NetKeyMap,
    pub app_key_map: AppKeyMap,
}
