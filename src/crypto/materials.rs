use crate::crypto::key::{BeaconKey, EncryptionKey, IdentityKey, NetKey, PrivacyKey};
use crate::crypto::{k2, KeyRefreshPhases, NetKeyIndex, NetworkID};
use crate::mesh::NID;
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
    pub fn encryption_key(&self) -> EncryptionKey {
        self.encryption
    }
    pub fn privacy_key(&self) -> PrivacyKey {
        self.privacy
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
