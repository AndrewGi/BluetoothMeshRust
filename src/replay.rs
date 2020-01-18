//! Replay Cache based on a BTreeMap that keeps track of each ivi and seq per src address. Updating
//! the IVIndex causes a 'Garbage Collection' like effect that will delete any cache entries for
//! any 'too' old IVIndices.
use crate::address::UnicastAddress;
use crate::mesh::{SequenceNumber, IVI};

use crate::net::PrivateHeader;
use alloc::collections::btree_map::Entry;
use alloc::collections::BTreeMap;

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct CacheEntry {
    seq: SequenceNumber,
    ivi: IVI,
}
impl CacheEntry {
    pub fn is_old_header(&self, ivi: IVI, seq: SequenceNumber) -> Option<bool> {
        if self.ivi == ivi {
            Some(self.seq < seq)
        } else {
            None
        }
    }
}
impl From<PrivateHeader<'_>> for CacheEntry {
    fn from(p: PrivateHeader<'_>) -> Self {
        CacheEntry {
            seq: p.seq(),
            ivi: p.ivi(),
        }
    }
}
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default)]
pub struct Cache {
    map: BTreeMap<UnicastAddress, CacheEntry>,
}
impl Cache {
    pub fn new() -> Cache {
        Cache::default()
    }
    pub fn get_entry(&self, address: UnicastAddress) -> Option<&CacheEntry> {
        self.map.get(&address)
    }
    pub fn is_old_header(
        &self,
        src: UnicastAddress,
        ivi: IVI,
        seq: SequenceNumber,
    ) -> Option<bool> {
        self.get_entry(src)?.is_old_header(ivi, seq)
    }
    /// Returns `true` if the `header` is old or `false` if the `header` is new and valid.
    /// If no information about the source of the PDU (Src and Seq), it records the header
    /// and returns `false`
    pub fn replay_check(&mut self, src: UnicastAddress, seq: SequenceNumber, ivi: IVI) -> bool {
        match self.map.entry(src) {
            Entry::Vacant(v) => {
                v.insert(CacheEntry { seq, ivi });
                false
            }
            Entry::Occupied(mut o) => {
                if o.get().is_old_header(ivi, seq).unwrap_or(false) {
                    true
                } else {
                    o.insert(CacheEntry { seq, ivi });
                    false
                }
            }
        }
    }
}
