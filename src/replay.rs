//! Replay Cache based on a BTreeMap that keeps track of each ivi and seq per src address. Updating
//! the IVIndex causes a 'Garbage Collection' like effect that will delete any cache entries for
//! any 'too' old IVIndices.
use crate::address::UnicastAddress;
use crate::mesh::{SequenceNumber, IVI};

use crate::lower::SeqZero;
use crate::net::PrivateHeader;
use alloc::collections::btree_map::Entry;
use alloc::collections::BTreeMap;

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
#[cfg_attr(feature = "serde-1", derive(serde::Serialize, serde::Deserialize))]
pub struct CacheEntry {
    seq: SequenceNumber,
    ivi: IVI,
    seq_zero: Option<SeqZero>,
}
impl CacheEntry {
    /// Returns (if seq is old, if seq_zero is old).
    pub fn is_old_header(
        &self,
        ivi: IVI,
        seq: SequenceNumber,
        seq_zero: Option<SeqZero>,
    ) -> Option<(bool, bool)> {
        if self.ivi == ivi {
            let is_old_seq = match (self.seq_zero, seq_zero) {
                (Some(old_seq), Some(new_seq)) => old_seq >= new_seq,
                _ => false,
            };
            Some((self.seq >= seq, is_old_seq))
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
            seq_zero: None,
        }
    }
}
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default)]
#[cfg_attr(feature = "serde-1", derive(serde::Serialize, serde::Deserialize))]
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
        seq_zero: Option<SeqZero>,
    ) -> Option<(bool, bool)> {
        self.get_entry(src)?.is_old_header(ivi, seq, seq_zero)
    }
    pub fn update_seq_zero(&mut self, src: UnicastAddress, ivi: IVI, seq_zero: SeqZero) {
        match self.map.entry(src) {
            Entry::Vacant(_) => {}
            Entry::Occupied(mut o) => {
                if o.get().ivi == ivi {
                    o.get_mut().seq_zero = Some(seq_zero)
                }
            }
        }
    }
    /// Returns `true` if the `header` is old or `false` if the `header` is new and valid.
    /// If no information about the source of the PDU (Src and Seq), it records the header
    /// and returns `false`
    pub fn replay_net_check(
        &mut self,
        src: UnicastAddress,
        seq: SequenceNumber,
        ivi: IVI,
        seq_zero: Option<SeqZero>,
    ) -> (bool, bool) {
        match self.map.entry(src) {
            Entry::Vacant(v) => {
                v.insert(CacheEntry {
                    seq,
                    ivi,
                    seq_zero: None,
                });
                (false, false)
            }
            Entry::Occupied(mut o) => {
                match o.get().is_old_header(ivi, seq, seq_zero) {
                    None => (false, false), // IVI doesn't match
                    Some((is_old_seq, is_old_seq_zero)) => {
                        // If Seq is old, update it
                        if is_old_seq {
                            o.insert(CacheEntry {
                                seq,
                                ivi,
                                seq_zero: None,
                            });
                        }
                        (is_old_seq, is_old_seq_zero)
                    }
                }
            }
        }
    }
}
