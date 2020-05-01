use crate::provisioning::pb_adv;
use crate::provisioning::pb_adv::{LinkID, TransactionNumber};
use crate::uuid::UUID;
use alloc::collections::BTreeSet;
use core::sync::atomic::Ordering;

#[derive(Debug)]
pub struct AtomicTransactionNumber(core::sync::atomic::AtomicU8);
impl AtomicTransactionNumber {
    pub const fn new(num: TransactionNumber) -> Self {
        Self(core::sync::atomic::AtomicU8::new(num.0))
    }
    pub fn get(&self) -> TransactionNumber {
        TransactionNumber(self.0.load(Ordering::SeqCst))
    }
    pub fn set(&self, new_number: TransactionNumber) {
        self.0.store(new_number.0, Ordering::SeqCst);
    }
}
impl Clone for AtomicTransactionNumber {
    fn clone(&self) -> Self {
        Self::new(self.get())
    }
}
impl PartialEq for AtomicTransactionNumber {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}
impl Eq for AtomicTransactionNumber {}
impl PartialOrd for AtomicTransactionNumber {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.get().partial_cmp(&other.get())
    }
}
impl Ord for AtomicTransactionNumber {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.get().cmp(&other.get())
    }
}
pub enum Link {
    Open(OpenLink),
    Pending(PendingLink),
}
pub struct Links {
    links: BTreeSet<Link>,
}
impl Links {
    // C
    pub fn open_uuid(&mut self, _uuid: &UUID) -> Option<PendingLink> {
        unimplemented!()
    }
    pub fn handle_pb_adv_pdu(&mut self, _pdu: &pb_adv::PDU) {
        unimplemented!()
    }
}
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct PendingLink {
    link_id: LinkID,
}
impl PendingLink {
    pub fn handle_pb_adv_pdu(&self, _pdu: &pb_adv::PDU) {}
}
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct OpenLink {
    link_id: LinkID,
    my_transaction_number: AtomicTransactionNumber,
    other_transaction_number: Option<AtomicTransactionNumber>,
}
impl OpenLink {
    pub fn handle_pb_adv_pdu(&self, pdu: &pb_adv::PDU) {
        if pdu.link_id != self.link_id {
            return;
        }
    }
}
