use crate::provisioning::pb_adv;
use crate::provisioning::pb_adv::{LinkID, TransactionNumber};
use alloc::collections::BTreeSet;
use core::sync::atomic::Ordering;
#[derive(Debug)]
pub struct AtomicTransactionNumber(core::sync::atomic::AtomicU8);
impl AtomicTransactionNumber {
    pub fn new(num: TransactionNumber) -> Self {
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
pub struct Links {
    links: BTreeSet<Link>,
}
impl Links {
    pub fn handle_pb_adv_pdu(&mut self, _pdu: &pb_adv::PDU) {
        unimplemented!()
    }
}
pub enum LinkError {
    Closed,
}
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct Link {
    link_id: LinkID,
    my_transaction_number: AtomicTransactionNumber,
    other_transaction_number: Option<AtomicTransactionNumber>,
}
impl Link {
    pub fn handle_pb_adv_pdu(&self, pdu: &pb_adv::PDU) {
        if pdu.link_id != self.link_id {
            return;
        }
    }
}
