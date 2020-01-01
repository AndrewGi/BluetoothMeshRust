//! PB-ADV Provisioning bearer for Bluetooth Mesh
use super::generic;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct LinkID(u32);

impl LinkID {
    pub fn new(link_id: u32) -> LinkID {
        LinkID(link_id)
    }
    pub fn value(&self) -> u32 {
        self.0
    }
}
const PROVISIONEE_START: u8 = 0x80;
const PROVISIONEE_END: u8 = 0xFF;

const PROVISIONER_START: u8 = 0;
const PROVISIONER_END: u8 = 0x7F;
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct TransactionNumber(u8);
impl TransactionNumber {
    pub fn new(trans_num: u8) -> TransactionNumber {
        TransactionNumber(trans_num)
    }
    pub fn value(&self) -> u8 {
        self.0
    }
    pub fn new_provisionee() -> TransactionNumber {
        Self::new(PROVISIONEE_START)
    }
    pub fn new_provisioner() -> TransactionNumber {
        Self::new(PROVISIONER_START)
    }
    pub fn is_provisionee(&self) -> bool {
        self.0 >= PROVISIONEE_START && self.0 <= PROVISIONEE_END
    }
    pub fn is_provisioner(&self) -> bool {
        self.0 >= PROVISIONER_START && self.0 <= PROVISIONER_END
    }
    pub fn next(&self) -> TransactionNumber {
        // Provisionee 0x80-0xFF
        // Provisioner 0x00-0x7F
        // Check if were at the end of the range and we have to wrap to the start
        if self.is_provisionee() {
            if self.0 == PROVISIONEE_END {
                return Self::new(PROVISIONEE_START);
            }
        } else {
            if self.0 == PROVISIONER_END {
                return Self::new(PROVISIONER_START);
            }
        }
        Self::new(self.0 + 1)
    }
    /// Same as calling `next()` but modifies the TransactionNumber instead of returning a new one
    pub fn increment(&mut self) {
        let next = self.next();
        *self = next;
    }
}
impl From<u8> for TransactionNumber {
    fn from(b: u8) -> Self {
        TransactionNumber(b)
    }
}
impl From<TransactionNumber> for u8 {
    fn from(num: TransactionNumber) -> Self {
        num.0
    }
}
pub struct PDU {
    link_id: LinkID,
    transaction_number: TransactionNumber,
    generic_pdu: generic::PDU,
}
