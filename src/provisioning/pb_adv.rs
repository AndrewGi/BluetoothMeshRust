//! PB-ADV Provisioning bearer for Bluetooth Mesh
use super::generic;
use crate::provisioning::generic::GENERIC_PDU_MAX_LEN;
use btle::bytes::Storage;
use btle::{PackError, RSSI};
use std::convert::TryInto;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct LinkID(u32);

impl LinkID {
    pub const BYTE_LEN: usize = 4;
    pub fn new(link_id: u32) -> LinkID {
        LinkID(link_id)
    }
    pub fn value(self) -> u32 {
        self.0
    }
}
const PROVISIONEE_START: u8 = 0x80;
const PROVISIONEE_END: u8 = 0xFF;

const PROVISIONER_START: u8 = 0;
const PROVISIONER_END: u8 = 0x7F;
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct TransactionNumber(pub u8);
impl TransactionNumber {
    pub const BYTE_LEN: usize = 1;
    pub const fn new(trans_num: u8) -> TransactionNumber {
        TransactionNumber(trans_num)
    }
    pub const fn value(self) -> u8 {
        self.0
    }
    pub const fn new_provisionee() -> TransactionNumber {
        Self::new(PROVISIONEE_START)
    }
    pub const fn new_provisioner() -> TransactionNumber {
        Self::new(PROVISIONER_START)
    }
    pub fn is_provisionee(self) -> bool {
        self.0 >= PROVISIONEE_START && self.0 <= PROVISIONEE_END
    }
    pub fn is_provisioner(self) -> bool {
        self.0 >= PROVISIONER_START && self.0 <= PROVISIONER_END
    }
    pub fn next(self) -> TransactionNumber {
        // Provisionee 0x80-0xFF
        // Provisioner 0x00-0x7F
        // Check if were at the end of the range and we have to wrap to the start
        if self.is_provisionee() {
            if self.0 == PROVISIONEE_END {
                return Self::new(PROVISIONEE_START);
            }
        } else if self.0 == PROVISIONER_END {
            return Self::new(PROVISIONER_START);
        }
        Self::new(self.0 + 1)
    }
    pub fn prev(self) -> TransactionNumber {
        // Provisionee 0x80-0xFF
        // Provisioner 0x00-0x7F
        // Check if were at the end of the range and we have to wrap to the start
        if self.is_provisionee() {
            if self.0 == PROVISIONEE_START {
                return Self::new(PROVISIONEE_END);
            }
        } else if self.0 == PROVISIONER_START {
            return Self::new(PROVISIONER_END);
        }
        Self::new(self.0 - 1)
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
    #[must_use]
    fn from(num: TransactionNumber) -> Self {
        num.0
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PDU<B: AsRef<[u8]>> {
    pub link_id: LinkID,
    pub transaction_number: TransactionNumber,
    pub generic_pdu: generic::PDU<B>,
}
impl<B: AsRef<[u8]>> core::fmt::Debug for PDU<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PDU<B>")
            .field("link_id", &self.link_id)
            .field("transaction_number", &self.transaction_number)
            .field("generic_pdu", &self.generic_pdu)
            .finish()
    }
}
impl<B: Storage<u8>> PDU<B> {
    pub const HEADER_BYTE_LEN: usize = LinkID::BYTE_LEN + TransactionNumber::BYTE_LEN;
    pub const MIN_BYTE_LEN: usize = Self::HEADER_BYTE_LEN + 1;
    pub const MAX_BYTE_LEN: usize = Self::HEADER_BYTE_LEN + GENERIC_PDU_MAX_LEN;
    pub fn byte_len(&self) -> usize {
        LinkID::BYTE_LEN + TransactionNumber::BYTE_LEN + self.generic_pdu.byte_len()
    }
    pub fn pack_into(&self, buf: &mut [u8]) -> Result<(), PackError> {
        PackError::expect_length(self.byte_len(), buf)?;
        self.generic_pdu
            .pack_into(&mut buf[LinkID::BYTE_LEN + TransactionNumber::BYTE_LEN..])?;
        buf[..LinkID::BYTE_LEN].copy_from_slice(self.link_id.0.to_be_bytes().as_ref());
        buf[LinkID::BYTE_LEN] = self.transaction_number.0;
        Ok(())
    }
    pub fn unpack_from(buf: &[u8]) -> Result<Self, PackError> {
        PackError::atleast_length(Self::MIN_BYTE_LEN, buf)?;
        Ok(PDU {
            generic_pdu: generic::PDU::unpack_from(&buf[Self::HEADER_BYTE_LEN..])?,
            link_id: LinkID(u32::from_be_bytes(
                (&buf[..LinkID::BYTE_LEN])
                    .try_into()
                    .expect("array checked above"),
            )),
            transaction_number: TransactionNumber(buf[LinkID::BYTE_LEN]),
        })
    }
}
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct IncomingPDU<B: AsRef<[u8]>> {
    pub pdu: PDU<B>,
    pub rssi: Option<RSSI>,
}
impl<B: AsRef<[u8]>> core::fmt::Debug for IncomingPDU<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IncomingPDU<B>")
            .field("pdu", &self.pdu)
            .field("rssi", &self.rssi)
            .finish()
    }
}
pub struct PackedPDU {}
impl AsRef<[u8]> for PackedPDU {
    fn as_ref(&self) -> &[u8] {
        unimplemented!()
    }
}
