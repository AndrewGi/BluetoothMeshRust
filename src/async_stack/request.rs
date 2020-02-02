use crate::address::Address;
use crate::mesh::AppKeyIndex;

pub struct Destination {
    pub address: Address,
    pub index: AppKeyIndex,
}

pub struct Request {}
