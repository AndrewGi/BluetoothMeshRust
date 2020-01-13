use crate::access::ModelIdentifier;
use crate::address::{Address, UnicastAddress};
use crate::mesh::{AppKeyIndex, TTL};
use alloc::collections::BTreeMap;

pub struct ModelPublication {
    address: Address,
    app_key_index: AppKeyIndex,
    credential_flag: bool,
    ttl: TTL,
    //period: PublishPeri,
}

pub struct Element {
    address: UnicastAddress,
    //models: BTreeMap<ModelIdentifier, ModelPublication>,
}
