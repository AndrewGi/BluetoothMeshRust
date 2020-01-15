7pub mod beacon {
    use crate::foundation::state::SecureNetworkBeaconState;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get;
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Set(pub SecureNetworkBeaconState);
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status(pub SecureNetworkBeaconState);
}

pub mod composition_data {
    use crate::foundation::CompositionDataPage0;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get(u8);
    #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status {
        page_number: u8,
        page: CompositionDataPage0,
    }
}
pub mod default_ttl {
    use crate::foundation::state::DefaultTTLState;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get;
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Set(pub DefaultTTLState);
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status(pub DefaultTTLState);
}
pub mod gatt_proxy {
    use crate::foundation::state::GATTProxyState;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get;
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Set(pub GATTProxyState);
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status(pub GATTProxyState);
}
pub mod relay {
    use crate::foundation::state::{RelayRetransmit, RelayState};
    use crate::models::PackableMessage;
    use crate::access::Opcode;
    use crate::models::config::ConfigOpcode;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get;
    impl PackableMessage for Get {
        fn opcode() -> Opcode {
            ConfigOpcode::RelayGet.into();
        }

        fn message_size(&self) -> usize {
            unimplemented!()
        }

        fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError> {
            unimplemented!()
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            unimplemented!()
        }
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Set(pub RelayState, pub RelayRetransmit);
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status(pub RelayState, pub RelayRetransmit);
}
pub mod model_publication {
    use crate::access::{ModelIdentifier, Opcode};
    use crate::address::{UnicastAddress, ADDRESS_LEN};
    use crate::foundation::publication::ModelPublishInfo;
    use crate::models::{MessagePackError, PackableMessage};
    use crate::serializable::bytes::ToFromBytesEndian;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get {
        pub element_address: UnicastAddress,
        pub model_identifier: ModelIdentifier,
    }

    impl PackableMessage for Get {
        const OPCODE: Opcode = unimplemented!();

        fn message_size(&self) -> usize {
            ADDRESS_LEN + self.model_identifier.byte_len()
        }

        fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError> {
            if buffer.len() < self.message_size() {
                Err(MessagePackError::SmallBuffer)
            } else {
                buffer[0..2].copy_from_slice(&self.element_address.to_bytes_le());
                self.model_identifier.pack_into(&mut buffer[2..]);
                Ok(())
            }
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            const SIG_LEN: usize = ADDRESS_LEN + ModelIdentifier::vendor_byte_len();
            const VENDOR_LEN: usize = ADDRESS_LEN + ModelIdentifier::vendor_byte_len();
            if buffer.len() == SIG_LEN || buffer.len() == VENDOR_LEN {
                Ok(Get {
                    element_address: UnicastAddress::from_bytes_le(&buffer[0..2])
                        .ok_or(MessagePackError::BadBytes)?,
                    model_identifier: ModelIdentifier::unpack_from(&buffer[2..])
                        .ok_or(MessagePackError::BadBytes)?,
                })
            } else {
                None
            }
        }
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Set {
        pub element_address: UnicastAddress,
        pub publication: ModelPublishInfo,
        pub model_identifier: ModelIdentifier,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status {
        pub element_address: UnicastAddress,
        pub publication: ModelPublishInfo,
        pub model_identifier: ModelIdentifier,
    }
}
pub mod model_subscription {
    use crate::access::ModelIdentifier;
    use crate::address::{Address, UnicastAddress};
    use crate::foundation::StatusCode;
    use crate::mesh::ModelID;
    use alloc::vec::Vec;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Add {
        pub element_address: UnicastAddress,
        pub address: Address,
        pub model_identifier: ModelIdentifier,
    }

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Delete {
        pub element_address: UnicastAddress,
        pub address: Address,
        pub model_identifier: ModelIdentifier,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Overwrite {
        pub element_address: UnicastAddress,
        pub address: Address,
        pub model_identifier: ModelIdentifier,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct DeleteAll {
        pub element_address: UnicastAddress,
        pub model_identifier: ModelIdentifier,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status {
        pub status_code: StatusCode,
        pub element_address: UnicastAddress,
        pub address: Address,
        pub model_identifier: ModelIdentifier,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get {
        pub element_address: UnicastAddress,
        pub model_identifier: ModelIdentifier,
    }
    #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct List {
        pub status_code: StatusCode,
        pub element_address: UnicastAddress,
        pub model_identifier: ModelIdentifier,
        pub addresses: Vec<Address>,
    }
}
pub mod net_key_list {
    use crate::crypto::key::NetKey;
    use crate::crypto::NetKeyIndex;
    use crate::foundation::StatusCode;
    use alloc::vec::Vec;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Add {
        pub index: NetKeyIndex,
        pub key: NetKey,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Update {
        pub index: NetKeyIndex,
        pub key: NetKey,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Delete {
        pub index: NetKeyIndex,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status {
        pub status_code: StatusCode,
        pub index: NetKeyIndex,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get;
    #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct List {
        pub indexes: Vec<NetKeyIndex>,
    }
}
pub mod app_key_list {
    use crate::crypto::key::{AppKey, NetKey};
    use crate::crypto::NetKeyIndex;
    use crate::foundation::StatusCode;
    use crate::mesh::AppKeyIndex;
    use alloc::vec::Vec;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Add {
        pub net_index: NetKeyIndex,
        pub app_index: AppKeyIndex,
        pub app_key: AppKey,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Update {
        pub net_index: NetKeyIndex,
        pub app_index: AppKeyIndex,
        pub app_key: AppKey,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Delete {
        pub net_index: NetKeyIndex,
        pub app_index: AppKeyIndex,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status {
        pub status_code: StatusCode,
        pub net_index: NetKeyIndex,
        pub app_index: AppKeyIndex,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get(NetKeyIndex);
    #[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct List {
        pub status_code: StatusCode,
        pub net_index: NetKeyIndex,
        pub indexes: Vec<NetKeyIndex>,
    }
}
