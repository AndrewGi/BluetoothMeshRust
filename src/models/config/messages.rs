pub mod beacon {
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
    use crate::access::Opcode;
    use crate::foundation::state::DefaultTTLState;
    use crate::models::config::ConfigOpcode;
    use crate::models::{MessagePackError, PackableMessage};
    use core::convert::TryInto;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get;
    impl PackableMessage for Get {
        fn opcode() -> Opcode {
            ConfigOpcode::DefaultTTLGet.into()
        }

        fn message_size(&self) -> usize {
            0
        }

        fn pack_into(&self, _buffer: &mut [u8]) -> Result<(), MessagePackError> {
            Ok(())
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            if buffer.is_empty() {
                Ok(Get)
            } else {
                Err(MessagePackError::BadLength)
            }
        }
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Set(pub DefaultTTLState);
    impl PackableMessage for Set {
        fn opcode() -> Opcode {
            ConfigOpcode::DefaultTTLSet.into()
        }

        fn message_size(&self) -> usize {
            1
        }

        fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError> {
            if buffer.is_empty() {
                Err(MessagePackError::SmallBuffer)
            } else {
                buffer[0] = self.0.into();
                Ok(())
            }
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            if buffer.len() == 1 {
                Ok(Set(buffer[0]
                    .try_into()
                    .map_err(|_| MessagePackError::BadBytes)?))
            } else {
                Err(MessagePackError::BadLength)
            }
        }
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status(pub DefaultTTLState);
    impl PackableMessage for Status {
        fn opcode() -> Opcode {
            ConfigOpcode::DefaultTTLStatus.into()
        }

        fn message_size(&self) -> usize {
            1
        }

        fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError> {
            if buffer.is_empty() {
                Err(MessagePackError::SmallBuffer)
            } else {
                buffer[0] = self.0.into();
                Ok(())
            }
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            if buffer.len() == 1 {
                Ok(Status(
                    buffer[0]
                        .try_into()
                        .map_err(|_| MessagePackError::BadBytes)?,
                ))
            } else {
                Err(MessagePackError::BadLength)
            }
        }
    }
}
pub mod gatt_proxy {
    use crate::access::Opcode;
    use crate::foundation::state::GATTProxyState;
    use crate::models::config::ConfigOpcode;
    use crate::models::{MessagePackError, PackableMessage};
    use core::convert::TryInto;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get;

    impl PackableMessage for Get {
        fn opcode() -> Opcode {
            ConfigOpcode::GATTProxyGet.into()
        }

        fn message_size(&self) -> usize {
            0
        }

        fn pack_into(&self, _buffer: &mut [u8]) -> Result<(), MessagePackError> {
            Ok(())
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            if buffer.is_empty() {
                Ok(Get)
            } else {
                Err(MessagePackError::BadLength)
            }
        }
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Set(pub GATTProxyState);
    impl PackableMessage for Set {
        fn opcode() -> Opcode {
            ConfigOpcode::GATTProxySet.into()
        }

        fn message_size(&self) -> usize {
            1
        }

        fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError> {
            if buffer.is_empty() {
                Err(MessagePackError::SmallBuffer)
            } else {
                buffer[0] = self.0.into();
                Ok(())
            }
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            if buffer.len() == 1 {
                Ok(Set(buffer[0]
                    .try_into()
                    .map_err(|_| MessagePackError::BadBytes)?))
            } else {
                Err(MessagePackError::BadLength)
            }
        }
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status(pub GATTProxyState);
    impl PackableMessage for Status {
        fn opcode() -> Opcode {
            ConfigOpcode::GATTProxyStatus.into()
        }

        fn message_size(&self) -> usize {
            1
        }

        fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError> {
            if buffer.is_empty() {
                Err(MessagePackError::SmallBuffer)
            } else {
                buffer[0] = self.0.into();
                Ok(())
            }
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            if buffer.len() == 1 {
                Ok(Status(
                    buffer[0]
                        .try_into()
                        .map_err(|_| MessagePackError::BadBytes)?,
                ))
            } else {
                Err(MessagePackError::BadLength)
            }
        }
    }
}
pub mod relay {
    use crate::access::Opcode;
    use crate::foundation::state::{RelayRetransmit, RelayState};
    use crate::models::config::ConfigOpcode;
    use crate::models::{MessagePackError, PackableMessage};
    use core::convert::TryInto;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get;
    impl PackableMessage for Get {
        fn opcode() -> Opcode {
            ConfigOpcode::RelayGet.into()
        }

        fn message_size(&self) -> usize {
            0
        }

        fn pack_into(&self, _buffer: &mut [u8]) -> Result<(), MessagePackError> {
            Ok(())
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            if buffer.is_empty() {
                Ok(Get)
            } else {
                Err(MessagePackError::BadLength)
            }
        }
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Set(pub RelayState, pub RelayRetransmit);
    impl PackableMessage for Set {
        fn opcode() -> Opcode {
            ConfigOpcode::RelaySet.into()
        }

        fn message_size(&self) -> usize {
            2
        }

        fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError> {
            if buffer.len() < self.message_size() {
                Err(MessagePackError::SmallBuffer)
            } else {
                buffer[0] = self.0.into();
                buffer[1] = (self.1).0.into();
                Ok(())
            }
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            if buffer.len() != 2 {
                Err(MessagePackError::BadLength)
            } else {
                Ok(Set(
                    buffer[0]
                        .try_into()
                        .map_err(|_| MessagePackError::BadBytes)?,
                    RelayRetransmit(
                        buffer[1]
                            .try_into()
                            .map_err(|_| MessagePackError::BadBytes)?,
                    ),
                ))
            }
        }
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status(pub RelayState, pub RelayRetransmit);
    impl PackableMessage for Status {
        fn opcode() -> Opcode {
            ConfigOpcode::RelayStatus.into()
        }

        fn message_size(&self) -> usize {
            2
        }

        fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError> {
            if buffer.len() < self.message_size() {
                Err(MessagePackError::SmallBuffer)
            } else {
                buffer[0] = self.0.into();
                buffer[1] = (self.1).0.into();
                Ok(())
            }
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            if buffer.len() != 2 {
                Err(MessagePackError::BadLength)
            } else {
                Ok(Status(
                    buffer[0]
                        .try_into()
                        .map_err(|_| MessagePackError::BadBytes)?,
                    RelayRetransmit(
                        buffer[1]
                            .try_into()
                            .map_err(|_| MessagePackError::BadBytes)?,
                    ),
                ))
            }
        }
    }
}
pub mod model_publication {
    use crate::access::{ModelIdentifier, Opcode};
    use crate::address::{Address, UnicastAddress, ADDRESS_LEN};
    use crate::foundation::publication::ModelPublishInfo;
    use crate::foundation::StatusCode;
    use crate::models::config::ConfigOpcode;
    use crate::models::{MessagePackError, PackableMessage};
    use crate::serializable::bytes::ToFromBytesEndian;
    use core::convert::TryInto;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Get {
        pub element_address: UnicastAddress,
        pub model_identifier: ModelIdentifier,
    }

    impl PackableMessage for Get {
        fn opcode() -> Opcode {
            ConfigOpcode::ModelPublicationGet.into()
        }

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
                Err(MessagePackError::BadLength)
            }
        }
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct NonVirtualSet {
        pub element_address: UnicastAddress,
        pub publication: ModelPublishInfo,
        pub model_identifier: ModelIdentifier,
    }
    impl PackableMessage for NonVirtualSet {
        fn opcode() -> Opcode {
            ConfigOpcode::ModelPublicationSet.into()
        }

        fn message_size(&self) -> usize {
            ADDRESS_LEN + ModelPublishInfo::NON_VIRTUAL_LEN + self.model_identifier.byte_len()
        }

        fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError> {
            if buffer.len() < self.message_size() {
                Err(MessagePackError::SmallBuffer)
            } else if self.publication.address.is_virtual() {
                Err(MessagePackError::BadState)
            } else {
                buffer[0..ADDRESS_LEN].copy_from_slice(&self.element_address.to_bytes_le());
                self.publication.pack_into(
                    &mut buffer[ADDRESS_LEN..ADDRESS_LEN + ModelPublishInfo::NON_VIRTUAL_LEN],
                );
                self.model_identifier
                    .pack_into(&mut buffer[ADDRESS_LEN + ModelPublishInfo::NON_VIRTUAL_LEN..]);
                Ok(())
            }
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            const SIG_LEN: usize = ADDRESS_LEN
                + ModelPublishInfo::NON_VIRTUAL_LEN
                + ModelIdentifier::vendor_byte_len();
            const VENDOR_LEN: usize = ADDRESS_LEN
                + ModelPublishInfo::NON_VIRTUAL_LEN
                + ModelIdentifier::vendor_byte_len();
            if buffer.len() == SIG_LEN || buffer.len() == VENDOR_LEN {
                Ok(NonVirtualSet {
                    element_address: UnicastAddress::from_bytes_le(&buffer[..ADDRESS_LEN])
                        .ok_or(MessagePackError::BadBytes)?,
                    publication: ModelPublishInfo::unpack(
                        &buffer[ADDRESS_LEN..ADDRESS_LEN + ModelPublishInfo::NON_VIRTUAL_LEN],
                    )
                    .ok_or(MessagePackError::BadBytes)?,
                    model_identifier: ModelIdentifier::unpack_from(
                        &buffer[ModelPublishInfo::NON_VIRTUAL_LEN + ADDRESS_LEN..],
                    )
                    .ok_or(MessagePackError::BadBytes)?,
                })
            } else {
                Err(MessagePackError::BadLength)
            }
        }
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct VirtualSet {
        pub element_address: UnicastAddress,
        pub publication: ModelPublishInfo,
        pub model_identifier: ModelIdentifier,
    }
    impl PackableMessage for VirtualSet {
        fn opcode() -> Opcode {
            ConfigOpcode::ModelPublicationVirtualAddressSet.into()
        }

        fn message_size(&self) -> usize {
            ADDRESS_LEN + ModelPublishInfo::VIRTUAL_LEN + self.model_identifier.byte_len()
        }

        fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError> {
            if buffer.len() < self.message_size() {
                Err(MessagePackError::SmallBuffer)
            } else if !self.publication.address.is_full_virtual() {
                Err(MessagePackError::BadState)
            } else {
                buffer[0..2].copy_from_slice(&self.element_address.to_bytes_le());
                self.publication.pack_into(
                    &mut buffer[ADDRESS_LEN..ADDRESS_LEN + ModelPublishInfo::VIRTUAL_LEN],
                );
                self.model_identifier
                    .pack_into(&mut buffer[ADDRESS_LEN + ModelPublishInfo::VIRTUAL_LEN..]);
                Ok(())
            }
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            const SIG_LEN: usize =
                ADDRESS_LEN + ModelPublishInfo::VIRTUAL_LEN + ModelIdentifier::vendor_byte_len();
            const VENDOR_LEN: usize =
                ADDRESS_LEN + ModelPublishInfo::VIRTUAL_LEN + ModelIdentifier::vendor_byte_len();
            if buffer.len() == SIG_LEN || buffer.len() == VENDOR_LEN {
                Ok(VirtualSet {
                    element_address: UnicastAddress::from_bytes_le(&buffer[..ADDRESS_LEN])
                        .ok_or(MessagePackError::BadBytes)?,
                    publication: ModelPublishInfo::unpack(
                        &buffer[ADDRESS_LEN..ADDRESS_LEN + ModelPublishInfo::VIRTUAL_LEN],
                    )
                    .ok_or(MessagePackError::BadBytes)?,
                    model_identifier: ModelIdentifier::unpack_from(
                        &buffer[ModelPublishInfo::VIRTUAL_LEN + ADDRESS_LEN..],
                    )
                    .ok_or(MessagePackError::BadBytes)?,
                })
            } else {
                Err(MessagePackError::BadLength)
            }
        }
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct Status {
        pub status_code: StatusCode,
        pub element_address: UnicastAddress,
        pub publication: ModelPublishInfo,
        pub model_identifier: ModelIdentifier,
    }
    impl PackableMessage for Status {
        fn opcode() -> Opcode {
            ConfigOpcode::ModelPublicationStatus.into()
        }

        fn message_size(&self) -> usize {
            1 + ADDRESS_LEN + ModelPublishInfo::NON_VIRTUAL_LEN + self.model_identifier.byte_len()
        }

        fn pack_into(&self, buffer: &mut [u8]) -> Result<(), MessagePackError> {
            if buffer.len() < self.message_size() {
                Err(MessagePackError::SmallBuffer)
            } else {
                // Status Message don't send the full 128-bit UUID, only the hash.
                let publish_info = if let Some(hash) = self.publication.address.virtual_hash() {
                    let mut pub_info = self.publication;
                    pub_info.address = Address::VirtualHash(hash);
                    pub_info
                } else {
                    self.publication
                };
                buffer[0] = self.status_code.into();
                buffer[1..1 + ADDRESS_LEN].copy_from_slice(&self.element_address.to_bytes_le());
                publish_info.pack_into(
                    &mut buffer
                        [1 + ADDRESS_LEN..1 + ADDRESS_LEN + ModelPublishInfo::NON_VIRTUAL_LEN],
                );
                self.model_identifier
                    .pack_into(&mut buffer[1 + ADDRESS_LEN + ModelPublishInfo::NON_VIRTUAL_LEN..]);
                Ok(())
            }
        }

        fn unpack_from(buffer: &[u8]) -> Result<Self, MessagePackError> {
            const SIG_LEN: usize = 1
                + ADDRESS_LEN
                + ModelPublishInfo::NON_VIRTUAL_LEN
                + ModelIdentifier::vendor_byte_len();
            const VENDOR_LEN: usize = 1
                + ADDRESS_LEN
                + ModelPublishInfo::NON_VIRTUAL_LEN
                + ModelIdentifier::vendor_byte_len();
            if buffer.len() == SIG_LEN || buffer.len() == VENDOR_LEN {
                Ok(Status {
                    status_code: buffer[0]
                        .try_into()
                        .map_err(|_| MessagePackError::BadBytes)?,
                    element_address: UnicastAddress::from_bytes_le(&buffer[1..1 + ADDRESS_LEN])
                        .ok_or(MessagePackError::BadBytes)?,
                    publication: ModelPublishInfo::unpack(
                        &buffer
                            [1 + ADDRESS_LEN..1 + ADDRESS_LEN + ModelPublishInfo::NON_VIRTUAL_LEN],
                    )
                    .ok_or(MessagePackError::BadBytes)?,
                    model_identifier: ModelIdentifier::unpack_from(
                        &buffer[1 + ModelPublishInfo::NON_VIRTUAL_LEN + ADDRESS_LEN..],
                    )
                    .ok_or(MessagePackError::BadBytes)?,
                })
            } else {
                Err(MessagePackError::BadLength)
            }
        }
    }
}
pub mod model_subscription {
    use crate::access::ModelIdentifier;
    use crate::address::{Address, UnicastAddress, VirtualAddress};
    use crate::foundation::StatusCode;
    use alloc::vec::Vec;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct NonVirtualAdd {
        pub element_address: UnicastAddress,
        pub address: Address,
        pub model_identifier: ModelIdentifier,
    }

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct VirtualAdd {
        pub element_address: UnicastAddress,
        pub address: VirtualAddress,
        pub model_identifier: ModelIdentifier,
    }

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct NonVirtualDelete {
        pub element_address: UnicastAddress,
        pub address: Address,
        pub model_identifier: ModelIdentifier,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct VirtualDelete {
        pub element_address: UnicastAddress,
        pub address: Address,
        pub model_identifier: ModelIdentifier,
    }
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct NonVirtualOverwrite {
        pub element_address: UnicastAddress,
        pub address: Address,
        pub model_identifier: ModelIdentifier,
    }

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct VirtualOverwrite {
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
    use crate::foundation::StatusCode;
    use crate::mesh::NetKeyIndex;
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
    use crate::crypto::key::AppKey;
    use crate::foundation::StatusCode;
    use crate::mesh::{AppKeyIndex, NetKeyIndex};
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
