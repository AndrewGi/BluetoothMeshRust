use crate::address::{UnicastAddress, ADDRESS_LEN};
use crate::bytes::ToFromBytesEndian;
use crate::crypto::aes::{AESCipher, MicSize};
use crate::crypto::key::{NetKey, SessionKey, KEY_LEN};
use crate::crypto::nonce::SessionNonce;
use crate::crypto::{ECDHSecret, ProvisioningSalt};
use crate::mesh::{IVIndex, KeyIndex, NetKeyIndex};
use crate::provisioning::protocol::EncryptedProvisioningData;
use btle::{ConversionError, PackError};
use core::convert::TryFrom;
pub struct SessionSecurityMaterials {
    pub key: SessionKey,
    pub nonce: SessionNonce,
}
impl SessionSecurityMaterials {
    pub fn new(key: SessionKey, nonce: SessionNonce) -> SessionSecurityMaterials {
        SessionSecurityMaterials { key, nonce }
    }
    pub fn from_secret_salt(
        secret: &ECDHSecret,
        salt: &ProvisioningSalt,
    ) -> SessionSecurityMaterials {
        SessionSecurityMaterials {
            key: SessionKey::from_secret_salt(secret, salt),
            nonce: SessionNonce::from_secret_salt(secret, salt),
        }
    }
}
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Hash, Debug)]
#[repr(u8)]
pub enum Flag {
    KeyRefresh = 0,
    IVUpdate = 1,
}
pub const FLAGS_MAX: u8 = 0b11;
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Default, Debug, Hash)]
pub struct Flags(u8);
impl Flags {
    fn flag_bit(flag: Flag) -> u8 {
        1_u8 << (flag as u8)
    }
    pub fn enable(&mut self, flag: Flag) {
        self.0 |= Self::flag_bit(flag)
    }
    pub fn disable(&mut self, flag: Flag) {
        self.0 &= !Self::flag_bit(flag)
    }
    pub fn get(self, flag: Flag) -> bool {
        (self.0 & Self::flag_bit(flag)) != 0
    }
}
impl From<Flags> for u8 {
    fn from(f: Flags) -> Self {
        f.0
    }
}
impl TryFrom<u8> for Flags {
    type Error = ConversionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > FLAGS_MAX {
            Err(ConversionError(()))
        } else {
            Ok(Flags(value))
        }
    }
}
pub struct ProvisioningData {
    pub net_key: NetKey,
    pub net_key_index: NetKeyIndex,
    pub flags: Flags,
    pub iv_index: IVIndex,
    pub element_address: UnicastAddress,
}
/// Length of all the fields packed together as bytes (25 bytes).
pub const PACKED_LEN: usize = KEY_LEN + 2 + 1 + IVIndex::BYTE_LEN + ADDRESS_LEN;
impl ProvisioningData {
    pub fn packed_unencrypted(&self) -> [u8; PACKED_LEN] {
        let mut out = [0_u8; PACKED_LEN];
        out[..KEY_LEN].copy_from_slice(self.net_key.key().as_ref());
        out[KEY_LEN..KEY_LEN + 2].copy_from_slice(&self.net_key_index.0.to_bytes_be());
        out[KEY_LEN + 2] = self.flags.into();
        out[KEY_LEN + 2 + 1..KEY_LEN + 2 + 1 + IVIndex::BYTE_LEN]
            .copy_from_slice(&self.iv_index.to_bytes_be());
        out[KEY_LEN + 2 + 1 + IVIndex::BYTE_LEN..]
            .copy_from_slice(&self.element_address.to_bytes_be());
        out
    }
    pub fn unpack_unencrypted(buf: &[u8]) -> Result<ProvisioningData, PackError> {
        PackError::expect_length(PACKED_LEN, buf)?;
        let net_key = NetKey::try_from(&buf[..KEY_LEN]).expect("hard coded length");
        let net_key_index = NetKeyIndex(
            KeyIndex::from_bytes_be(&buf[KEY_LEN..KEY_LEN + 2])
                .ok_or(PackError::bad_index(KEY_LEN))?,
        );
        let flags =
            Flags::try_from(buf[KEY_LEN + 2]).map_err(|_| PackError::bad_index(KEY_LEN + 2))?;
        let element_address =
            UnicastAddress::from_bytes_be(&buf[KEY_LEN + 2 + 1 + IVIndex::BYTE_LEN..])
                .ok_or(PackError::bad_index(KEY_LEN + 2 + 1 + IVIndex::BYTE_LEN))?;
        let iv_index =
            IVIndex::from_bytes_be(&buf[KEY_LEN + 2 + 1..KEY_LEN + 2 + 1 + IVIndex::BYTE_LEN])
                .expect("hard coded length");
        Ok(ProvisioningData {
            net_key,
            net_key_index,
            flags,
            iv_index,
            element_address,
        })
    }
    pub fn encrypt(
        &self,
        security_materials: &SessionSecurityMaterials,
    ) -> EncryptedProvisioningData {
        let mut data = self.packed_unencrypted();
        let mic = AESCipher::new(security_materials.key.as_ref()).ccm_encrypt(
            security_materials.nonce.as_ref(),
            &[],
            data.as_mut(),
            MicSize::Big,
        );
        EncryptedProvisioningData { data, mic }
    }
    pub fn decrypt(
        security_materials: &SessionSecurityMaterials,
        mut encrypted_data: EncryptedProvisioningData,
    ) -> Option<Result<ProvisioningData, PackError>> {
        AESCipher::new(security_materials.key.as_ref())
            .ccm_decrypt(
                security_materials.nonce.as_ref(),
                &[],
                encrypted_data.data.as_mut(),
                encrypted_data.mic,
            )
            .ok();
        Some(ProvisioningData::unpack_unencrypted(
            encrypted_data.data.as_ref(),
        ))
    }
}
