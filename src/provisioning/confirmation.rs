use crate::crypto::aes::AESCipher;
use crate::crypto::key::Key;
use crate::crypto::{k1, s1, ECDHSecret, Salt};
use crate::provisioning::protocol;
use crate::provisioning::protocol::{Confirmation, ProtocolPDU, Random};

pub struct Input {
    pub invite: protocol::Invite,
    pub capabilities: protocol::Capabilities,
    pub start: protocol::Start,
    pub provisioner_public_key: protocol::PublicKey,
    pub device_public_key: protocol::PublicKey,
}

pub struct InputBuilder {
    pub invite: Option<protocol::Invite>,
    pub capabilities: Option<protocol::Capabilities>,
    pub start: Option<protocol::Start>,
    pub provisioner_public_key: Option<protocol::PublicKey>,
    pub device_public_key: Option<protocol::PublicKey>,
}
const CAPABILITIES_POS: usize = protocol::Invite::BYTE_LEN;
const START_POS: usize = CAPABILITIES_POS + protocol::Capabilities::BYTE_LEN;
const PROV_KEY_POS: usize = START_POS + protocol::Start::BYTE_LEN;
const DEVICE_KEY_POS: usize = PROV_KEY_POS + protocol::PublicKey::BYTE_LEN;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct ConfirmationSalt(pub Salt);
impl AsRef<Salt> for ConfirmationSalt {
    fn as_ref(&self) -> &Salt {
        &self.0
    }
}
impl AsRef<[u8]> for ConfirmationSalt {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl InputBuilder {
    pub fn is_ready(&self) -> bool {
        self.device_public_key.is_some()
            && self.provisioner_public_key.is_some()
            && self.start.is_some()
            && self.capabilities.is_some()
            && self.invite.is_some()
    }
    pub fn build(&self) -> Option<Input> {
        Some(Input {
            device_public_key: self.device_public_key?,
            provisioner_public_key: self.provisioner_public_key?,
            start: self.start?,
            capabilities: self.capabilities?,
            invite: self.invite?,
        })
    }
}
impl Input {
    pub fn salt(&self) -> ConfirmationSalt {
        let mut buf = [0_u8; INPUT_LEN];
        self.invite
            .pack(&mut buf[..CAPABILITIES_POS])
            .expect("length hardcoded");
        self.capabilities
            .pack(&mut buf[CAPABILITIES_POS..START_POS])
            .expect("length hardcoded");
        self.start
            .pack(&mut buf[START_POS..PROV_KEY_POS])
            .expect("length hardcoded");
        self.provisioner_public_key
            .pack(&mut buf[PROV_KEY_POS..DEVICE_KEY_POS])
            .expect("length hardcoded");
        self.device_public_key
            .pack(&mut buf[DEVICE_KEY_POS..INPUT_LEN])
            .expect("length hardcoded");
        ConfirmationSalt(s1(&buf[..]))
    }
}
pub const INPUT_LEN: usize = protocol::Invite::BYTE_LEN
    + protocol::Capabilities::BYTE_LEN
    + protocol::Start::BYTE_LEN
    + protocol::PublicKey::BYTE_LEN * 2;

pub const AUTH_VALUE_LEN: usize = 16;

#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Default, Hash)]
pub struct AuthValue(pub [u8; AUTH_VALUE_LEN]);
impl AuthValue {
    pub const ZEROED: AuthValue = AuthValue([0_u8; AUTH_VALUE_LEN]);
    pub const DEFAULT: AuthValue = Self::ZEROED;
}
impl AsRef<[u8]> for AuthValue {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsMut<[u8]> for AuthValue {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
#[derive(Clone, Copy, Debug, Hash, Eq, PartialOrd, PartialEq, Ord)]
pub struct ConfirmationKey(pub Key);
impl ConfirmationKey {
    pub fn from_salt_and_secret(salt: &ConfirmationSalt, secret: &ECDHSecret) -> ConfirmationKey {
        ConfirmationKey(k1(secret.as_ref(), &salt.0, b"prck"))
    }
    pub fn confirm_random(&self, random: &Random, auth_value: &AuthValue) -> Confirmation {
        Confirmation(
            *AESCipher::new(&self.0)
                .cmac_slice(&[random.0.as_ref(), auth_value.as_ref()])
                .array_ref(),
        )
    }
}
impl AsRef<Key> for ConfirmationKey {
    fn as_ref(&self) -> &Key {
        &self.0
    }
}
impl AsRef<[u8]> for ConfirmationKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    pub fn test_input_len() {
        assert_eq!(DEVICE_KEY_POS + protocol::PublicKey::BYTE_LEN, INPUT_LEN)
    }
}
