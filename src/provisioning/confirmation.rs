use crate::crypto::{s1, Salt};
use crate::provisioning::protocol;
use crate::provisioning::protocol::ProtocolPDU;

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

pub struct ConfirmationSalt(pub Salt);
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    pub fn test_input_len() {
        assert_eq!(DEVICE_KEY_POS + protocol::PublicKey::BYTE_LEN, INPUT_LEN)
    }
}
