use crate::crypto::{ecdh, ECDHSecret, ProvisioningSalt};
use crate::foundation::state::AttentionTimer;
use crate::provisioning::confirmation::{AuthValue, ConfirmationKey, ConfirmationSalt};
use crate::provisioning::data::SessionSecurityMaterials;
use crate::provisioning::protocol::{
    AuthenticationMethod, Capabilities, Confirmation, ErrorCode, Failed, InputOOBAction, Invite,
    OOBSize, OutputOOBAction, PublicKey, PublicKeyType, Random, Start, PDU,
};
use crate::provisioning::{confirmation, protocol};
use btle::PackError;
use driver_async::asyncs::sync::mpsc;
use driver_async::time::{Duration, Instant, InstantTrait};

#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub enum ProvisionerError {
    ChannelClosed,
    Closed,
    TimedOut,
    PrivateKeyMissing,
    OOBPublicKeyMissing,
    DeviceConfirmationMismatch,
    ECDH(ecdh::Error),
    PackError(PackError),
    Failed(ErrorCode),
}
impl btle::error::Error for ProvisionerError {}
impl From<PackError> for ProvisionerError {
    fn from(e: PackError) -> Self {
        ProvisionerError::PackError(e)
    }
}
impl From<ecdh::Error> for ProvisionerError {
    fn from(e: ecdh::Error) -> Self {
        ProvisionerError::ECDH(e)
    }
}
pub enum Stage {
    Pending,
    Invited {
        invite: Invite,
    },
    /// OOB Public Key will be use if enable after this
    Capabilities {
        invite: Invite,
        capabilities: Capabilities,
    },
    Started {
        invite: Invite,
        capabilities: Capabilities,
        start: Start,
    },
    StartedOOBPublicKey {
        invite: Invite,
        capabilities: Capabilities,
        start: Start,
    },
    OOBPublicKey {
        invite: Invite,
        capabilities: Capabilities,
        start: Start,
        device_public_key: PublicKey,
    },
    PublicKeyProvisioner {
        invite: Invite,
        capabilities: Capabilities,
        start: Start,
        private_key: Option<ecdh::PrivateKey>,
        provisioner_public_key: PublicKey,
    },
    PublicKeyDevice {
        invite: Invite,
        capabilities: Capabilities,
        start: Start,
        private_key: Option<ecdh::PrivateKey>,
        provisioner_public_key: PublicKey,
        device_public_key: PublicKey,
    },
    /// OOB Information should be fed after this
    Confirmation {
        ecdh_secret: ECDHSecret,
        confirmation_key: ConfirmationKey,
        provisioner_random: Random,
        confirmation_salt: ConfirmationSalt,
        oob_type: AuthenticationMethod,
    },
    OutputOOB {
        ecdh_secret: ECDHSecret,
        confirmation_key: ConfirmationKey,
        confirmation_salt: ConfirmationSalt,
        provisioner_random: Random,
        output_oob_action: OutputOOBAction,
        output_oob_size: OOBSize,
    },
    InputOOB {
        ecdh_secret: ECDHSecret,
        confirmation_key: ConfirmationKey,
        confirmation_salt: ConfirmationSalt,
        provisioner_random: Random,
        input_oob_action: InputOOBAction,
        input_oob_size: OOBSize,
    },
    StaticOOB {
        ecdh_secret: ECDHSecret,
        confirmation_key: ConfirmationKey,
        confirmation_salt: ConfirmationSalt,
        provisioner_random: Random,
    },
    SendConfirmation {
        ecdh_secret: ECDHSecret,
        confirmation_key: ConfirmationKey,
        confirmation_salt: ConfirmationSalt,
        provisioner_random: Random,
        auth_value: AuthValue,
    },
    WaitForDeviceConfirmation {
        ecdh_secret: ECDHSecret,
        confirmation_key: ConfirmationKey,
        confirmation_salt: ConfirmationSalt,
        provisioner_random: Random,
        auth_value: AuthValue,
    },
    DeviceConfirmation {
        ecdh_secret: ECDHSecret,
        confirmation_key: ConfirmationKey,
        confirmation_salt: ConfirmationSalt,
        provisioner_random: Random,
        auth_value: AuthValue,
        device_confirmation: Confirmation,
    },
    WaitForDeviceRandom {
        ecdh_secret: ECDHSecret,
        confirmation_key: ConfirmationKey,
        confirmation_salt: ConfirmationSalt,
        provisioner_random: Random,
        auth_value: AuthValue,
        device_confirmation: Confirmation,
    },
    DeviceRandom {
        ecdh_secret: ECDHSecret,
        confirmation_key: ConfirmationKey,
        confirmation_salt: ConfirmationSalt,
        provisioner_random: Random,
        auth_value: AuthValue,
        device_confirmation: Confirmation,
        device_random: Random,
    },
    Distribute {
        security_materials: SessionSecurityMaterials,
    },
    Closed,
    Failed(Failed),
}
impl Stage {
    pub fn is_closed(&self) -> bool {
        match self {
            Stage::Closed => true,
            _ => false,
        }
    }
    pub fn failed_reason(&self) -> Option<ErrorCode> {
        match self {
            Stage::Failed(reason) => Some(reason.0),
            _ => None,
        }
    }
}
pub struct Bearer {
    in_bearer: mpsc::Receiver<PDU>,
    out_bearer: mpsc::Sender<PDU>,
}
impl Bearer {
    pub async fn recv(&mut self, timeout: Duration) -> Result<PDU, ProvisionerError> {
        driver_async::asyncs::time::timeout(timeout, self.in_bearer.recv())
            .await
            .map_err(|_| ProvisionerError::TimedOut)?
            .ok_or(ProvisionerError::ChannelClosed)
    }
    pub async fn send(&mut self, pdu: &PDU) -> Result<(), ProvisionerError> {
        self.out_bearer
            .send(*pdu)
            .await
            .map_err(|_| ProvisionerError::ChannelClosed)
    }
}
pub struct Process {
    stage: Stage,
    last_message_time: Option<Instant>,
    pub oob_public_key: Option<PublicKey>,
    pub attention_timer: AttentionTimer,
    pub authentication_method: AuthenticationMethod,
    pub auth_value: AuthValue,
    pub public_key_type: PublicKeyType,
    pub bearer: Bearer,
}
impl Process {
    pub const TIMEOUT: Duration = Duration::from_secs(30);
    pub fn new_with(
        bearer: Bearer,
        attention_timer: AttentionTimer,
        authentication_method: AuthenticationMethod,
        auth_value: AuthValue,
        public_key_type: PublicKeyType,
    ) -> Process {
        Process {
            stage: Stage::Pending,
            last_message_time: None,
            oob_public_key: None,
            attention_timer,
            authentication_method,
            auth_value,
            public_key_type,
            bearer,
        }
    }
    pub fn new(bearer: Bearer) -> Process {
        Process::new_with(
            bearer,
            AttentionTimer::default(),
            AuthenticationMethod::NoOOB,
            AuthValue::DEFAULT,
            PublicKeyType::NotAvailable,
        )
    }
    pub fn is_timed_out(&self) -> bool {
        self.last_message_time
            .and_then(|i| Instant::now().checked_duration_since(i))
            .map(|d| d < Self::TIMEOUT)
            .unwrap_or(false)
    }
    pub fn time_until_timeout(&self) -> Result<Option<Duration>, ProvisionerError> {
        match self.last_message_time {
            Some(last_message_time) => Ok(Some(
                Instant::now()
                    .checked_duration_until(last_message_time + Self::TIMEOUT)
                    .ok_or(ProvisionerError::TimedOut)?,
            )),
            None => Ok(None),
        }
    }
    pub async fn fail(&mut self, reason: ErrorCode) -> Result<(), ProvisionerError> {
        self.stage = Stage::Closed;
        self.bearer
            .send(&PDU::Failed(Failed(reason)))
            .await
            .map_err(|_| ProvisionerError::ChannelClosed)?;
        Ok(())
    }
    async fn fail_with(&mut self, reason: ErrorCode) -> Result<(), ProvisionerError> {
        self.fail(reason).await?;
        Err(ProvisionerError::Failed(reason))
    }
    pub fn stage(&self) -> &'_ Stage {
        &self.stage
    }
    pub fn can_send(&self) -> bool {
        match self.stage {
            Stage::Closed | Stage::Failed(_) => false,
            _ => true,
        }
    }
    fn update_last_message_time(&mut self) {
        self.last_message_time = Some(Instant::now())
    }
    fn bad_stage(&self) -> Result<(), ProvisionerError> {
        match self.stage {
            Stage::Closed => Err(ProvisionerError::Closed),
            Stage::Failed(reason) => Err(ProvisionerError::Failed(reason.0)),
            _ => Ok(()),
        }
    }
    fn recv_timeout(&self) -> Result<Duration, ProvisionerError> {
        Ok(self.time_until_timeout()?.unwrap_or(Process::TIMEOUT))
    }
    async fn recv(&mut self) -> Result<PDU, ProvisionerError> {
        self.bad_stage()?;
        let pdu = self.bearer.recv(self.recv_timeout()?).await?;
        self.update_last_message_time();
        Ok(pdu)
    }
    async fn send(&mut self, pdu: &PDU) -> Result<(), ProvisionerError> {
        self.bad_stage()?;
        self.bearer.send(pdu).await?;
        self.update_last_message_time();
        Ok(())
    }
    fn start_pdu(&self) -> Start {
        Start {
            algorithm: protocol::AlgorithmsFlags::FIPSP256,
            public_key_type: self.public_key_type,
            auth_method: self.authentication_method,
        }
    }
    pub async fn next_stage(&mut self) -> Result<&Stage, ProvisionerError> {
        let timeout = self.recv_timeout()?;
        match &mut self.stage {
            Stage::Failed(reason) => return Err(ProvisionerError::Failed(reason.0)),
            Stage::Closed => return Err(ProvisionerError::Closed),
            Stage::Pending => {
                let invite = Invite(self.attention_timer);
                self.send(&PDU::Invite(invite)).await?;
                self.stage = Stage::Invited { invite };
            }
            Stage::Invited { invite } => {
                let invite = *invite;
                let response = self.recv().await?;
                match response {
                    PDU::Capabilities(capabilities) => {
                        self.stage = Stage::Capabilities {
                            invite,
                            capabilities,
                        }
                    }
                    _ => self.fail_with(ErrorCode::UnexpectedPDU).await?,
                }
            }
            Stage::Capabilities {
                invite,
                capabilities,
            } => {
                // Send Start
                let invite = *invite;
                let capabilities = *capabilities;
                let start = self.start_pdu();
                self.send(&PDU::Start(start)).await?;
                if start.public_key_type == PublicKeyType::NotAvailable {
                    self.stage = Stage::Started {
                        invite,
                        capabilities,
                        start,
                    }
                } else {
                    self.stage = Stage::StartedOOBPublicKey {
                        invite,
                        capabilities,
                        start,
                    }
                }
            }
            Stage::Started {
                invite,
                capabilities,
                start,
            } => {
                // Send Provisioner Public Key
                let invite = *invite;
                let capabilities = *capabilities;
                let start = *start;
                let private_key = ecdh::PrivateKey::new()?;
                let public_key = (&private_key.public_key()?).into();
                self.send(&PDU::PublicKey(public_key)).await?;
                self.stage = Stage::PublicKeyProvisioner {
                    invite,
                    capabilities,
                    start,
                    private_key: Some(private_key),
                    provisioner_public_key: public_key,
                }
            }
            Stage::StartedOOBPublicKey {
                invite,
                capabilities,
                start,
            } => {
                self.stage = Stage::OOBPublicKey {
                    device_public_key: self
                        .oob_public_key
                        .ok_or(ProvisionerError::OOBPublicKeyMissing)?,
                    invite: *invite,
                    capabilities: *capabilities,
                    start: *start,
                }
            }
            Stage::OOBPublicKey {
                invite,
                capabilities,
                start,
                device_public_key,
            } => {
                let private_key = ecdh::PrivateKey::new()?;
                let provisioner_public_key = (&private_key.public_key()?).into();
                let invite = *invite;
                let capabilities = *capabilities;
                let start = *start;
                let device_public_key = *device_public_key;
                self.send(&PDU::PublicKey(provisioner_public_key)).await?;
                self.stage = Stage::PublicKeyDevice {
                    invite,
                    start,
                    capabilities,
                    device_public_key,
                    private_key: Some(private_key),
                    provisioner_public_key,
                }
            }
            Stage::PublicKeyProvisioner {
                invite,
                capabilities,
                start,
                private_key,
                provisioner_public_key,
            } => {
                // Wait for Device Public Key
                self.stage = Stage::PublicKeyDevice {
                    device_public_key: {
                        let response = self.bearer.recv(timeout).await?;
                        self.last_message_time = Some(Instant::now());
                        match response {
                            PDU::PublicKey(device_public_key) => device_public_key,
                            _ => {
                                self.fail(ErrorCode::UnexpectedPDU).await?;
                                return Err(ProvisionerError::Failed(ErrorCode::UnexpectedPDU));
                            }
                        }
                    },
                    invite: *invite,
                    capabilities: *capabilities,
                    start: *start,
                    private_key: Some(
                        private_key
                            .take()
                            .ok_or(ProvisionerError::PrivateKeyMissing)?,
                    ),
                    provisioner_public_key: *provisioner_public_key,
                };
            }
            Stage::PublicKeyDevice {
                invite,
                capabilities,
                start,
                private_key,
                provisioner_public_key,
                device_public_key,
            } => {
                let private_key = private_key
                    .take()
                    .ok_or(ProvisionerError::PrivateKeyMissing)?;
                let ecdh_secret = private_key.agree(device_public_key, |s| ECDHSecret::new(s))?;
                let confirmation_salt = confirmation::Input {
                    invite: *invite,
                    capabilities: *capabilities,
                    start: *start,
                    provisioner_public_key: *provisioner_public_key,
                    device_public_key: *device_public_key,
                }
                .salt();
                let confirmation_key =
                    ConfirmationKey::from_salt_and_secret(&confirmation_salt, &ecdh_secret);
                self.stage = Stage::Confirmation {
                    ecdh_secret,
                    confirmation_key,
                    provisioner_random: Random::new_rand(),
                    confirmation_salt,
                    oob_type: start.auth_method,
                }
            }
            Stage::Confirmation {
                ecdh_secret,
                confirmation_key,
                provisioner_random,
                confirmation_salt,
                oob_type,
            } => match oob_type {
                AuthenticationMethod::NoOOB => {
                    self.stage = Stage::SendConfirmation {
                        ecdh_secret: *ecdh_secret,
                        confirmation_key: *confirmation_key,
                        confirmation_salt: *confirmation_salt,
                        provisioner_random: *provisioner_random,
                        auth_value: AuthValue::ZEROED,
                    }
                }
                AuthenticationMethod::StaticOOB => {
                    self.stage = Stage::StaticOOB {
                        ecdh_secret: *ecdh_secret,
                        confirmation_key: *confirmation_key,
                        confirmation_salt: *confirmation_salt,
                        provisioner_random: *provisioner_random,
                    }
                }
                AuthenticationMethod::OutputOOB(a, s) => {
                    self.stage = Stage::OutputOOB {
                        ecdh_secret: *ecdh_secret,
                        confirmation_key: *confirmation_key,
                        confirmation_salt: *confirmation_salt,
                        provisioner_random: *provisioner_random,
                        output_oob_action: *a,
                        output_oob_size: *s,
                    }
                }
                AuthenticationMethod::InputOOB(a, s) => {
                    self.stage = Stage::InputOOB {
                        ecdh_secret: *ecdh_secret,
                        confirmation_key: *confirmation_key,
                        confirmation_salt: *confirmation_salt,
                        provisioner_random: *provisioner_random,
                        input_oob_action: *a,
                        input_oob_size: *s,
                    }
                }
            },

            Stage::OutputOOB {
                ecdh_secret,
                confirmation_key,
                confirmation_salt,
                provisioner_random,
                ..
            } => {
                self.stage = Stage::SendConfirmation {
                    auth_value: self.auth_value,
                    ecdh_secret: *ecdh_secret,
                    confirmation_key: *confirmation_key,
                    confirmation_salt: *confirmation_salt,
                    provisioner_random: *provisioner_random,
                }
            }
            Stage::InputOOB {
                ecdh_secret,
                confirmation_key,
                confirmation_salt,
                provisioner_random,
                ..
            } => {
                self.stage = Stage::SendConfirmation {
                    auth_value: self.auth_value,
                    ecdh_secret: *ecdh_secret,
                    confirmation_key: *confirmation_key,
                    provisioner_random: *provisioner_random,
                    confirmation_salt: *confirmation_salt,
                }
            }
            Stage::StaticOOB {
                ecdh_secret,
                confirmation_key,
                provisioner_random,
                confirmation_salt,
            } => {
                self.stage = Stage::SendConfirmation {
                    auth_value: self.auth_value,
                    ecdh_secret: *ecdh_secret,
                    confirmation_key: *confirmation_key,
                    confirmation_salt: *confirmation_salt,
                    provisioner_random: *provisioner_random,
                }
            }
            Stage::SendConfirmation {
                ecdh_secret,
                confirmation_key,
                confirmation_salt,
                provisioner_random,
                auth_value,
            } => {
                let confirmation = confirmation_key.confirm_random(provisioner_random, auth_value);
                self.bearer.send(&PDU::Confirm(confirmation)).await?;
                self.last_message_time = Some(Instant::now());
                self.stage = Stage::WaitForDeviceConfirmation {
                    auth_value: self.auth_value,
                    ecdh_secret: *ecdh_secret,
                    confirmation_key: *confirmation_key,
                    confirmation_salt: *confirmation_salt,
                    provisioner_random: *provisioner_random,
                }
            }
            Stage::WaitForDeviceConfirmation {
                ecdh_secret,
                confirmation_key,
                confirmation_salt,
                provisioner_random,
                auth_value,
            } => {
                let device_confirmation = match self.bearer.recv(Self::TIMEOUT).await? {
                    PDU::Confirm(confirmation) => confirmation,
                    _ => {
                        self.fail(ErrorCode::UnexpectedPDU).await?;
                        return Err(ProvisionerError::Failed(ErrorCode::UnexpectedPDU));
                    }
                };
                self.last_message_time = Some(Instant::now());
                self.stage = Stage::DeviceConfirmation {
                    ecdh_secret: *ecdh_secret,
                    confirmation_key: *confirmation_key,
                    confirmation_salt: *confirmation_salt,
                    provisioner_random: *provisioner_random,
                    auth_value: *auth_value,
                    device_confirmation,
                }
            }
            Stage::DeviceConfirmation {
                ecdh_secret,
                confirmation_key,
                confirmation_salt,
                provisioner_random,
                auth_value,
                device_confirmation,
            } => {
                self.bearer.send(&PDU::Random(*provisioner_random)).await?;
                self.last_message_time = Some(Instant::now());
                self.stage = Stage::WaitForDeviceRandom {
                    ecdh_secret: *ecdh_secret,
                    confirmation_key: *confirmation_key,
                    confirmation_salt: *confirmation_salt,
                    provisioner_random: *provisioner_random,
                    auth_value: *auth_value,
                    device_confirmation: *device_confirmation,
                }
            }
            Stage::WaitForDeviceRandom {
                ecdh_secret,
                confirmation_key,
                confirmation_salt,
                provisioner_random,
                auth_value,
                device_confirmation,
            } => {
                let device_random = match self.bearer.recv(Self::TIMEOUT).await? {
                    PDU::Random(random) => random,
                    _ => {
                        self.fail(ErrorCode::UnexpectedPDU).await?;
                        return Err(ProvisionerError::Failed(ErrorCode::UnexpectedPDU));
                    }
                };
                self.last_message_time = Some(Instant::now());
                self.stage = Stage::DeviceRandom {
                    ecdh_secret: *ecdh_secret,
                    confirmation_key: *confirmation_key,
                    confirmation_salt: *confirmation_salt,
                    provisioner_random: *provisioner_random,
                    auth_value: *auth_value,
                    device_confirmation: *device_confirmation,
                    device_random,
                }
            }
            Stage::DeviceRandom {
                ecdh_secret,
                confirmation_key,
                confirmation_salt,
                provisioner_random,
                auth_value,
                device_confirmation,
                device_random,
            } => {
                if device_confirmation
                    != &confirmation_key.confirm_random(device_random, auth_value)
                {
                    self.fail(ErrorCode::ConfirmationFailed).await?;
                    return Err(ProvisionerError::DeviceConfirmationMismatch);
                }
                let provisioning_salt = ProvisioningSalt::from_randoms(
                    confirmation_salt,
                    provisioner_random,
                    device_random,
                );
                self.stage = Stage::Distribute {
                    security_materials: SessionSecurityMaterials::from_secret_salt(
                        ecdh_secret,
                        &provisioning_salt,
                    ),
                }
            }
            Stage::Distribute { security_materials } => unimplemented!(),
        }
        Ok(&self.stage)
    }
}
