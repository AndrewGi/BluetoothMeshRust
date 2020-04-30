use crate::crypto::ecdh;
use crate::foundation::state::AttentionTimer;
use crate::provisioning::protocol;
use crate::provisioning::protocol::{
    AuthenticationMethod, Capabilities, ErrorCode, Failed, Invite, PublicKey, PublicKeyType, Start,
    PDU,
};
use btle::PackError;
use driver_async::asyncs::sync::mpsc;
use driver_async::time::{Duration, Instant, InstantTrait};

#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Debug, Hash)]
pub enum ProvisionerError {
    ChannelClosed,
    Closed,
    TimedOut,
    PrivateKeyMissing,
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
    Capabilities {
        invite: Invite,
        capabilities: Capabilities,
    },
    Started {
        invite: Invite,
        capabilities: Capabilities,
        start: Start,
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
    pub attention_timer: AttentionTimer,
    pub authentication_method: AuthenticationMethod,
    pub public_key_type: PublicKeyType,
    pub bearer: Bearer,
}
impl Process {
    pub const TIMEOUT: Duration = Duration::from_secs(30);
    pub fn new_with(
        bearer: Bearer,
        attention_timer: AttentionTimer,
        authentication_method: AuthenticationMethod,
        public_key_type: PublicKeyType,
    ) -> Process {
        Process {
            stage: Stage::Pending,
            last_message_time: None,
            attention_timer,
            authentication_method,
            public_key_type,
            bearer,
        }
    }
    pub fn new(bearer: Bearer) -> Process {
        Process::new_with(
            bearer,
            AttentionTimer::default(),
            AuthenticationMethod::NoOOB,
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
                self.stage = Stage::Started {
                    invite,
                    capabilities,
                    start,
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
            Stage::PublicKeyDevice { .. } => {}
        }
        Ok(&self.stage)
    }
}
