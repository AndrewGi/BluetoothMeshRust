//! Full Bluetooth Mesh Stack. Takes `IncomingEncryptedNetworkPDU`s and `OutgoingMessages` and takes
//! care of all the stack layer between them.
//use crate::interface::{InputInterfaces, InterfaceSink, OutputInterfaces};

use crate::replay;
use crate::stack::{incoming, outgoing, RecvError, SendError, StackInternals};

use crate::asyncs::sync::{mpsc, Mutex, RwLock};
use crate::stack::bearer::{IncomingEncryptedNetworkPDU, OutgoingMessage};
use crate::stack::incoming::Incoming;
use crate::stack::outgoing::Outgoing;
use alloc::sync::Arc;
use core::ops::{Deref, DerefMut};
pub struct FullStack {
    pub replay_cache: Arc<Mutex<replay::Cache>>,
    pub internals: Arc<RwLock<StackInternals>>,
    pub outgoing_bearer: mpsc::Receiver<OutgoingMessage>,
    pub incoming_bearer: mpsc::Sender<IncomingEncryptedNetworkPDU>,
    pub incoming: incoming::Incoming,
    pub outgoing: outgoing::Outgoing,
    _priv: (),
}
pub enum FullStackError {
    SendError(SendError),
    RecvError(RecvError),
}
pub const CONTROL_CHANNEL_SIZE: usize = 5;
impl FullStack {
    /// Create a new `FullStack` based on `StackInternals` and `replay::Cache`.
    /// `StackInternals` holds the `device_state::State` which should be save persistently for the
    /// entire time a node is in a Mesh Network. If you lose the `StackInternals`, the node will
    /// have to be reprovisioned as a new nodes and the old allocated Unicast Addresses are lost.
    pub fn new(
        internals: StackInternals,
        replay_cache: replay::Cache,
        channel_size: usize,
    ) -> Self {
        let (tx_bearer, rx_bearer) = mpsc::channel(2);
        let (tx_incoming_encrypted_net, rx_incoming_encrypted_net) = mpsc::channel(channel_size);
        let (tx_outgoing_transport, _rx_outgoing_transport) = mpsc::channel(channel_size);
        let (tx_control, _rx_control) = mpsc::channel(CONTROL_CHANNEL_SIZE);
        let (tx_access, _rx_access) = mpsc::channel(channel_size);
        let (tx_ack, rx_ack) = mpsc::channel(channel_size);
        let internals = Arc::new(RwLock::new(internals));
        let replay_cache = Arc::new(Mutex::new(replay_cache));

        // Encrypted Incoming Network PDU Handler.

        Self {
            internals: internals.clone(),
            outgoing_bearer: rx_bearer,
            incoming_bearer: tx_incoming_encrypted_net,
            incoming: Incoming::new(
                internals.clone(),
                replay_cache.clone(),
                rx_incoming_encrypted_net,
                tx_outgoing_transport,
                tx_ack,
                tx_access,
                tx_control,
                channel_size,
            ),
            replay_cache,
            outgoing: Outgoing::new(internals, rx_ack, tx_bearer),
            _priv: (),
        }
    }
    pub async fn feed_network_pdu(
        &mut self,
        pdu: IncomingEncryptedNetworkPDU,
    ) -> Result<(), RecvError> {
        self.incoming_bearer
            .send(pdu)
            .await
            .map_err(|_| RecvError::ChannelClosed)
    }
    pub async fn internals_with<R>(&self, func: impl FnOnce(&StackInternals) -> R) -> R {
        func(self.internals.read().await.deref())
    }
    pub async fn internals_with_mut<R>(&self, func: impl FnOnce(&mut StackInternals) -> R) -> R {
        func(self.internals.write().await.deref_mut())
    }
}
