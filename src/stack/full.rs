use crate::bearer::{IncomingEncryptedNetworkPDU, OutgoingEncryptedNetworkPDU};
use crate::interface::{InputInterfaces, InterfaceSink, OutputInterfaces};

use crate::relay::RelayPDU;
use crate::stack::messages::{
    EncryptedIncomingMessage, IncomingControlMessage, IncomingNetworkPDU, IncomingTransportPDU,
};
use crate::stack::{segments, RecvError, SendError, Stack, StackInternals};
use crate::{lower, replay};

use crate::control;
use crate::stack::segments::Segments;
use crate::upper::PDU;
use alloc::boxed::Box;
use core::convert::TryFrom;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};

pub struct FullStack<'a> {
    input_interfaces: Mutex<InputInterfaces<InputInterfaceSink>>,
    output_interfaces: Mutex<OutputInterfaces<'a>>,
    segments: Arc<Mutex<segments::Segments>>,
    replay_cache: Arc<Mutex<replay::Cache>>,
    internals: Arc<RwLock<StackInternals>>,
}
#[derive(Clone)]
pub struct InputInterfaceSink(mpsc::Sender<IncomingEncryptedNetworkPDU>);

impl InterfaceSink for InputInterfaceSink {
    fn consume_pdu(&mut self, pdu: &IncomingEncryptedNetworkPDU) {
        // Proper Error Handling?
        match self.0.try_send(*pdu) {
            Ok(_) => (),  // Worked
            Err(_) => (), // Full Queue, drop packet
        }
    }
}
pub enum FullStackError {
    SendError(SendError),
    RecvError(RecvError),
}
pub const CONTROL_CHANNEL_SIZE: usize = 5;
impl FullStack<'_> {
    /// Create a new `FullStack` based on `StackInternals` and `replay::Cache`.
    /// `StackInternals` holds the `device_state::State` which should be save persistently for the
    /// entire time a node is in a Mesh Network. If you lose the `StackInternals`, the node will
    /// have to be reprovisioned as a new nodes and the old allocated Unicast Addresses are lost.
    pub fn new(
        internals: StackInternals,
        replay_cache: replay::Cache,
        channel_size: usize,
    ) -> Self {
        let (tx_incoming_encrypted_net, rx_incoming_encrypted_net) = mpsc::channel(channel_size);
        let (tx_incoming_net, rx_incoming_net) = mpsc::channel(channel_size);
        let (tx_incoming_transport, rx_incoming_transport) = mpsc::channel(channel_size);
        let (tx_outgoing_transport, rx_outgoing_transport) = mpsc::channel(channel_size);
        let (tx_control, rx_control) = mpsc::channel(CONTROL_CHANNEL_SIZE);
        let (tx_access, rx_access) = mpsc::channel(channel_size);

        let internals = Arc::new(RwLock::new(internals));
        let replay_cache = Arc::new(Mutex::new(replay_cache));
        let segments = Arc::new(Mutex::new(segments::Segments::new(
            channel_size,
            tx_outgoing_transport,
            tx_incoming_transport,
        )));
        // Encrypted Incoming Network PDU Handler.

        Self {
            input_interfaces: Mutex::new(InputInterfaces::new(InputInterfaceSink(
                tx_incoming_encrypted_net,
            ))),
            output_interfaces: Mutex::new(OutputInterfaces::default()),
            internals,
            replay_cache,
            segments,
        }
    }
    /// Send encrypted net_pdu through all output interfaces.
    async fn send_encrypted_net_pdu(
        &self,
        pdu: OutgoingEncryptedNetworkPDU,
    ) -> Result<(), SendError> {
        self.output_interfaces
            .lock()
            .await
            .send_pdu(&pdu)
            .map_err(|e| SendError::BearerError(e))
    }

    pub async fn internals_with<R>(&self, func: impl FnOnce(&StackInternals) -> R) -> R {
        func(self.internals.read().await.deref())
    }
}
