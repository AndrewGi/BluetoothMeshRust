use crate::bearer::{IncomingEncryptedNetworkPDU, OutgoingEncryptedNetworkPDU};
use crate::interface::{InputInterfaces, InterfaceSink, OutputInterfaces};
use crate::net::PrivateHeader;
use crate::relay::RelayPDU;
use crate::stack::messages::IncomingNetworkPDU;
use crate::stack::{SendError, StackInternals};
use crate::{lower, net, replay, upper};
use core::borrow::BorrowMut;
use core::ops::Deref;
use parking_lot::{Mutex, RwLock};
use std::sync::mpsc;

pub struct FullStack<'a> {
    network_pdu_sender: mpsc::Sender<IncomingEncryptedNetworkPDU>,
    network_pdu_receiver: mpsc::Receiver<IncomingEncryptedNetworkPDU>,
    input_interfaces: InputInterfaces<InputInterfaceSink>,
    output_interfaces: OutputInterfaces<'a>,
    replay_cache: Mutex<replay::Cache>,
    internals: RwLock<StackInternals>,
}
#[derive(Clone)]
pub struct InputInterfaceSink(mpsc::Sender<IncomingEncryptedNetworkPDU>);

impl InterfaceSink for InputInterfaceSink {
    fn consume_pdu(&self, pdu: &IncomingEncryptedNetworkPDU) {
        // Proper Error Handling?
        self.0.send(*pdu).expect("stack sink shutdown")
    }
}
pub enum FullStackError {
    NetworkPDUQueueClosed,
    SendError(SendError),
}

impl<'a> FullStack<'a> {
    pub fn new(internals: StackInternals) -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            network_pdu_sender: tx.clone(),
            network_pdu_receiver: rx,
            input_interfaces: InputInterfaces::new(InputInterfaceSink(tx)),
            output_interfaces: Default::default(),
            internals: RwLock::new(internals),
            replay_cache: Mutex::new(replay::Cache::new()),
        }
    }
    pub fn next_encrypted_network_pdu(
        &self,
    ) -> Result<IncomingEncryptedNetworkPDU, FullStackError> {
        self.network_pdu_receiver
            .recv()
            .map_err(|_| FullStackError::NetworkPDUQueueClosed)
    }
    /// Returns `true` if the `header` is old or `false` if the `header` is new and valid.
    /// If no information about the source of the PDU (Src and Seq), it records the header
    /// and returns `false`
    fn check_replay_cache(&self, header: &net::Header) -> bool {
        self.replay_cache
            .lock()
            .replay_check(header.src, header.seq, header.ivi)
    }
    fn handle_net_pdu(&self, incoming: IncomingNetworkPDU) {}
    /// Send encrypted net_pdu through all output interfaces.
    fn send_encrypted_net_pdu(
        &self,
        pdu: OutgoingEncryptedNetworkPDU,
    ) -> Result<(), FullStackError> {
        self.output_interfaces
            .send_pdu(&pdu)
            .map_err(|e| FullStackError::SendError(SendError::BearerError(e)))
    }
    fn relay_pdu(&self, pdu: RelayPDU) {
        let internals = self.internals.read_recursive();
        if !internals.device_state.relay_state().is_enabled()
            || !pdu.pdu.header().ttl.should_relay()
        {
            // Relay isn't enable so we shouldn't relay
            return;
        }
    }

    pub fn handle_encrypted_net_pdu(&self, incoming: IncomingEncryptedNetworkPDU) {
        let internals = self.internals.read();
        if let Some((net_key_index, iv_index, pdu)) =
            internals.decrypt_network_pdu(incoming.encrypted_pdu.as_ref())
        {
            if self.check_replay_cache(pdu.header()) {
                return; // Found PDU in the replay cache
            }
            if !incoming.dont_relay
                && pdu.header().ttl.should_relay()
                && internals.device_state.relay_state().is_enabled()
            {
                self.relay_pdu(RelayPDU {
                    pdu,
                    iv_index,
                    net_key_index,
                })
            }
            self.handle_net_pdu(IncomingNetworkPDU {
                pdu,
                net_key_index,
                iv_index,
                rssi: incoming.rssi,
            })
        }
    }
}
