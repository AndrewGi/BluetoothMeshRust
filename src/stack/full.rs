use crate::bearer::{IncomingEncryptedNetworkPDU, OutgoingEncryptedNetworkPDU};
use crate::interface::{InputInterfaces, InterfaceSink, OutputInterfaces};

use crate::relay::RelayPDU;
use crate::stack::messages::{
    EncryptedIncomingMessage, IncomingControlMessage, IncomingNetworkPDU, IncomingTransportPDU,
};
use crate::stack::{segments, SendError, StackInternals};
use crate::{lower, net, replay};

use crate::control::{ControlMessageError, ControlOpcode, ControlPDU};
use crate::lower::SegmentedPDU::Control;
use crate::lower::SeqZero;
use crate::upper::{EncryptedAppPayload, UpperPDUConversionError, PDU};
use core::convert::{TryFrom, TryInto};
use parking_lot::{Mutex, RwLock};
use std::sync::mpsc;

pub struct FullStack<'a> {
    network_pdu_sender: mpsc::Sender<IncomingEncryptedNetworkPDU>,
    network_pdu_receiver: mpsc::Receiver<IncomingEncryptedNetworkPDU>,
    input_interfaces: InputInterfaces<InputInterfaceSink>,
    output_interfaces: OutputInterfaces<'a>,
    segments: segments::Segments,
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
pub enum RecvError {
    MalformedNetworkPDU,
    MalformedControlPDU,
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
            segments: segments::Segments::new(),
        }
    }
    fn handle_next_encrypted_network_pdu(&self) -> Result<(), FullStackError> {
        self.handle_encrypted_net_pdu(self.next_encrypted_network_pdu()?);
        Ok(())
    }
    fn next_encrypted_network_pdu(&self) -> Result<IncomingEncryptedNetworkPDU, FullStackError> {
        self.network_pdu_receiver
            .recv()
            .map_err(|_| FullStackError::NetworkPDUQueueClosed)
    }
    /// Returns `true` if the `header` is old or `false` if the `header` is new and valid.
    /// If no information about the source of the PDU (Src and Seq), it records the header
    /// and returns `false`
    fn check_replay_cache(&self, header: &net::Header, seq_zero: Option<SeqZero>) -> (bool, bool) {
        self.replay_cache
            .lock()
            .replay_net_check(header.src, header.seq, header.ivi, seq_zero)
    }
    fn handle_net_pdu(&self, incoming: IncomingNetworkPDU) -> Result<(), RecvError> {
        if let Ok(seg_event) = segments::SegmentEvent::try_from(&incoming) {
            self.segments.feed_event(seg_event);
        }
        match &incoming.pdu.payload {
            lower::PDU::UnsegmentedAccess(unseg_access) => {
                self.handle_encrypted_incoming_message(EncryptedIncomingMessage {
                    encrypted_app_payload: unseg_access.into(),
                    seq: incoming.pdu.header.seq.into(),
                    seg_count: 0,
                    net_key_index: incoming.net_key_index,
                    dst: incoming.pdu.header.dst,
                    src: incoming.pdu.header.src,
                    ttl: Some(incoming.pdu.header.ttl),
                    rssi: incoming.rssi,
                })
            }
            lower::PDU::UnsegmentedControl(unseg_control) => {
                self.handle_control(IncomingControlMessage {
                    control_pdu: {
                        match ControlPDU::try_from(unseg_control) {
                            Ok(pdu) => pdu,
                            Err(_) => return Err(RecvError::MalformedControlPDU), // Badly formatted Control PDU
                        }
                    },
                    src: incoming.pdu.header.src,
                    rssi: incoming.rssi,
                    ttl: Some(incoming.pdu.header.ttl),
                })
            }
            // The rest of Segmented PDUs which are SegmentEvents. If they made it this far
            // they are badly formatted Segmented PDUs
            _ => Err(RecvError::MalformedNetworkPDU),
        }
    }
    fn handle_control(&self, control_pdu: IncomingControlMessage) {}
    fn handle_encrypted_incoming_message<Storage: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        msg: EncryptedIncomingMessage<Storage>,
    ) -> Result<(), RecvError> {
    }
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
        todo!("relay PDU")
    }
    fn handle_upper_pdu<Storage: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        pdu: IncomingTransportPDU<Storage>,
    ) {
        match EncryptedAppPayload::try_from(pdu.upper_pdu) {
            Ok(app_pdu) => {}
            Err(_) => {}
        }
    }
    pub fn handle_encrypted_net_pdu(&self, incoming: IncomingEncryptedNetworkPDU) {
        let internals = self.internals.read();
        if let Some((net_key_index, iv_index, pdu)) =
            internals.decrypt_network_pdu(incoming.encrypted_pdu.as_ref())
        {
            let (is_old_seq, is_old_seq_zero) =
                self.check_replay_cache(pdu.header(), pdu.payload.seq_zero());
            if is_old_seq {
                // We've already seen this PDU
                return;
            }
            // Seq isn't old but SeqZero might be. Even if SeqZero is old, we still relay it to other nodes.
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
            if is_old_seq_zero {
                // We've already handle this PDU
                return;
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
