use crate::bearer::{IncomingEncryptedNetworkPDU, OutgoingEncryptedNetworkPDU};
use crate::interface::{InputInterfaces, InterfaceSink, OutputInterfaces};

use crate::relay::RelayPDU;
use crate::stack::messages::{
    EncryptedIncomingMessage, IncomingControlMessage, IncomingNetworkPDU, IncomingTransportPDU,
    OutgoingTransportMessage,
};
use crate::stack::{segments, SendError, Stack, StackInternals};
use crate::{lower, net, replay};

use crate::control;
use crate::lower::SeqZero;
use crate::stack::segments::Segments;
use crate::upper::PDU;
use alloc::boxed::Box;
use core::convert::TryFrom;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};

pub struct FullStack<'a> {
    network_pdu_sender: mpsc::Sender<IncomingEncryptedNetworkPDU>,
    upper_pdu_sender: mpsc::Sender<OutgoingTransportMessage>,
    control_pdu_sender: mpsc::Sender<IncomingControlMessage>,
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
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum RecvError {
    NoMatchingNetKey,
    NoMatchingAppKey,
    InvalidDeviceKey,
    InvalidDestination,
    MalformedNetworkPDU,
    MalformedControlPDU,
    OldSeq,
    NetworkPDUQueueClosed,
    OldSeqZero,
}
pub const CONTROL_CHANNEL_SIZE: usize = 5;
impl<'a> FullStack<'a> {
    /// Create a new `FullStack` based on `StackInternals` and `replay::Cache`.
    /// `StackInternals` holds the `device_state::State` which should be save persistently for the
    /// entire time a node is in a Mesh Network. If you lose the `StackInternals`, the node will
    /// have to be reprovisioned as a new nodes and the old allocated Unicast Addresses are lost.
    pub fn new(
        internals: StackInternals,
        replay_cache: replay::Cache,
        channel_size: usize,
    ) -> Self {
        let (tx_net, rx_net) = mpsc::channel(channel_size);
        let (tx_transport, rx_transport) = mpsc::channel(channel_size);
        let (tx_msg, rx_msg) = mpsc::channel(channel_size);
        let (tx_control, rx_control) = mpsc::channel(CONTROL_CHANNEL_SIZE);
        let net_handler = tokio::task::spawn(async move {});
        let incoming_transport_handler = tokio::task::spawn(Self::handle_net_loop()
        Self {
            network_pdu_sender: tx_net.clone(),
            upper_pdu_sender: tx_transport.clone(),
            control_pdu_sender: tx_control,
            input_interfaces: Mutex::new(InputInterfaces::new(InputInterfaceSink(tx_net))),
            output_interfaces: Mutex::new(OutputInterfaces::default()),
            internals: Arc::new(RwLock::new(internals)),
            replay_cache: Arc::new(Mutex::new(replay_cache)),
            segments: Arc::new(Mutex::new(segments::Segments::new(
                channel_size,
                tx_transport,
                tx_msg,
            ))),
        }
    }
    pub fn output_interfaces(&self, use_interfaces: impl FnOnce(&mut OutputInterfaces)) {
        use_interfaces(&mut self.output_interfaces.lock());
    }
    async fn handle_net_loop(
        mut rx_net: mpsc::Receiver<IncomingEncryptedNetworkPDU>,
        tx_control: mpsc::Sender<IncomingControlMessage>,
        segments: Arc<Mutex<Segments>>,
    ) -> Result<(), RecvError> {
        loop {
            let incoming = rx_net
                .recv()
                .await
                .ok_or(RecvError::NetworkPDUQueueClosed)?;
            if let Ok(seg_event) = segments::SegmentEvent::try_from(&incoming) {
                segments.lock().await.feed_event(seg_event);
                continue;
            }
            match &incoming.pdu.payload {
                lower::PDU::UnsegmentedAccess(unseg_access) => self
                    .handle_encrypted_incoming_message(EncryptedIncomingMessage {
                        encrypted_app_payload: unseg_access.into(),
                        seq: incoming.pdu.header.seq.into(),
                        seg_count: 0,
                        iv_index: incoming.iv_index,
                        net_key_index: incoming.net_key_index,
                        dst: incoming.pdu.header.dst,
                        src: incoming.pdu.header.src,
                        ttl: Some(incoming.pdu.header.ttl),
                        rssi: incoming.rssi,
                    }),
                lower::PDU::UnsegmentedControl(unseg_control) => {
                    self.handle_control(IncomingControlMessage {
                        control_pdu: {
                            match control::ControlPDU::try_from(unseg_control) {
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
    }
    pub fn input_interfaces(
        &self,
        use_interfaces: impl FnOnce(&mut InputInterfaces<InputInterfaceSink>),
    ) {
        use_interfaces(&mut self.input_interfaces.lock());
    }
    fn handle_recv_error(&self, error: RecvError, pdu: &IncomingNetworkPDU) {
        #[cfg(debug_assertions)]
        eprintln!("recv_error: `{:?}` pdu: `{:?}`", error, pdu);
    }
    /// Returns `true` if the `header` is old or `false` if the `header` is new and valid.
    /// If no information about the source of the PDU (Src and Seq), it records the header
    /// and returns `false`
    async fn check_replay_cache(
        &self,
        header: &net::Header,
        seq_zero: Option<SeqZero>,
    ) -> (bool, bool) {
        self.replay_cache
            .lock()
            .await
            .replay_net_check(header.src, header.seq, header.ivi, seq_zero)
    }
    fn handle_net_pdu(&self, incoming: IncomingNetworkPDU) -> Result<(), RecvError> {}
    fn handle_control(&self, _control_pdu: IncomingControlMessage) -> Result<(), RecvError> {
        unimplemented!()
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
    fn handle_upper_pdu<Storage: AsRef<[u8]> + AsMut<[u8]> + Clone>(
        &self,
        pdu: IncomingTransportPDU<Storage>,
    ) -> Result<(), RecvError> {
        match pdu.upper_pdu {
            PDU::Control(control_pdu) => self.handle_control(IncomingControlMessage {
                control_pdu: control::ControlPDU::try_from(&control_pdu)
                    .map_err(|_| RecvError::MalformedControlPDU)?,
                src: pdu.src,
                rssi: pdu.rssi,
                ttl: pdu.ttl,
            }),
            PDU::Access(access_pdu) => {
                self.handle_encrypted_incoming_message(EncryptedIncomingMessage {
                    encrypted_app_payload: access_pdu,
                    seq: pdu.seq,
                    seg_count: pdu.seg_count,
                    iv_index: pdu.iv_index,
                    net_key_index: pdu.net_key_index,
                    dst: pdu.dst,
                    src: pdu.src,
                    ttl: pdu.ttl,
                    rssi: pdu.rssi,
                })
            }
        }
    }
    pub fn handle_encrypted_incoming_message<Storage: AsRef<[u8]> + AsMut<[u8]> + Clone>(
        &self,
        _msg: EncryptedIncomingMessage<Storage>,
    ) -> Result<(), RecvError> {
        unimplemented!()
    }

    pub async fn internals_with<R>(&self, func: impl FnOnce(&StackInternals) -> R) -> R {
        func(self.internals.read().await.deref())
    }
    pub fn handle_encrypted_net_pdu(
        &self,
        incoming: IncomingEncryptedNetworkPDU,
    ) -> Result<(), RecvError> {
        let internals = self.internals.read();
        if let Some((net_key_index, iv_index, pdu)) =
            internals.decrypt_network_pdu(incoming.encrypted_pdu.as_ref())
        {
            let (is_old_seq, is_old_seq_zero) =
                self.check_replay_cache(pdu.header(), pdu.payload.seq_zero());
            if is_old_seq {
                // We've already seen this PDU
                return Err(RecvError::OldSeq);
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
                return Err(RecvError::OldSeqZero);
            }
            self.handle_net_pdu(IncomingNetworkPDU {
                pdu,
                net_key_index,
                iv_index,
                rssi: incoming.rssi,
            })
        } else {
            Err(RecvError::NoMatchingNetKey)
        }
    }
}
/*
impl<'a> Stack for FullStack<'_> {
    fn iv_index(&self) -> (IVIndex, IVUpdateFlag) {
        let internals = self.internals.read().await;
        (
            internals.device_state.iv_index(),
            internals.device_state.iv_update_flag(),
        )
    }
    fn primary_address(&self) -> UnicastAddress {
        self.internals
            .read()
            .await
            .device_state
            .unicast_range()
            .start
    }

    fn element_count(&self) -> ElementCount {
        self.internals.read().device_state.element_count()
    }

    fn send_message<Storage: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        _source_element: ElementIndex,
        _app_index: AppKeyIndex,
        _dst: Address,
        _payload: AppPayload<Storage>,
    ) -> Result<(), SendError> {
        unimplemented!()
    }
}
*/
