use crate::bearer::IncomingEncryptedNetworkPDU;
use crate::control;
use crate::relay::RelayPDU;
use crate::stack::messages::{
    EncryptedIncomingMessage, IncomingControlMessage, IncomingMessage, IncomingNetworkPDU,
    IncomingTransportPDU, OutgoingLowerTransportMessage,
};
use crate::stack::segments::SegmentEvent;
use crate::stack::{segments, RecvError, StackInternals};
use crate::{lower, replay, upper};
use futures::SinkExt;
use std::convert::TryFrom;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;

pub struct Incoming {
    net_handler: JoinHandle<Result<(), RecvError>>,
    encrypted_net_handler: JoinHandle<Result<(), RecvError>>,
    upper_transport_handler: JoinHandle<Result<(), RecvError>>,
    encrypted_access_handler: JoinHandle<Result<(), RecvError>>,
}
impl Incoming {
    pub fn new(
        internals: Arc<RwLock<StackInternals>>,
        replay_cache: Arc<Mutex<replay::Cache>>,
        incoming_net: mpsc::Receiver<IncomingEncryptedNetworkPDU>,
        outgoing_transport: mpsc::Sender<OutgoingLowerTransportMessage>,
        tx_ack: mpsc::Sender<segments::IncomingPDU<control::Ack>>,
        tx_access: mpsc::Sender<IncomingMessage<Box<[u8]>>>,
        tx_control: mpsc::Sender<IncomingControlMessage>,
        channel_size: usize,
    ) -> Self {
        let (tx_incoming_net, rx_incoming_net) = mpsc::channel(channel_size);
        let (tx_encrypted_access, rx_encrypted_access) = mpsc::channel(channel_size);
        let (tx_incoming_upper, rx_incoming_upper) = mpsc::channel(chanel_size);
        let reassembler = Arc::new(Mutex::new(segments::Reassembler::new(outgoing_transport)));
        Self {
            encrypted_net_handler: tokio::task::spawn(Self::handle_encrypted_net_pdu_loop(
                internals.clone(),
                replay_cache,
                None,
                incoming_net,
                tx_incoming_net,
            )),
            net_handler: tokio::task::spawn(Self::handle_net_loop(
                reassembler,
                tx_ack,
                tx_control.clone(),
                tx_encrypted_access.clone(),
                rx_incoming_net,
            )),
            upper_transport_handler: tokio::task::spawn(Self::handle_upper_transport_loop(
                rx_incoming_upper,
                tx_encrypted_access,
                tx_control,
            )),
            encrypted_access_handler: tokio::task::spawn(Self::handle_encrypted_access_loop(
                internals,
                rx_encrypted_access,
                tx_access,
            )),
        }
    }
    async fn handle_encrypted_access_loop(
        internals: Arc<RwLock<StackInternals>>,
        mut incoming_encrypted_access: mpsc::Receiver<EncryptedIncomingMessage<Box<[u8]>>>,
        mut outgoing_encrypted_access: mpsc::Sender<IncomingMessage<Box<[u8]>>>,
    ) -> Result<(), RecvError> {
        loop {
            let next = incoming_encrypted_access
                .recv()
                .await
                .ok_or(RecvError::ChannelClosed)?;
            if let Ok(decrypted) = internals.read().await.app_decrypt(next) {
                outgoing_encrypted_access
                    .send(decrypted)
                    .await
                    .ok()
                    .ok_or(RecvError::ChannelClosed)?;
            }
        }
    }
    async fn handle_net_loop(
        reassembler: Arc<Mutex<segments::Reassembler>>,
        mut tx_ack: mpsc::Sender<segments::IncomingPDU<control::Ack>>,
        mut tx_control: mpsc::Sender<IncomingControlMessage>,
        mut tx_access: mpsc::Sender<EncryptedIncomingMessage<Box<[u8]>>>,
        mut incoming: mpsc::Receiver<IncomingNetworkPDU>,
    ) -> Result<(), RecvError> {
        loop {
            match Self::handle_net(
                &reassembler,
                &mut tx_ack,
                &mut tx_control,
                &mut tx_access,
                incoming.recv().await.ok_or(RecvError::ChannelClosed)?,
            ) {
                RecvError::ChannelClosed => return Err(RecvError::ChannelClosed),
                // Ignore handle_net errors.
                _ => (),
            }
        }
    }
    async fn handle_net(
        reassembler: &Mutex<segments::Reassembler>,
        tx_ack: &mut mpsc::Sender<segments::IncomingPDU<control::Ack>>,
        tx_control: &mut mpsc::Sender<IncomingControlMessage>,
        tx_access: &mut mpsc::Sender<EncryptedIncomingMessage<Box<[u8]>>>,
        incoming: IncomingNetworkPDU,
    ) -> Result<(), RecvError> {
        if let Ok(seg_event) = segments::SegmentEvent::try_from(&incoming) {
            match seg_event {
                SegmentEvent::IncomingSegment(seg) => {
                    reassembler.lock().await.feed_pdu(seg).await.ok()
                }
                SegmentEvent::IncomingAck(ack) => tx_ack.send(ack).await.ok(),
            }
            .ok_or(RecvError::ChannelClosed)?;
            return Ok(());
        }
        match &incoming.pdu.payload {
            lower::PDU::UnsegmentedAccess(unseg_access) => tx_access
                .send(EncryptedIncomingMessage {
                    encrypted_app_payload: unseg_access.into(),
                    seq: incoming.pdu.header.seq.into(),
                    seg_count: 0,
                    iv_index: incoming.iv_index,
                    net_key_index: incoming.net_key_index,
                    dst: incoming.pdu.header.dst,
                    src: incoming.pdu.header.src,
                    ttl: Some(incoming.pdu.header.ttl),
                    rssi: incoming.rssi,
                })
                .await
                .ok()
                .ok_or(RecvError::ChannelClosed),
            lower::PDU::UnsegmentedControl(unseg_control) => {
                tx_control
                    .send(IncomingControlMessage {
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
                    .await
                    .ok()
                    .ok_or(RecvError::ChannelClosed)
            }

            // The rest of Segmented PDUs which are SegmentEvents. If they made it this far
            // they are badly formatted Segmented PDUs
            _ => Err(RecvError::MalformedNetworkPDU),
        }
    }
    async fn handle_upper_transport_loop<Storage: AsRef<[u8]> + AsMut<[u8]> + Clone>(
        mut incoming: mpsc::Receiver<IncomingTransportPDU<Storage>>,
        mut tx_access: mpsc::Sender<EncryptedIncomingMessage<Storage>>,
        mut tx_control: mpsc::Sender<IncomingControlMessage>,
    ) -> Result<(), RecvError> {
        loop {
            let pdu = incoming.recv().await.ok_or(RecvError::ChannelClosed)?;
            match pdu.upper_pdu {
                upper::PDU::Control(control_pdu) => {
                    if let Ok(control_pdu) = control::ControlPDU::try_from(&control_pdu) {
                        tx_control
                            .send(IncomingControlMessage {
                                control_pdu,
                                src: pdu.src,
                                rssi: pdu.rssi,
                                ttl: pdu.ttl,
                            })
                            .await
                            .ok()
                            .ok_or(RecvError::ChannelClosed)?;
                    }
                }
                upper::PDU::Access(access_pdu) => {
                    tx_access
                        .send(EncryptedIncomingMessage {
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
                        .await
                        .ok()
                        .ok_or(RecvError::ChannelClosed)?;
                }
            }
        }
    }
    pub async fn handle_encrypted_net_pdu_loop(
        internals: Arc<RwLock<StackInternals>>,
        replay_cache: Arc<Mutex<replay::Cache>>,
        mut outgoing_relay: Option<mpsc::Sender<RelayPDU>>,
        mut incoming: mpsc::Receiver<IncomingEncryptedNetworkPDU>,
        mut outgoing: mpsc::Sender<IncomingNetworkPDU>,
    ) -> Result<(), RecvError> {
        loop {
            let next = incoming.recv().await.ok_or(RecvError::ChannelClosed)?;
            match Self::handle_encrypted_net_pdu(
                &internals,
                &replay_cache,
                outgoing_relay.as_mut(),
                next,
            )
            .await
            {
                Ok(pdu) => outgoing
                    .send(pdu)
                    .await
                    .ok()
                    .ok_or(RecvError::ChannelClosed)?,
                Err(e) => {
                    // Log the error, otherwise ignore it.
                    #[cfg(debug_assertions)]
                    eprintln!("recv error: {:?}", e);
                }
            }
        }
    }
    pub async fn handle_encrypted_net_pdu(
        internals: &RwLock<StackInternals>,
        replay_cache: &Mutex<replay::Cache>,
        outgoing_relay: Option<&mut mpsc::Sender<RelayPDU>>,
        incoming: IncomingEncryptedNetworkPDU,
    ) -> Result<IncomingNetworkPDU, RecvError> {
        let internals = internals.read().await;
        if let Some((net_key_index, iv_index, pdu)) =
            internals.decrypt_network_pdu(incoming.encrypted_pdu.as_ref())
        {
            let header = pdu.header();
            let (is_old_seq, is_old_seq_zero) = replay_cache.lock().await.replay_net_check(
                header.src,
                header.seq,
                header.ivi,
                pdu.payload.seq_zero(),
            );
            if is_old_seq {
                // We've already seen this PDU
                return Err(RecvError::OldSeq);
            }
            // Seq isn't old but SeqZero might be. Even if SeqZero is old, we still relay it to other nodes.
            if !incoming.dont_relay
                && pdu.header().ttl.should_relay()
                && internals.device_state.relay_state().is_enabled()
            {
                if let Some(mut relay_tx) = outgoing_relay {
                    relay_tx
                        .send(RelayPDU {
                            pdu,
                            iv_index,
                            net_key_index,
                        })
                        .await;
                }
            }
            if is_old_seq_zero {
                // We've already handle this PDU
                return Err(RecvError::OldSeqZero);
            }
            Ok(IncomingNetworkPDU {
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
