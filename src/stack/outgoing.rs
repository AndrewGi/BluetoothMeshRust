//! Outgoing PDU handler.
use crate::device_state::SeqRange;
use crate::mesh::{SequenceNumber, CTL};
use crate::net::Header;
use crate::stack::bearer::{OutgoingEncryptedNetworkPDU, OutgoingMessage};
use crate::stack::messages::{OutgoingLowerTransportMessage, OutgoingUpperTransportMessage};
use crate::stack::segments::{IncomingPDU, OutgoingSegments};
use crate::stack::{segments, SendError, StackInternals};
use crate::{control, net};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time;
use tokio::time::Duration;

pub struct Outgoing {
    pub outgoing_network: Mutex<mpsc::Sender<OutgoingMessage>>,
    pub internals: Arc<RwLock<StackInternals>>,
    pub ack_rx: Mutex<mpsc::Receiver<IncomingPDU<control::Ack>>>,
}
pub const SEND_TIMEOUT_SECS: u64 = 10;
impl Outgoing {
    pub fn new(
        internals: Arc<RwLock<StackInternals>>,
        ack_rx: mpsc::Receiver<IncomingPDU<control::Ack>>,
        outgoing: mpsc::Sender<OutgoingMessage>,
    ) -> Self {
        Self {
            outgoing_network: Mutex::new(outgoing),
            internals,
            ack_rx: Mutex::new(ack_rx),
        }
    }
    pub async fn send_upper_transport<Storage: AsRef<[u8]>>(
        &self,
        _msg: OutgoingUpperTransportMessage<Storage>,
    ) -> Result<(), SendError> {
        todo!("implement sending upper transport PDU")
    }
    pub fn send_timeout(&self) -> Duration {
        Duration::from_secs(SEND_TIMEOUT_SECS)
    }
    pub async fn next_ack<Storage: AsRef<[u8]>>(
        segments: &OutgoingSegments<Storage>,
        ack_rx: &mut mpsc::Receiver<IncomingPDU<control::Ack>>,
    ) -> Result<IncomingPDU<control::Ack>, SendError> {
        loop {
            let next_ack = ack_rx.recv().await.ok_or(SendError::ChannelClosed)?;
            match segments.is_new_ack(next_ack) {
                Ok(is_new) if is_new => return Ok(next_ack),
                _ => continue, // Ack doesn't match
            };
        }
    }
    pub async fn send_encrypted_network_pdu(
        &self,
        outgoing_pdu: OutgoingEncryptedNetworkPDU,
    ) -> Result<(), SendError> {
        self.outgoing_network
            .lock()
            .await
            .send(OutgoingMessage::Network(outgoing_pdu))
            .await
            .ok()
            .ok_or(SendError::ChannelClosed)
    }
    pub async fn send_unsegmented(
        &self,
        msg: OutgoingLowerTransportMessage,
    ) -> Result<(), SendError> {
        let internals = self.internals.read().await;
        let (pdu, net_sm) = internals.lower_to_net(&msg)?;
        let transmit_parameters = internals.device_state.config_states().network_transmit.0;
        // Release the lock on StackInternals.
        self.send_encrypted_network_pdu(OutgoingEncryptedNetworkPDU {
            transmit_parameters,
            pdu: pdu
                .encrypt(net_sm.network_keys(), msg.iv_index)
                .map_err(|_| SendError::NetEncryptError)?,
        })
        .await
    }
    pub async fn send_segments<Storage: AsRef<[u8]>>(
        &self,
        msg: segments::OutgoingSegments<Storage>,
    ) -> Result<(), SendError> {
        //todo check element_index (src address?)
        //todo Lock out SeqCounter
        let seq = msg.segments.seq_auth().first_seq;
        let internals = self.internals.read().await;
        let iv_index = msg.segments.seq_auth().iv_index;
        if !internals.is_valid_iv_index(iv_index) {
            return Err(SendError::InvalidIVIndex);
        }
        let ivi = iv_index.ivi();
        let net_sm = internals
            .net_keys()
            .get_keys(msg.net_key_index)
            .ok_or(SendError::InvalidNetKeyIndex)?
            .tx_key();
        let nid = net_sm.network_keys().nid();
        let ctl = CTL(msg.segments.upper_pdu.is_control());
        let transmit_parameters = internals.device_state().config_states().network_transmit.0;
        let ttl = msg.ttl.unwrap_or(internals.default_ttl());
        let mut ack_rx = self.ack_rx.lock().await;
        let make_net_header = |seq: SequenceNumber| Header {
            ivi,
            nid,
            ctl,
            ttl,
            seq,
            src: msg.src,
            dst: msg.dst,
        };
        // Immediately send out the PDUs with the acquired seq range.
        for (seg, seq) in msg
            .segments
            .iter(msg.block_ack)
            .zip(SeqRange::new_segs(seq, msg.segments.seg_o()))
        {
            self.send_encrypted_network_pdu(OutgoingEncryptedNetworkPDU {
                transmit_parameters,
                pdu: net::PDU {
                    header: make_net_header(seq),
                    payload: seg.into(),
                }
                .encrypt(net_sm.network_keys(), iv_index)
                .map_err(|_| SendError::NetEncryptError)?,
            })
            .await?;
        }
        time::timeout(self.send_timeout(), async {
            loop {
                let _first_ack = Self::next_ack(&msg, &mut ack_rx).await?;

                // Check for a valid ack
                todo!()
            }
            // Allow unreachable_code so we can annotate the async result type.
            #[allow(unreachable_code)]
            Ok::<(), SendError>(())
        })
        .await
        .ok()
        .ok_or(SendError::AckTimeout)?
    }
}
