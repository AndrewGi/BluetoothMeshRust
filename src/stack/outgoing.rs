//! Outgoing PDU handler.
use crate::control;
use crate::device_state::SeqRange;
use crate::stack::bearer::OutgoingEncryptedNetworkPDU;
use crate::stack::messages::OutgoingUpperTransportMessage;
use crate::stack::segments::{IncomingPDU, OutgoingSegments};
use crate::stack::{segments, SendError, StackInternals};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time;
use tokio::time::Duration;

pub struct Outgoing {
    pub outgoing_network: Mutex<mpsc::Sender<OutgoingEncryptedNetworkPDU>>,
    pub internals: Arc<RwLock<StackInternals>>,
    pub ack_rx: Mutex<mpsc::Receiver<IncomingPDU<control::Ack>>>,
}
pub const SEND_TIMEOUT_SECS: u64 = 10;
impl Outgoing {
    pub fn new(
        internals: Arc<RwLock<StackInternals>>,
        ack_rx: mpsc::Receiver<IncomingPDU<control::Ack>>,
        outgoing: mpsc::Sender<OutgoingEncryptedNetworkPDU>,
    ) -> Self {
        Self {
            outgoing_network: Mutex::new(outgoing),
            internals,
            ack_rx: Mutex::new(ack_rx),
        }
    }
    pub async fn send_upper_transport<Storage: AsRef<[u8]>>(
        &self,
        msg: OutgoingUpperTransportMessage<Storage>,
    ) -> Result<(), SendError> {
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
    pub async fn send_segments<Storage: AsRef<[u8]>>(
        &self,
        msg: segments::OutgoingSegments<Storage>,
    ) -> Result<(), SendError> {
        let mut ack_rx = self.ack_rx.lock().await;
        // Immediately send out the PDUs with the acquired seq range.
        let seq = msg.segments.seq_auth().first_seq;
        for (seg, seq) in msg
            .segments
            .iter(msg.segments.block_ack)
            .zip(SeqRange::new_segs(seq, msg.segments.seg_o()))
        {
            self.outgoing_network
                .send(msg.segments.seg_to_outgoing(seg, Some(seq)))
                .await
                .ok()
                .ok_or(SendError::ChannelClosed)?;
        }
        time::timeout(self.send_timeout(), async {
            loop {
                let first_ack = Self::next_ack(&msg.segments, &mut ack_rx).await?;

                // Check for a valid ack
            }
            Ok::<(), SendError>(())
        })
        .await
        .ok()
        .ok_or(SendError::AckTimeout)?
    }
}
