use crate::asyncs::sync::mpsc;
use crate::provisioning::bearer_control::{CloseReason, PDU};
use crate::provisioning::generic::{Control, ReassembleError, Reassembler, SegmentIndex};
use crate::provisioning::pb_adv::{LinkID, TransactionNumber};
use crate::provisioning::{bearer_control, generic, pb_adv, protocol};
use crate::uuid::UUID;
use alloc::collections::BTreeMap;
use btle::bytes::Storage;
use btle::PackError;
use core::mem::{discriminant, Discriminant};
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::time::Duration;
use driver_async::time::{Instant, InstantTrait};
use futures_util::stream::{Stream, StreamExt};

#[derive(Debug)]
pub struct AtomicTransactionNumber(core::sync::atomic::AtomicU8);
impl AtomicTransactionNumber {
    pub const fn new(num: TransactionNumber) -> Self {
        Self(core::sync::atomic::AtomicU8::new(num.0))
    }
    pub fn get(&self) -> TransactionNumber {
        TransactionNumber(self.0.load(Ordering::SeqCst))
    }
    pub fn set(&self, new_number: TransactionNumber) {
        self.0.store(new_number.0, Ordering::SeqCst);
    }
}
impl Clone for AtomicTransactionNumber {
    fn clone(&self) -> Self {
        Self::new(self.get())
    }
}
impl PartialEq for AtomicTransactionNumber {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}
impl Eq for AtomicTransactionNumber {}
impl PartialOrd for AtomicTransactionNumber {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.get().partial_cmp(&other.get())
    }
}
impl Ord for AtomicTransactionNumber {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.get().cmp(&other.get())
    }
}
#[derive(Clone, Debug)]
pub struct Links<B: Storage<u8>> {
    links: BTreeMap<LinkID, Link<B>>,
}
impl<B: Storage<u8>> Links<B> {
    pub fn new() -> Links<B> {
        Links {
            links: BTreeMap::new(),
        }
    }
}
impl<B: Storage<u8>> Links<B> {
    // C
    pub fn handle_pb_adv_pdu(&mut self, _pdu: &pb_adv::PDU<B>) {
        unimplemented!()
    }
}
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum State<B: AsRef<[u8]> + AsMut<[u8]>> {
    PendingInvite(Instant),
    OpenTimedOut,
    Working,
    Segmenting {
        segments: generic::SegmentGenerator<B>,
        last_send_time: Instant,
    },
    Reassembling(generic::Reassembler<B>),
    WeClosed(bearer_control::CloseReason),
    TheyClosed(bearer_control::CloseReason),
}
#[derive(Clone, Debug)]
pub struct Link<B: Storage<u8>> {
    link_id: LinkID,
    my_transaction_number: TransactionNumber,
    other_transaction_number: TransactionNumber,
    state: State<B>,
    outgoing: mpsc::Sender<pb_adv::PDU<B>>,
}

pub const GENERIC_PDU_DATA_MAX_LEN: usize = generic::MAX_CONTINUATION_DATA_LEN as usize;
#[derive(Copy, Clone, Debug)]
pub enum LinkError {
    BadLinkID,
    OldTransactionID,
    BadTransactionID,
    AlreadySending,
    EarlyBearerEnd,
    TimedOut,
    OutBackedUp,
    ChannelClosed,
    PDUPackError(PackError),
    ReassembleError(generic::ReassembleError),
    Closed(bearer_control::CloseReason),
}
impl btle::error::Error for LinkError {}
#[derive(Copy, Clone, Debug)]
pub enum LinkBearerError<E> {
    Link(LinkError),
    Bearer(E),
}
impl From<generic::ReassembleError> for LinkError {
    fn from(e: ReassembleError) -> Self {
        LinkError::ReassembleError(e)
    }
}
impl<E> From<LinkError> for LinkBearerError<E> {
    fn from(e: LinkError) -> Self {
        LinkBearerError::Link(e)
    }
}

impl<B: Storage<u8>> Link<B> {
    pub const INVITE_TIMEOUT: Duration = Duration::from_secs(60);
    pub const CHANNEL_SIZE: usize = SegmentIndex::MAX_SEGMENTS as usize;
    pub fn invite(
        tx_bearer: mpsc::Sender<pb_adv::PDU<B>>,
        link_id: LinkID,
        uuid: &UUID,
    ) -> Link<B> {
        let link = Link {
            link_id,
            my_transaction_number: TransactionNumber::new_provisioner().next(),
            other_transaction_number: TransactionNumber::new_provisionee(),
            state: State::PendingInvite(Instant::now()),
            outgoing: tx_bearer,
        };
        link.outgoing
            .try_send(link.prepare_generic_pdu(generic::PDU::<B> {
                control: generic::Control::BearerControl(bearer_control::PDU::LinkOpen(
                    bearer_control::LinkOpen(*uuid),
                )),
                payload: None,
            }))
            .expect("just created channel starts empty");
        link
    }
    pub fn state(&self) -> &State<B> {
        &self.state
    }
    fn prepare_generic_pdu(&self, pdu: generic::PDU<B>) -> pb_adv::PDU<B> {
        pb_adv::PDU {
            link_id: self.link_id,
            transaction_number: self.my_transaction_number,
            generic_pdu: pdu,
        }
    }
    async fn send_generic_pdu(&mut self, pdu: generic::PDU<B>) -> Result<(), LinkError> {
        let outgoing_pdu = self.prepare_generic_pdu(pdu);
        self.send_pb_adv(outgoing_pdu).await
    }
    pub async fn send_pb_adv(&mut self, pdu: pb_adv::PDU<B>) -> Result<(), LinkError> {
        self.outgoing
            .send(pdu)
            .await
            .map_err(|_| LinkError::ChannelClosed)
    }
    async fn send_transaction_ack(&mut self) -> Result<(), LinkError> {
        self.send_generic_pdu(generic::PDU {
            control: generic::Control::TransactionAcknowledgement(
                generic::TransactionAcknowledgmentPDU::new(),
            ),
            payload: None,
        })
        .await
    }
    pub async fn close(&mut self, reason: bearer_control::CloseReason) -> Result<(), LinkError> {
        match self.state {
            State::PendingInvite(_)
            | State::Working
            | State::Segmenting { .. }
            | State::Reassembling(_) => (),
            State::TheyClosed(reason) | State::WeClosed(reason) => {
                return Err(LinkError::Closed(reason))
            }
            State::OpenTimedOut => return Err(LinkError::TimedOut),
        }
        self.state = State::WeClosed(reason);
        self.send_generic_pdu(generic::PDU {
            control: generic::Control::BearerControl(bearer_control::PDU::LinkClose(
                bearer_control::LinkClose(reason),
            )),
            payload: None,
        })
        .await
    }
    async fn fail_unexpected_pdu(&mut self) -> Result<(), LinkError> {
        self.close(CloseReason::Fail).await
    }
    pub async fn handle_bearer_control(
        &mut self,
        pdu: bearer_control::PDU,
    ) -> Result<(), LinkError> {
        match pdu {
            PDU::LinkOpen(_) => {
                self.close(CloseReason::Fail).await?;
                Err(LinkError::Closed(CloseReason::Fail))
            }
            PDU::LinkAck(_) => {
                match self.state {
                    State::PendingInvite(time) => {
                        if Instant::now()
                            .checked_duration_until(time)
                            .unwrap_or(Duration::from_secs(0))
                            > Self::INVITE_TIMEOUT
                        {
                            self.state = State::OpenTimedOut;
                            Err(LinkError::TimedOut)
                        } else {
                            self.state = State::Working;
                            self.other_transaction_number.increment();
                            Ok(())
                        }
                    }
                    State::OpenTimedOut => Err(LinkError::TimedOut),
                    // Closed Stream
                    State::WeClosed(e) | State::TheyClosed(e) => Err(LinkError::Closed(e)),
                    _ => self.fail_unexpected_pdu().await,
                }
            }
            PDU::LinkClose(bearer_control::LinkClose(reason)) => {
                self.state = State::TheyClosed(reason);
                Err(LinkError::Closed(reason))
            }
        }
    }
    async fn bad_state(&mut self) -> Result<(), LinkError> {
        match self.state {
            State::PendingInvite(time) => {
                if Instant::now()
                    .checked_duration_until(time)
                    .unwrap_or(Duration::from_secs(0))
                    > Self::INVITE_TIMEOUT
                {
                    self.state = State::OpenTimedOut;
                    Err(LinkError::TimedOut)
                } else {
                    Ok(())
                }
            }
            State::OpenTimedOut => Err(LinkError::TimedOut),
            // Closed Stream
            State::WeClosed(e) | State::TheyClosed(e) => Err(LinkError::Closed(e)),
            _ => Ok(()),
        }
    }
    pub fn state_discriminant(&self) -> Discriminant<State<B>> {
        discriminant(&self.state)
    }
    pub async fn next_message<E, S: Stream<Item = Result<pb_adv::PDU<B>, E>>>(
        &mut self,
        mut stream: Pin<&mut S>,
    ) -> Result<protocol::PDU, LinkBearerError<E>> {
        // Check if we're in a state that wants to receive messages
        let current_state = match &self.state {
            State::PendingInvite(_) | State::Working | State::Reassembling(..) => {
                self.state_discriminant()
            }
            State::Segmenting { .. } => {
                return Err(LinkBearerError::Link(LinkError::AlreadySending))
            }
            State::OpenTimedOut => return Err(LinkBearerError::Link(LinkError::TimedOut)),
            State::WeClosed(r) | State::TheyClosed(r) => {
                return Err(LinkBearerError::Link(LinkError::Closed(*r)))
            }
        };
        while self.state_discriminant() != current_state {
            let pdu = stream
                .as_mut()
                .next()
                .await
                .ok_or(LinkError::EarlyBearerEnd)?
                .map_err(LinkBearerError::Bearer)?;
            if let Some(msg) = self.handle_pb_adv_pdu(pdu.as_ref()).await? {
                return Ok(msg);
            }
        }
        Err(LinkBearerError::Link(LinkError::EarlyBearerEnd))
    }

    pub async fn handle_pb_adv_pdu(
        &mut self,
        pdu: pb_adv::PDU<&[u8]>,
    ) -> Result<Option<protocol::PDU>, LinkError> {
        if pdu.link_id != self.link_id {
            return Err(LinkError::BadLinkID);
        }
        self.bad_state().await?;
        if pdu.transaction_number.is_provisioner() == pdu.transaction_number.is_provisioner() {
            // Incorrect Transaction Number
            return Err(LinkError::BadTransactionID);
        }
        // If its a new PDU
        if pdu.transaction_number != self.other_transaction_number {
            // Old PDU
            if pdu.transaction_number == self.other_transaction_number.prev() {
                // Transaction number is last transaction number so it could've just miss the ack
                self.send_transaction_ack().await?;
            }
            return Ok(None);
        }
        match &mut self.state {
            State::PendingInvite(_) => match pdu.generic_pdu.control {
                Control::BearerControl(control) => self.handle_bearer_control(control).await?,
                _ => self.fail_unexpected_pdu().await?,
            },
            State::Working => match pdu.generic_pdu.control {
                Control::BearerControl(pdu) => {
                    self.handle_bearer_control(pdu).await?;
                }
                Control::TransactionStart(start) => {
                    self.state = State::Reassembling(Reassembler::from_start(
                        start,
                        pdu.generic_pdu.payload.unwrap_or(&[]),
                    )?);
                }
                Control::TransactionContinuation(_) => {
                    // maybe just missed the Transaction Start PDU so we wait for the start again
                }
                Control::TransactionAcknowledgement(_) => {
                    self.fail_unexpected_pdu().await?;
                }
            },
            State::Segmenting { .. } => match pdu.generic_pdu.control {
                Control::TransactionAcknowledgement(_) => {
                    self.state = State::Working;
                    self.other_transaction_number.increment();
                }
                Control::BearerControl(pdu) => {
                    self.handle_bearer_control(pdu).await?;
                }
                _ => self.fail_unexpected_pdu().await?,
            },
            State::Reassembling(reassembler) => {
                match pdu.generic_pdu.control {
                    Control::TransactionStart(_start) => {
                        // We already started this transaction so we ignore the resent start
                    }
                    Control::TransactionContinuation(con) => {
                        if con.seg_i == reassembler.seg_i() {
                            reassembler
                                .insert(pdu.generic_pdu.payload.unwrap_or(&[]), con.seg_i)?;
                        }
                        if reassembler.is_done() {
                            let incoming_pdu = reassembler.finish_pdu()?;
                            self.send_transaction_ack().await?;
                            self.other_transaction_number.increment();
                            return Ok(Some(incoming_pdu));
                        }
                    }
                    Control::TransactionAcknowledgement(_) => self.fail_unexpected_pdu().await?,
                    Control::BearerControl(bc) => self.handle_bearer_control(bc).await?,
                }
            }
            State::OpenTimedOut => return Err(LinkError::TimedOut),
            // Closed Stream
            State::WeClosed(e) | State::TheyClosed(e) => return Err(LinkError::Closed(*e)),
        }
        Ok(None)
    }
}
