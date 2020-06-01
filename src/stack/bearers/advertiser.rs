use crate::mesh::TransmitInterval;
use crate::stack::bearer::{IncomingMessage, Message, OutgoingMessage};
use btle::hci::adapter;
use btle::le::advertisement::RawAdvertisement;
use btle::le::advertiser;
use btle::{BTAddress, PackError};
use core::convert::From;
use driver_async::asyncs::sync::mpsc;
use driver_async::asyncs::task;
use driver_async::asyncs::time;
use futures_util::stream::{Stream, StreamExt};

pub struct HCIBearer<A> {
    hci: A,
}
impl<A> HCIBearer<A> {
    pub const fn new(hci_adapter: A) -> HCIBearer<A> {
        HCIBearer { hci: hci_adapter }
    }
    pub fn into_inner(self) -> A {
        self.hci
    }
}
impl<A: advertiser::Advertiser> HCIBearer<A> {
    pub const ADVERTISING_INTERVAL: advertiser::AdvertisingInterval =
        advertiser::AdvertisingInterval::MIN;
    pub const ADVERTISING_INTERVAL_MICROSECONDS: u32 = Self::ADVERTISING_INTERVAL.as_microseconds();
    pub const ADVERTISING_DURATION: time::Duration =
        time::Duration::from_micros(Self::ADVERTISING_INTERVAL_MICROSECONDS as u64);
    pub const ADVERTISING_PARAMETERS: advertiser::AdvertisingParameters =
        advertiser::AdvertisingParameters {
            // advertiser::AdvertisingInterval::MIN for the highest packet throughput
            interval_min: Self::ADVERTISING_INTERVAL,
            interval_max: Self::ADVERTISING_INTERVAL,
            advertising_type: advertiser::AdvertisingType::AdvNonnconnInd,
            // PublicDevice for now for debugging. Should probably be Random in the future
            own_address_type: advertiser::OwnAddressType::PublicDevice,
            // Peer address should be unused
            peer_address_type: advertiser::PeerAddressType::Public,
            peer_address: BTAddress::ZEROED,
            channel_map: advertiser::ChannelMap::ALL,
            filter_policy: advertiser::FilterPolicy::All,
        };
    /// Sets advertising parameters. Only need to be called once at setup (unless something else
    /// changs advertising parameters).
    pub async fn setup_for_advertising(&mut self) -> Result<(), adapter::Error> {
        self.hci.set_advertising_enable(false).await?;
        self.hci
            .set_advertising_parameters(Self::ADVERTISING_PARAMETERS)
            .await
    }
    pub async fn send(
        &mut self,
        msg: OutgoingMessage,
    ) -> Result<Result<(), adapter::Error>, PackError> {
        let (advertisement, interval) = msg.to_raw_advertisement()?;
        Ok(self.advertise(advertisement, interval).await)
    }
    pub async fn advertise(
        &mut self,
        advertisement: RawAdvertisement,
        transmit_interval: TransmitInterval,
    ) -> Result<(), adapter::Error> {
        let interval_duration = transmit_interval.steps.to_duration();
        let interval_delay = interval_duration
            .checked_sub(Self::ADVERTISING_DURATION)
            .unwrap_or_default();
        // transmit_count is 0-based (0 means transmit once, 1 means twice, etc)
        let transmit_count = u8::from(transmit_interval.count);
        self.hci
            .set_advertising_data(advertisement.as_ref())
            .await?;
        for i in 0..=transmit_count {
            self.hci.set_advertising_enable(true).await?;
            time::delay_for(Self::ADVERTISING_DURATION).await;
            self.hci.set_advertising_enable(false).await?;
            if i != transmit_count {
                time::delay_for(interval_delay).await;
            }
        }
        Ok(())
    }
}
impl<A: btle::le::scan::Observer> HCIBearer<A> {
    pub async fn incoming_message_stream<'a>(
        &'a mut self,
    ) -> Result<impl Stream<Item = Result<IncomingMessage, adapter::Error>> + 'a, adapter::Error>
    {
        Ok(self
            .hci
            .advertisement_stream()
            .await?
            .filter_map(|r| async move { r.map(IncomingMessage::from_report_info).transpose() }))
    }
    pub async fn incoming_message_stream_without_mask<'a>(
        &'a mut self,
    ) -> Result<impl Stream<Item = Result<IncomingMessage, adapter::Error>> + 'a, adapter::Error>
    {
        Ok(self
            .hci
            .advertisement_stream_without_mask()
            .await?
            .filter_map(|r| async move { r.map(IncomingMessage::from_report_info).transpose() }))
    }
}
/// [`HCIBearer`] with `mpsc` channels buffering it.
pub struct BufferedHCIAdvertiser<A> {
    bearer: HCIBearer<A>,
    incoming_tx: mpsc::Sender<IncomingMessage>,
    outgoing_rx: mpsc::Receiver<OutgoingMessage>,
}
impl<A: btle::le::advertiser::Advertiser + btle::le::scan::Observer> BufferedHCIAdvertiser<A> {
    pub const ADVERTISING_DURATION: time::Duration = HCIBearer::<A>::ADVERTISING_DURATION;
    pub fn new_with(
        bearer: HCIBearer<A>,
        incoming_tx: mpsc::Sender<IncomingMessage>,
        outgoing_rx: mpsc::Receiver<OutgoingMessage>,
    ) -> BufferedHCIAdvertiser<A> {
        BufferedHCIAdvertiser {
            bearer,
            incoming_tx,
            outgoing_rx,
        }
    }
    pub fn bearer_ref(&self) -> &HCIBearer<A> {
        &self.bearer
    }
    pub fn bearer_mut(&mut self) -> &mut HCIBearer<A> {
        &mut self.bearer
    }
    pub fn into_bearer(self) -> HCIBearer<A> {
        self.bearer
    }
    pub fn new_with_channel_size(
        bearer: HCIBearer<A>,
        channel_size: usize,
    ) -> (
        BufferedHCIAdvertiser<A>,
        mpsc::Receiver<IncomingMessage>,
        mpsc::Sender<OutgoingMessage>,
    ) {
        let (incoming_tx, incoming_rx) = mpsc::channel(channel_size);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(channel_size);
        (
            Self::new_with(bearer, incoming_tx, outgoing_rx),
            incoming_rx,
            outgoing_tx,
        )
    }
    /// Spawn the `run_loop()` on the task executor. This method will call `task::spawn_local` for
    /// adapters that are `!Send`. This means `run_loop()` will run on the local thread,
    /// asynchronously without blocking.
    pub fn spawn_local(mut self) -> task::JoinHandle<Result<(), adapter::Error>>
    where
        A: 'static,
    {
        task::spawn_local(async move { self.run_loop().await })
    }
    async fn setup(&mut self) -> Result<(), adapter::Error> {
        self.bearer.setup_for_advertising().await?;
        //Get HCI event mask ready for advertisements
        let _ = self.bearer.incoming_message_stream().await?;
        Ok(())
    }
    async fn next(&mut self) -> Result<(), adapter::Error> {
        // If theres a message waiting to be sent, send the message before setting up for
        // receiving.
        if let Some(outgoing) = self.outgoing_rx.try_recv().ok() {
            return self.send(outgoing).await;
        }
        let mut incoming = self.bearer.incoming_message_stream_without_mask().await?;
        let incoming_pin =
            unsafe { core::pin::Pin::new_unchecked(&mut incoming) }.map(|r| r.map(Message::from));
        let outgoing_pinned =
            core::pin::Pin::new(&mut self.outgoing_rx).map(|m| Ok(Message::from(m)));
        let mut selected = futures_util::stream::select(incoming_pin, outgoing_pinned);
        if let Some(msg_r) = selected.next().await {
            match msg_r? {
                Message::Incoming(incoming) => self
                    .incoming_tx
                    .send(incoming)
                    .await
                    .map_err(|_| adapter::Error::ChannelClosed),
                Message::Outgoing(outgoing) => {
                    core::mem::drop(incoming);
                    self.send(outgoing).await
                }
            }
        } else {
            // Both the advertisement stream and the bearer returned None
            Err(adapter::Error::ChannelClosed)
        }
    }
    /// Listen and handle incoming messages for `listen_duration` amount of time.
    async fn handle_incoming_for(
        &mut self,
        listen_duration: time::Duration,
    ) -> Result<(), adapter::Error> {
        match time::timeout(listen_duration, self.handle_incoming_loop()).await {
            Ok(r) => r,
            // we timed out
            Err(_) => Ok(()),
        }
    }
    async fn handle_incoming_loop(&mut self) -> Result<(), adapter::Error> {
        let mut stream = self.bearer.incoming_message_stream_without_mask().await?;
        let mut stream = unsafe { core::pin::Pin::new_unchecked(&mut stream) };
        while let Some(incoming) = stream.next().await {
            self.incoming_tx
                .send(incoming?)
                .await
                .map_err(|_| adapter::Error::ChannelClosed)?
        }
        Ok(())
    }
    /// Send outgoing messages and receive incoming continuously. Run until the
    /// bearer and `outgoing_rx` return `None` or if an error occures.
    pub async fn run_loop(&mut self) -> Result<(), adapter::Error> {
        self.setup().await?;
        loop {
            self.next().await?;
        }
    }
    async fn send(&mut self, msg: OutgoingMessage) -> Result<(), adapter::Error> {
        let (advertisement, interval) = msg
            .to_raw_advertisement()
            .expect("no packing errors should happen TODO: verify");
        self.advertise(advertisement, interval).await
    }
    /// Same as `HCIBearer` advertise but also listens for packets while waiting
    async fn advertise(
        &mut self,
        advertisement: RawAdvertisement,
        transmit_interval: TransmitInterval,
    ) -> Result<(), adapter::Error> {
        let interval_duration = transmit_interval.steps.to_duration();
        let interval_delay = interval_duration
            .checked_sub(Self::ADVERTISING_DURATION)
            .unwrap_or_default();
        // transmit_count is 0-based (0 means transmit once, 1 means twice, etc)
        let transmit_count = u8::from(transmit_interval.count);
        self.bearer
            .hci
            .set_advertising_data(advertisement.as_ref())
            .await?;
        for i in 0..=transmit_count {
            self.bearer.hci.set_advertising_enable(true).await?;

            self.handle_incoming_for(Self::ADVERTISING_DURATION).await?;

            self.bearer.hci.set_advertising_enable(false).await?;
            if i != transmit_count {
                self.handle_incoming_for(interval_delay).await?;
            }
        }
        Ok(())
    }
}
