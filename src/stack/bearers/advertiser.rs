use crate::stack::bearer::{IncomingMessage, OutgoingMessage, TransmitInstructions};
use btle::hci::adapter;
use btle::hci::adapters::buffer::HCIEventBuffer;
use btle::hci::adapters::le::LEAdapter;
use btle::hci::event::EventPacket;
use btle::hci::le::report::AdvertisingReport;
use btle::hci::le::MetaEvent;
use btle::hci::le::RawMetaEvent;
use btle::le::advertisement::RawAdvertisement;
use btle::le::advertiser::AdvertisingInterval;
use btle::le::report::ReportInfo;
use btle::le::{advertiser, scan};
use btle::BTAddress;
use core::convert::{From, TryFrom};
use driver_async::asyncs::sync::mpsc;
use driver_async::asyncs::task;
use driver_async::asyncs::time;

type AdvertiserBuf = Box<[u8]>;

/// [`HCIBearer`] with `mpsc` channels buffering it.
pub struct BufferedHCIAdvertiser<A: btle::hci::adapter::Adapter> {
    bearer: LEAdapter<A, HCIEventBuffer<AdvertiserBuf>>,
    incoming_tx: mpsc::Sender<Result<IncomingMessage, adapter::Error>>,
    outgoing_rx: mpsc::Receiver<OutgoingMessage>,
}

impl<A: btle::hci::adapter::Adapter> BufferedHCIAdvertiser<A> {
    pub const SCANNING_PARAMETERS: scan::ScanParameters = scan::ScanParameters {
        scan_type: scan::ScanType::Passive,
        scan_interval: scan::ScanInterval::DEFAULT,
        scan_window: scan::ScanWindow::DEFAULT,
        own_address_type: scan::OwnAddressType::Public,
        scanning_filter_policy: scan::ScanningFilterPolicy::All,
    };
    /// Advertising Interval Min of `0x00A0` or `100ms` (To comply with the BT 4.0 spec) (BT 5.0
    /// raises this limitation)
    pub const ADVERTISING_INTERVAL_MIN: advertiser::AdvertisingInterval =
        advertiser::AdvertisingInterval::MIN_NON_CONN;

    pub fn advertising_parameters(
        interval: advertiser::AdvertisingInterval,
    ) -> advertiser::AdvertisingParameters {
        let interval = core::cmp::max(interval, Self::ADVERTISING_INTERVAL_MIN);
        advertiser::AdvertisingParameters {
            // advertiser::AdvertisingInterval::MIN for the highest packet throughput
            interval_min: interval,
            interval_max: interval,
            advertising_type: advertiser::AdvertisingType::AdvNonnConnInd,
            // PublicDevice for now for debugging. Should probably be Random in the future
            own_address_type: advertiser::OwnAddressType::PublicDevice,
            // Peer address should be unused
            peer_address_type: advertiser::PeerAddressType::Public,
            peer_address: BTAddress::ZEROED,
            channel_map: advertiser::ChannelMap::ALL,
            filter_policy: advertiser::FilterPolicy::All,
        }
    }
    pub fn new_with(
        bearer: A,
        incoming_tx: mpsc::Sender<Result<IncomingMessage, adapter::Error>>,
        outgoing_rx: mpsc::Receiver<OutgoingMessage>,
    ) -> BufferedHCIAdvertiser<A> {
        BufferedHCIAdvertiser {
            bearer: LEAdapter::new(btle::hci::adapters::Adapter::new_with_handler(
                bearer,
                HCIEventBuffer::new(),
            )),
            incoming_tx,
            outgoing_rx,
        }
    }
    pub fn new_with_channel_size(
        bearer: A,
        channel_size: usize,
    ) -> (
        BufferedHCIAdvertiser<A>,
        mpsc::Receiver<Result<IncomingMessage, adapter::Error>>,
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
    /// adapters that are `!Send`. This means `run_loop()`
    /// will run on the local thread,
    /// asynchronously without blocking.
    pub fn spawn_local(mut self) -> task::JoinHandle<()>
    where
        A: 'static,
    {
        task::spawn_local(async move { self.run_loop_send_error().await })
    }

    async fn setup(&mut self) -> Result<(), adapter::Error> {
        self.bearer.adapter.reset().await?;
        self.bearer
            .set_scan_parameters(Self::SCANNING_PARAMETERS)
            .await?;
        //Get HCI event mask ready for advertisements
        let _ = self
            .bearer
            .advertisement_stream::<Box<[ReportInfo]>>()
            .await?;
        self.bearer.set_scan_enable(true, false).await?;
        Ok(())
    }
    async fn flush_hci_buffer(&mut self) -> Result<(), adapter::Error> {
        while let Some(event) = self.bearer.adapter.event_handler.pop() {
            self.handle_event(event).await?
        }
        Ok(())
    }
    async fn recv(&self, msg: IncomingMessage) -> Result<(), adapter::Error> {
        self.incoming_tx
            .send(Ok(msg))
            .await
            .map_err(|_| adapter::Error::ChannelClosed)
    }
    async fn recv_err(&mut self, err: adapter::Error) -> Result<(), adapter::Error> {
        self.incoming_tx
            .send(Err(err))
            .await
            .map_err(|_| adapter::Error::ChannelClosed)
    }
    async fn handle_event(&self, event: EventPacket<AdvertiserBuf>) -> Result<(), adapter::Error> {
        if let Ok(event) = RawMetaEvent::try_from(event.as_ref()) {
            if let Ok(advertisement) =
                AdvertisingReport::<Box<[ReportInfo]>>::meta_unpack_packet(event)
            {
                for report in advertisement.into_iter() {
                    if let Some(msg) = IncomingMessage::from_report_info(report) {
                        self.recv(msg).await?
                    }
                }
            }
        }
        Ok(())
    }
    async fn read_event(&mut self) -> Result<EventPacket<AdvertiserBuf>, adapter::Error> {
        self.bearer.adapter.hci_read_event().await
    }
    async fn handle_next(&mut self) -> Result<(), adapter::Error> {
        self.flush_hci_buffer().await?;
        // If theres a message waiting to be sent, send the message before setting up for
        // receiving.
        if let Some(outgoing) = self.outgoing_rx.try_recv().ok() {
            return self.send(outgoing).await;
        }
        let mut incoming = self.bearer.adapter.hci_read_event::<AdvertiserBuf>();
        let incoming_pin = unsafe { core::pin::Pin::new_unchecked(&mut incoming) };
        let mut outgoing = self.outgoing_rx.recv();
        let outgoing_pin = unsafe { core::pin::Pin::new_unchecked(&mut outgoing) };

        match futures_util::future::select(incoming_pin, outgoing_pin).await {
            futures_util::future::Either::Left((event, _)) => {
                drop(incoming);
                drop(outgoing);
                self.handle_event(event?).await
            }
            futures_util::future::Either::Right((msg, _)) => {
                drop(incoming);
                drop(outgoing);
                self.send(msg.ok_or(adapter::Error::ChannelClosed)?).await
            }
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
        loop {
            let event = self.read_event().await?;
            self.handle_event(event).await?
        }
    }
    /// Send outgoing messages and receive incoming continuously. Run until the
    /// bearer and `outgoing_rx` return `None` or if an error occures.
    pub async fn run_loop(&mut self) -> Result<(), adapter::Error> {
        self.setup().await?;
        loop {
            self.handle_next().await?;
        }
    }
    pub async fn run_loop_send_error(&mut self) {
        if let Err(e) = self.setup().await {
            self.recv_err(e).await.ok();
            return;
        }
        loop {
            match self.handle_next().await {
                Err(adapter::Error::ChannelClosed) => return,
                Err(e) => {
                    if self.recv_err(e).await.is_err() {
                        return;
                    }
                }
                Ok(_) => (),
            }
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
        transmit_interval: TransmitInstructions,
    ) -> Result<(), adapter::Error> {
        let advertising_interval = AdvertisingInterval::try_from(transmit_interval.interval)
            .unwrap_or(Self::ADVERTISING_INTERVAL_MIN);
        let advertisement_duration = advertising_interval.as_duration();
        let parameters = Self::advertising_parameters(advertising_interval);
        // transmit_count is 0-based (0 means transmit once, 1 means twice, etc)
        let transmit_count = transmit_interval.times + 1;
        // Set advertising parameters
        self.bearer.set_advertising_parameters(parameters).await?;
        self.bearer
            .set_advertising_data(advertisement.as_ref())
            .await?;
        // Enable advertising
        self.bearer.set_advertising_enable(true).await?;
        // Scan for advertisements while advertising for `advertisement_duration`
        self.handle_incoming_for(advertisement_duration * u32::from(transmit_count))
            .await?;
        // Disable advertising
        self.bearer.set_advertising_enable(false).await?;
        Ok(())
    }
}
