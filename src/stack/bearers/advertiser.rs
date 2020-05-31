use crate::mesh::TransmitInterval;
use crate::stack::bearer::{IncomingMessage, OutgoingMessage};
use btle::hci::adapter;
use btle::le::advertisement::RawAdvertisement;
use btle::le::advertiser;
use btle::{BTAddress, PackError};
use driver_async::asyncs::task;
use driver_async::asyncs::time::{delay_for, Duration};
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
    pub const ADVERTISING_DURATION: Duration =
        Duration::from_micros(Self::ADVERTISING_INTERVAL_MICROSECONDS as u64);
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
        let interval_duration =
            Duration::from_millis(transmit_interval.steps.to_milliseconds().into());
        let interval_delay = interval_duration
            .checked_sub(Self::ADVERTISING_DURATION)
            .unwrap_or(Duration::from_micros(0));
        let transmit_count = u8::from(transmit_interval.count);
        self.hci
            .set_advertising_data(advertisement.as_ref())
            .await?;
        for i in 0..=transmit_count {
            self.hci.set_advertising_enable(true).await?;
            delay_for(Self::ADVERTISING_DURATION).await;
            self.hci.set_advertising_enable(false).await?;
            if i != transmit_count {
                delay_for(interval_delay).await;
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
}
pub struct BufferedHCIAdvertiser {
    hci_task: task::JoinHandle<Result<(), adapter::Error>>,
}
/*
impl<A: btle::le::advertiser::Advertiser> BufferedHCIAdvertiser<A> {
    pub fn new_with(
        bearer: HCIBearer<A>,
        incoming_tx: mpsc::Sender<IncomingMessage>,
        outgoing_rx: mpsc::Receiver<OutgoingMessage>,
    ) -> BufferedHCIAdvertiser<A> {
        BufferedHCIAdvertiser {
            hci_task: task::spawn(async move { loop {} }),
        }
    }
}

    */
