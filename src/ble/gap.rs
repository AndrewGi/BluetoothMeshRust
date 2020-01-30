use crate::ble::advertisement::RawAdvertisement;
pub trait ScannerSink {
    fn consume_advertisement(&self, advertisement: &RawAdvertisement);
}
pub trait Scanner<Sink: ScannerSink> {
    fn take_sink(&mut self, sink: Sink);
}

pub enum AdvertiserError {}
pub trait Advertiser {
    fn advertise(&self, advertisement: &RawAdvertisement) -> Result<(), AdvertiserError>;
}
