use crate::ble::advertisement::{AdStructureError, IncomingAdvertisement, RawAdvertisement};
use alloc::boxed::Box;
pub trait ScannerSink {
    fn consume_advertisement(&self, advertisement: &RawAdvertisement);
}
pub trait Scanner<'a> {
    fn take_sink(&mut self, sink: &'a dyn ScannerSink);
}

pub enum AdvertiserError {}
pub trait Advertiser {
    fn advertise(&self, advertisement: &RawAdvertisement) -> Result<(), AdvertiserError>;
}
