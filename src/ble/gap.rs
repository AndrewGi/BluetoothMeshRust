use crate::ble::advertisement::{AdStructureError, IncomingAdvertisement, RawAdvertisement};
use alloc::boxed::Box;

pub trait Scanner {
    fn on_advertisement(&mut self, callback: Box<dyn FnMut(&IncomingAdvertisement)>);
}

pub enum AdvertiserError {}
pub trait Advertiser {
    fn advertise(&mut self, advertisement: &RawAdvertisement) -> Result<(), AdStructureError>;
}
