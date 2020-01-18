use crate::bearer::{BearerError, IncomingEncryptedNetworkPDU, OutgoingEncryptedNetworkPDU};
use crate::ble::advertisement::{AdStructure, AdStructureDataBuffer, RawAdvertisement};
use crate::ble::gap::{Advertiser, AdvertiserError, Scanner, ScannerSink};
use crate::interface::{InputInterface, InterfaceSink, OutputInterface};
use crate::net::OwnedEncryptedPDU;
use crate::{ble, net};
use alloc::boxed::Box;
use core::marker::PhantomData;

impl From<net::EncryptedPDU<'_>> for ble::advertisement::AdStructure {
    fn from(pdu: net::EncryptedPDU<'_>) -> Self {
        AdStructure::MeshPDU(ble::advertisement::AdStructureDataBuffer::new(pdu.data()))
    }
}

pub struct AdvertisementInterface<'a, A: Advertiser, S: Scanner<'a>> {
    advertiser: A,
    scanner: S,
    scanner_sink: Option<Box<dyn InterfaceSink + 'a>>,
}
pub struct ScannerInputSink<'a>(&'a (dyn InterfaceSink + 'a));
impl<'a> ScannerSink for ScannerInputSink<'a> {
    fn consume_advertisement(&self, advertisement: &RawAdvertisement) {
        match advertisement.iter().next() {
            Some(AdStructure::MeshPDU(buf)) => {
                if let Some(pdu) = net::OwnedEncryptedPDU::new(buf.as_ref()) {
                    let incoming = IncomingEncryptedNetworkPDU {
                        encrypted_pdu: pdu,
                        rssi: advertisement.rssi(),
                        dont_relay: false,
                    };
                    self.0.consume_pdu(&incoming);
                }
            }
            _ => (),
        }
    }
}

impl<'a, A: Advertiser, S: Scanner<'a>> Advertiser for AdvertisementInterface<'a, A, S> {
    fn advertise(&self, advertisement: &RawAdvertisement) -> Result<(), AdvertiserError> {
        self.advertiser.advertise(advertisement)
    }
}
impl<'a, A: Advertiser, S: Scanner<'a>> OutputInterface for AdvertisementInterface<'a, A, S> {
    fn send_pdu(&self, pdu: &OutgoingEncryptedNetworkPDU) -> Result<(), BearerError> {
        for _ in 0..u8::from(pdu.transmit_parameters.count) {
            self.advertiser
                .advertise(&(&AdStructure::from(pdu.pdu.as_ref())).into())
                .map_err(|_| BearerError::AdvertiseError)?;
        }
        Ok(())
    }
}
impl<'a, A: Advertiser, S: Scanner<'a>> InputInterface<'a> for AdvertisementInterface<'a, A, S> {
    fn take_sink(&'a mut self, sink: Box<dyn InterfaceSink + 'a>) {
        self.scanner_sink = Some(sink);

        self.scanner.take_sink(Box::new(ScannerInputSink(
            self.scanner_sink.as_ref().unwrap().as_ref(),
        )))
    }
}
