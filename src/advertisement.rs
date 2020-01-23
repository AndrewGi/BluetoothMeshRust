use crate::bearer::{BearerError, IncomingEncryptedNetworkPDU, OutgoingEncryptedNetworkPDU};
use crate::ble::advertisement::{AdStructure, RawAdvertisement};
use crate::ble::gap::{Advertiser, Scanner, ScannerSink};
use crate::interface::{InputInterface, InterfaceSink, OutputInterface};
use crate::{ble, net};

impl From<net::EncryptedPDU<'_>> for ble::advertisement::AdStructure {
    fn from(pdu: net::EncryptedPDU<'_>) -> Self {
        AdStructure::MeshPDU(ble::advertisement::AdStructureDataBuffer::new(pdu.data()))
    }
}

pub struct ScannerInterface<'a, S: Scanner<'a>> {
    scanner: S,
    scanner_sink: Option<ScannerInputSink<'a>>,
}
#[derive(Clone, Copy)]
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
impl<'a, S: Scanner<'a>> From<S> for ScannerInterface<'a, S> {
    fn from(scanner: S) -> Self {
        Self {
            scanner,
            scanner_sink: None,
        }
    }
}
impl<A: Advertiser> OutputInterface for A {
    fn send_pdu(&self, pdu: &OutgoingEncryptedNetworkPDU) -> Result<(), BearerError> {
        for _ in 0..u8::from(pdu.transmit_parameters.count) {
            self.advertise(&(&AdStructure::from(pdu.pdu.as_ref())).into())
                .map_err(|_| BearerError::AdvertiseError)?;
        }
        Ok(())
    }
}
impl<'a, S: Scanner<'a>> InputInterface<'a> for ScannerInterface<'a, S> {
    fn take_sink(&'a mut self, sink: &'a dyn InterfaceSink) {
        self.scanner_sink = Some(ScannerInputSink(sink));
        self.scanner.take_sink(self.scanner_sink.as_ref().unwrap())
    }
}
