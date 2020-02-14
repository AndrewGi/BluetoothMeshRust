use crate::bearer::{BearerError, IncomingEncryptedNetworkPDU, OutgoingEncryptedNetworkPDU};
use crate::btle::advertisement::{AdStructure, RawAdvertisement};
use crate::btle::advertiser::{Advertiser, Scanner, ScannerSink};
use crate::interface::{InputInterface, InterfaceSink, OutputInterface};
use crate::net;

impl From<net::EncryptedPDU<'_>> for btle::advertisement::AdStructure {
    fn from(pdu: net::EncryptedPDU<'_>) -> Self {
        AdStructure::MeshPDU(btle::advertisement::AdStructureDataBuffer::new(pdu.data()))
    }
}

pub struct ScannerInterface<InterSink: InterfaceSink, Scan: Scanner<ScannerInputSink<InterSink>>> {
    scanner: Scan,
    _marker: core::marker::PhantomData<InterSink>,
}
pub struct ScannerInputSink<InterSink: InterfaceSink>(InterSink);
impl<InterSink: InterfaceSink + Clone> Clone for ScannerInputSink<InterSink> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<InterSink: InterfaceSink> ScannerSink for ScannerInputSink<InterSink> {
    fn consume_advertisement(&mut self, advertisement: &RawAdvertisement) {
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

impl<A: Advertiser> OutputInterface for A {
    fn send_pdu(&mut self, pdu: &OutgoingEncryptedNetworkPDU) -> Result<(), BearerError> {
        for _ in 0..u8::from(pdu.transmit_parameters.count) {
            self.advertise(&(&AdStructure::from(pdu.pdu.as_ref())).into())
                .map_err(|_| BearerError::AdvertiseError)?;
        }
        Ok(())
    }
}
impl<InterSink: InterfaceSink, Scan: Scanner<ScannerInputSink<InterSink>>> InputInterface<InterSink>
    for ScannerInterface<InterSink, Scan>
{
    fn take_sink(&mut self, sink: InterSink) {
        self.scanner.take_sink(ScannerInputSink(sink))
    }
}
