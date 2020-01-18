//! Network Input/Output Interface and Filter.
use crate::bearer::{BearerError, IncomingEncryptedNetworkPDU, OutgoingEncryptedNetworkPDU};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;

pub trait InterfaceSink {
    fn consume_pdu(&self, pdu: &IncomingEncryptedNetworkPDU);
}
pub trait InputInterface<'a> {
    fn take_sink(&'a mut self, sink: Box<dyn InterfaceSink + 'a>);
}

pub struct InputInterfaces<Sink: InterfaceSink + Clone + 'static> {
    sink: Sink,
}
impl<'a, Sink: InterfaceSink + Clone + 'static> InputInterfaces<Sink> {
    pub fn new(sink: Sink) -> Self {
        Self { sink }
    }
    pub fn add_interface(&'a self, interface: &'a mut dyn InputInterface<'a>) {
        interface.take_sink(Box::new(self.sink.clone()))
    }
}
pub trait OutputInterface {
    fn send_pdu(&self, pdu: &OutgoingEncryptedNetworkPDU) -> Result<(), BearerError>;
}
#[derive(Clone, Default)]
pub struct OutputInterfaces<'a> {
    interfaces: Vec<&'a dyn OutputInterface>,
}
impl<'a> OutputInterfaces<'a> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_interface<'b: 'a>(&mut self, interface: &'b dyn OutputInterface) {
        self.interfaces.push(interface)
    }
    pub fn send_pdu(&self, pdu: &OutgoingEncryptedNetworkPDU) -> Result<(), BearerError> {
        for &interface in self.interfaces.iter() {
            interface.send_pdu(pdu)?
        }
        Ok(())
    }
}
