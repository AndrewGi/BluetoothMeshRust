use crate::CLIError;
use std::convert::TryInto;
use btle::hci::command::CommandPacket;
use futures_core::future::LocalBoxFuture;
use std::pin::Pin;
use btle::error::IOError;

pub struct PcapAdapter<'a, A: btle::hci::adapter::Adapter> {
	adapter: &'a mut A,
	pcap_writer: pcap_file::PcapWriter<std::fs::File>,
}
impl<'a, A: btle::hci::adapter::Adapter> PcapAdapter<'a, A> {
	pub fn open<P: AsRef<std::path::Path>>(
		adapter: &'a mut A,
		path: P,
	) -> Result<Self, Box<dyn btle::error::Error>> {
		Ok(PcapAdapter {
			adapter,
			pcap_writer: {
				let header = pcap_file::pcap::PcapHeader {
					datalink: pcap_file::DataLink::BLUETOOTH_HCI_H4,
					..pcap_file::pcap::PcapHeader::default()
				};
				let file = std::fs::OpenOptions::new().create(true).write(true).open(path).map_err(|e| CLIError::IOError("io error opening pcap file".to_owned(), e))?;
				pcap_file::PcapWriter::with_header(header, file).map_err(|e| CLIError::OtherMessage(format!("error opening pcap writer: {}", e)))?
			}
		}
		)
	}
	pub fn dump_packet(
		&mut self,
		packet: btle::hci::packet::RawPacket<&[u8]>,
	) -> Result<(), Box<dyn btle::error::Error>> {
			// TODO: Reuse same buffer
			let out = packet
				.pack::<Box<[u8]>>()
				.expect("Box should be able to hold any packet");
			let time = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map_err(|_| {
					CLIError::OtherMessage("time set before UNIX_EPOCH, can't save pcap".to_owned())
				})?;
				let ts_sec = time.as_secs().try_into().map_err(|_| {
					CLIError::OtherMessage(
						"time overflow error (u64->i32), can't save pcap".to_owned(),
					)
				})?;
				let ts_nsec = time.subsec_nanos().try_into().map_err(|_| {
					CLIError::OtherMessage(
						"time overflow error (u32->i32), can't save pcap".to_owned(),
					)
				})?;
			let len = out
				.as_ref()
				.len()
				.try_into()
				.expect("all HCI packets should be smaller than u32::MAX");
		self.pcap_writer.write(ts_sec, ts_nsec, out.as_ref(),len).map_err(|e| CLIError::OtherMessage(format!("error writing pcap: {}", e)))?;
		Ok(())
	}
}

impl<'a, A: btle::hci::adapter::Adapter> btle::hci::adapter::Adapter for PcapAdapter<'a, A> {
	fn write_command<'s, 'p: 's>(
		mut self: Pin<&'s mut Self>,
		packet: CommandPacket<&'p [u8]>,
	) -> LocalBoxFuture<'s, Result<(), btle::hci::adapter::Error>> {
		Box::pin(async move {
			unsafe { self.as_mut().get_unchecked_mut() }
				.dump_packet(packet.to_raw_packet::<Box<[u8]>>().as_ref())
				.map_err(|_| btle::hci::adapter::Error::IOError(IOError::Other))?;
			unsafe { self.map_unchecked_mut(|s| s.adapter) }
				.write_command(packet)
				.await
		})
	}

	fn read_event<'s, 'p: 's, S: btle::bytes::Storage<u8> + 'p>(
		mut self: Pin<&'s mut Self>,
	) -> LocalBoxFuture<'s, Result<btle::hci::event::EventPacket<S>, btle::hci::adapter::Error>>
	{
		Box::pin(async move {
			let event: btle::hci::event::EventPacket<S> =
				unsafe { self.as_mut().map_unchecked_mut(|s| s.adapter) }
					.read_event()
					.await?;
			unsafe { self.get_unchecked_mut() }
				.dump_packet(event.to_raw_packet::<Box<[u8]>>().as_ref())
				.map_err(|_| btle::hci::adapter::Error::IOError(IOError::Other))?;
			Ok(event)
		})
	}
}