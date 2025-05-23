use crate::CLIError;
#[cfg(feature = "mesh")]
use bluetooth_mesh::{device_state, mesh};
use btle::bytes::Storage;
use btle::hci::adapter::Adapter;
use btle::hci::command::CommandPacket;
use btle::hci::event::EventPacket;
use futures_core::future::LocalBoxFuture;
use std::convert::TryFrom;
use std::fmt::{Error, Formatter};
use std::str::FromStr;
use usbw::libusb::asyncs::AsyncContext;

pub struct HexSlice<'a>(pub &'a [u8]);
impl<'a> std::fmt::UpperHex for HexSlice<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        for &b in self.0 {
            write!(f, "{:X}", b)?;
        }
        Ok(())
    }
}

impl<'a> std::fmt::LowerHex for HexSlice<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        for &b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}
pub fn is_hex_str(s: &str) -> bool {
    if s.len() % 2 == 1 {
        return false;
    }
    for c in s.chars() {
        if !c.is_digit(16) {
            return false;
        }
    }
    return true;
}
pub fn is_128_bit_hex_str_validator(input: String) -> Result<(), String> {
    if input.len() == 32 && is_hex_str(&input) {
        Ok(())
    } else {
        Err(format!("'{}' is not a 128-bit hex string", &input))
    }
}
#[cfg(feature = "mesh")]
pub fn is_ttl(input: String) -> Result<(), String> {
    let error_msg = || Err(format!("`{}` is not a valid TTL", &input));
    match u8::from_str(&input) {
        Ok(v) => match mesh::TTL::try_from(v) {
            Ok(_) => Ok(()),
            Err(_) => error_msg(),
        },
        Err(_) => error_msg(),
    }
}
pub fn is_u8_validator(input: String) -> Result<(), String> {
    match u8::from_str(&input) {
        Ok(_) => Ok(()),
        Err(_) => Err(format!("'{}' is not a 8-bit unsigned integer", &input)),
    }
}
pub fn is_u16_validator(input: String) -> Result<(), String> {
    match u16::from_str(&input) {
        Ok(_) => Ok(()),
        Err(_) => Err(format!("'{}' is not a 16-bit unsigned integer", &input)),
    }
}
#[cfg(feature = "mesh")]
pub fn is_u24_validator(input: String) -> Result<(), String> {
    match u32::from_str(&input)
        .ok()
        .and_then(|v| bluetooth_mesh::mesh::U24::try_from(v).ok())
    {
        Some(_) => Ok(()),
        None => Err(format!("'{}' is not a 24-bit unsigned integer", &input)),
    }
}
pub fn is_u32_validator(input: String) -> Result<(), String> {
    match u32::from_str(&input) {
        Ok(_) => Ok(()),
        Err(_) => Err(format!("'{}' is not a 32-bit unsigned integer", &input)),
    }
}
pub fn hex_str_to_bytes<T: Default + AsMut<[u8]>>(s: &str) -> Option<T> {
    let mut out = T::default();
    if s.len() != out.as_mut().len() * 2 || out.as_mut().len() == 0 {
        None
    } else {
        {
            let buf = out.as_mut();
            for (i, c) in s.chars().enumerate() {
                let v = u8::try_from(c.to_digit(16)?).expect("only returns [0..=15]");
                buf[i / 2] |= v << u8::try_from(((i + 1) % 2) * 4).expect("only returns 0 or 4");
            }
        }
        Some(out)
    }
}
pub fn is_bool_validator(input: String) -> Result<(), String> {
    bool::from_str(&input)
        .ok()
        .map(|_| ())
        .ok_or(format!("'{}' is not a valid bool", &input))
}
pub fn load_file(path: &str, writeable: bool, create: bool) -> Result<std::fs::File, CLIError> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(writeable)
        .truncate(writeable)
        .create(create)
        .open(path)
        .map_err(|e| CLIError::IOError(path.to_owned(), e))
}
#[cfg(feature = "mesh")]
pub fn load_device_state(path: &str) -> Result<device_state::DeviceState, CLIError> {
    serde_json::from_reader(load_file(path, false, false)?).map_err(CLIError::SerdeJSON)
}
#[cfg(feature = "mesh")]
pub fn write_device_state(
    path: &str,
    device_state: &device_state::DeviceState,
) -> Result<(), CLIError> {
    serde_json::to_writer_pretty(load_file(path, true, true)?, device_state)
        .map_err(CLIError::SerdeJSON)
}
pub fn tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("can't make async runtime")
}
#[derive(Debug)]
pub enum HCIAdapter {
    Usb(btle::hci::usb::adapter::Adapter),
    #[cfg(not(all(unix, feature = "btle_bluez")))]
    BlueZ(btle::hci::adapter::DummyAdapter),
    #[cfg(all(unix, feature = "btle_bluez"))]
    BlueZ(
        btle::hci::stream::Stream<
            btle::hci::bluez_socket::AsyncHCISocket,
            Box<btle::hci::bluez_socket::AsyncHCISocket>,
        >,
    ),
}
impl Adapter for HCIAdapter {
    fn write_command<'s, 'p: 's>(
        &'s mut self,
        packet: CommandPacket<&'p [u8]>,
    ) -> LocalBoxFuture<'s, Result<(), btle::hci::adapter::Error>> {
        match self {
            HCIAdapter::Usb(u) => Adapter::write_command(u, packet),
            HCIAdapter::BlueZ(b) => Adapter::write_command(b, packet),
        }
    }
    fn read_event<'s, 'p: 's, S: Storage<u8> + 'p>(
        &'s mut self,
    ) -> LocalBoxFuture<'s, Result<EventPacket<S>, btle::hci::adapter::Error>> {
        match self {
            HCIAdapter::Usb(u) => Adapter::read_event(u),
            HCIAdapter::BlueZ(b) => Adapter::read_event(b),
        }
    }
}
pub fn libusb_context() -> &'static AsyncContext {
    static CONTEXT: once_cell::sync::OnceCell<AsyncContext> = once_cell::sync::OnceCell::new();
    CONTEXT.get_or_init(|| {
        let context =
            usbw::libusb::context::default_context().expect("unable to start libusb context");
        context.set_debug_level(usbw::libusb::context::LogLevel::Info);
        context.start_async()
    })
}
pub async fn usb_adapter(adapter_id: u16) -> Result<btle::hci::usb::adapter::Adapter, CLIError> {
    let context = libusb_context();
    let device_list = context.context_ref().device_list();
    let mut adapters = btle::hci::usb::device::bluetooth_adapters(device_list.iter());
    let adapter = adapters
        .nth(adapter_id.into())
        .ok_or_else(|| CLIError::OtherMessage("no usb bluetooth adapters found".to_owned()))??
        .open()
        .map_err(|e: usbw::libusb::error::Error| match e {
            usbw::libusb::error::Error::NotSupported => CLIError::OtherMessage(
                "is the libusb driver installed for the USB adapter? (NotImplemented Error)"
                    .to_owned(),
            ),
            e => CLIError::HCIAdapterError(btle::hci::adapter::Error::IOError(
                btle::hci::usb::Error::from(e).into(),
            )),
        })?;
    let mut adapter = btle::hci::usb::adapter::Adapter::open(context.make_async_device(adapter))?;
    adapter
        .flush_event_buffer()
        .await
        .map_err(btle::hci::usb::Error::from)?;
    Ok(adapter)
}
pub async fn hci_adapter(which_adapter: &str) -> Result<HCIAdapter, CLIError> {
    pub const USB_PREFIX: &'static str = "usb:";
    pub const BLUEZ_PREFIX: &'static str = "bluez:";
    if which_adapter.starts_with(USB_PREFIX) {
        Ok(HCIAdapter::Usb(
            usb_adapter((&which_adapter[USB_PREFIX.len()..]).parse().map_err(|_| {
                CLIError::OtherMessage(format!("bad usb adapter {}", which_adapter))
            })?)
            .await?,
        ))
    } else if which_adapter.starts_with(BLUEZ_PREFIX) {
        Ok(HCIAdapter::BlueZ(bluez_adapter(
            (&which_adapter[BLUEZ_PREFIX.len()..])
                .parse()
                .map_err(|_| {
                    CLIError::OtherMessage(format!("bad bluez adapter {}", which_adapter))
                })?,
        )?))
    } else {
        Err(CLIError::OtherMessage(format!(
            "unrecognized HCI adapter `{}`",
            which_adapter
        )))
    }
}
#[cfg(not(all(unix, feature = "btle_bluez")))]
pub fn bluez_adapter(_: u16) -> Result<btle::hci::adapter::DummyAdapter, CLIError> {
    Err(CLIError::OtherMessage(
        "bluez either isn't enable or supported on this platform".to_owned(),
    ))
}
#[cfg(all(unix, feature = "btle_bluez"))]
pub fn bluez_adapter(
    adapter_id: u16,
) -> Result<
    btle::hci::stream::Stream<
        btle::hci::bluez_socket::AsyncHCISocket,
        Box<btle::hci::bluez_socket::AsyncHCISocket>,
    >,
    CLIError,
> {
    use btle::hci::bluez_socket;
    use core::convert::TryInto;
    let manager = bluez_socket::Manager::new()
        .map_err(|e| CLIError::HCIAdapterError(btle::hci::adapter::Error::IOError(e)))?;
    let socket = manager
        .get_adapter_socket(bluez_socket::AdapterID(adapter_id))
        .map_err(|e| CLIError::HCIAdapterError(btle::hci::adapter::Error::IOError(e)))?
        .try_into()
        .map_err(|e| CLIError::IOError("unable to turn the bluez socket -> async".to_owned(), e))?;
    Ok(btle::hci::stream::Stream::new(Box::pin(socket)))
}
