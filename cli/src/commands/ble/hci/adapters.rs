use crate::{helper, CLIError};
use btle::hci::usb;
pub fn sub_command() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("adapters").about("list possible HCI adapters")
}
pub fn list_possible_adapters() -> Result<(), CLIError> {
    list_usb_adapters()
}
#[cfg(feature = "btle_usb")]
pub fn list_usb_adapters() -> Result<(), CLIError> {
    for adapter in
        usb::device::bluetooth_adapters(helper::libusb_context().context_ref().device_list().iter())
    {
        println!("USB Adapter: {:?}", &adapter);
    }
    Ok(())
}
#[cfg(not(feature = "btle_usb"))]
pub fn list_usb_adapters() -> Result<(), CLIError> {
    println!("USB HCI not enabled");
    Ok(())
}
