use crate::CLIError;

pub fn sub_command() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("adapters").about("list possible HCI adapters")
}
pub fn list_possible_adapters() -> Result<(), CLIError> {
    list_usb_adapters()
}
#[cfg(feature = "btle_usb")]
pub fn list_usb_adapters() -> Result<(), CLIError> {
    for adapter in btle::hci::usb::manager::Manager::new()?
        .devices()?
        .bluetooth_adapters()
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
