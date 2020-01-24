use bluetooth_mesh::address::{Address, UnicastAddress};
use bluetooth_mesh::mesh::ElementCount;
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use crate::{CLIError, helper};
use bluetooth_mesh::address::Address::Unicast;
use bluetooth_mesh::device_state;
pub fn sub_command() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("generate")
        .about("Generate a device state with desired parameters")
        .arg(
            clap::Arg::with_name("element_count")
                .short("c")
                .value_name("ELEMENT_COUNT")
                .required(true)
                .default_value("1")
                .validator(|count| {
                    if let Ok(c) = usize::from_str(&count) {
                        match c {
                            1..=0xFF => Ok(()),
                            _ => Err(format!(
                                "Invalid element count '{}'. Expected in range [1..0xFF]",
                                c
                            )),
                        }
                    } else {
                        Err(format!("Invalid element count '{}'. Not a number", count))
                    }
                }),
        )
        .arg(
            clap::Arg::with_name("element_address")
                .short("a")
                .value_name("UNICAST_ADDRESS")
                .required(true)
                .default_value("1")
                .validator(|address| {
                    let radix = if address.starts_with("0x") { 16 } else { 10 };
                    if let Ok(a) = u16::from_str_radix(address.trim_start_matches("0x"), radix) {
                        match Address::from(a) {
                            Address::Unicast(_) => Ok(()),
                            _ => Err(format!("Non-unicast address '{}' given", &address)),
                        }
                    } else {
                        Err(format!("Non-address '{}' given", &address))
                    }
                }),
        )
}
pub fn generate_matches(
    parent_logger: &slog::Logger,
    device_state_path: &str,
    gen_matches: &clap::ArgMatches,
) -> Result<(), CLIError> {
    match (
        gen_matches.value_of("element_count"),
        gen_matches.value_of("element_address"),
    ) {
        (Some(element_count), Some(element_address)) => {
            let count = ElementCount(element_count.parse().expect("checked by clap"));
            let address = UnicastAddress::new(element_address.parse().expect("checked by clap"));
            generate(parent_logger, device_state_path, address, count)
        },
        _ => unreachable!("element count and element address should have default values")
    }
}
pub fn generate(
    parent_logger: &slog::Logger,
    device_state_path: &str,
    primary_address: UnicastAddress,
    element_count: ElementCount,
) -> Result<(), CLIError> {
    let logger = parent_logger.new(o!("device_state_path" => device_state_path.to_owned()));
    let f = helper::load_file(device_state_path, true, true)?;
    info!(logger, "found device_state");
    let device_state = device_state::DeviceState::new(primary_address, element_count);
    serde_json::to_writer(f, &device_state).map_err(CLIError::SerdeJSON)?;
    Ok(())
}
