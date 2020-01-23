use bluetooth_mesh::address::Address;
use bluetooth_mesh::mesh::ElementCount;
use std::fs::File;
use std::str::FromStr;

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
pub fn generate(device_state_path: File, element_count: ElementCount) {}
