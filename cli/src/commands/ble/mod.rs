use crate::CLIError;

pub mod bearers;
pub mod hci;
pub mod remote;

pub fn sub_command() -> clap::App<'static, 'static> {
    clap::SubCommand::with_name("ble")
        .about("interact directly with the BLE driver")
        .subcommand(hci::sub_command())
}

pub fn ble_matches(
    parent_logger: &slog::Logger,
    ble_matches: &clap::ArgMatches,
) -> Result<(), CLIError> {
    let logger = parent_logger.new(o!());
    match ble_matches.subcommand() {
        ("hci", Some(hci_matches)) => hci::hci_matches(&logger, hci_matches),
        ("", None) => Err(CLIError::Clap(clap::Error::with_description(
            "missing ble subcommand",
            clap::ErrorKind::ArgumentNotFound,
        ))),
        _ => unreachable!("unhandled ble subcommand"),
    }
}
