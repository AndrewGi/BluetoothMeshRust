use std::str::FromStr;
use bluetooth_mesh::mesh::KeyIndex;
use std::convert::TryFrom;
use crate::CLIError;
use bluetooth_mesh::device_state;

fn is_key_index(index: String) -> Result<(), String> {
	if u16::from_str(&index).ok().map(KeyIndex::try_from).map(|r| r.is_ok()).unwrap_or(false) {
		Ok(())
	} else {
		Err(format!("'{}' is not a valid key index", &index))
	}
}

pub fn sub_command() -> clap::App<'static, 'static> {
	clap::SubCommand::with_name("crypto")
		.about("Read/Write crypto information from/to a device_state file")
		.subcommand(
			clap::SubCommand::with_name("devkey")
				.about("show local device key")
		)
		.subcommand(
			clap::SubCommand::with_name("netkeys")
				.subcommand(
					clap::SubCommand::with_name("list")
						.arg(clap::Arg::with_name("nid")
							.help("include NID in list")
						)
				)
				.subcommand(clap::SubCommand::with_name("get")
					.arg(clap::Arg::with_name("index")
						.required(true)
						.value_name("INDEX")
						.validator(is_key_index)
					)
				)
		)
}
pub fn crypto_matches(
	parent_logger: &slog::Logger,
	device_state_path: &str,
	crypto_matches: &clap::ArgMatches) -> Result<(), CLIError> {
	let logger = parent_logger.new(o!("device_state_path" => device_state_path.to_owned()));
	debug!(logger, "crypto_subcommand");

	Ok(())

}
