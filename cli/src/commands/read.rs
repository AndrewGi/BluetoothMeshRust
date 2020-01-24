pub fn sub_command() -> clap::App<'static, 'static> {
	clap::SubCommand::with_name("read")
		.about("Read and check information from a device_state file")
}