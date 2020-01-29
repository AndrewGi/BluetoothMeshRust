# Bluetooth Mesh CLI
This is a command line utility to control and interface with Bluetooth Mesh Networks. While not all devices have supporting bearers,
they can still run utilitiy commands to generate keys, read device_state files and to encrypt/decrypt messages.  

See `cargo run -- --help` for more help/info.  

## Sub Commands
- `crypto` Read/Write/Generate crypto keys
- `provisioner` Act as a provisioner in a Mesh Network (requires bearer)
- `generate` Generate new `device_state.json` file
- Many more to come
