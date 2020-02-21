# Bluetooth Mesh Rust

[Docs](https://docs.rs/bluetooth_mesh/)

[Crates.io](https://crates.io/crates/bluetooth_mesh)  


See [Mesh CLI](/cli) for an application example.  

!! WIP but version 1.0 nearly finished !!

Cross-platform, full Bluetooth Mesh stack implemented in Rust. Following the Bluetooth Mesh Spec Core v1.0 by SIG. Designed to work with any almost any BLE radio (uses https://github.com/AndrewGi/btle/ for platform dependent Bluetooth drivers). While a stack is provided by the library, all the primatives and objects needed to customize and create your own stack are provided.

This library is designed for `#![no_std]` in mind. Because of the complexity of the Bluetooth Mesh Stack, `std` is required for teh  for full_stack which uses async tokio for message handling and processing.

The only heap allocations made durning processing a message is allocating memory for the message at the access layer. Most Mesh PDUs are <31 bytes (to fit in a single BLE Advertisement) so the Network and Lower Transport Layer stores its data staticly on the stack.

## How the Stack works
![The flowchart of the full mesh stack](/mesh_stack.png)
