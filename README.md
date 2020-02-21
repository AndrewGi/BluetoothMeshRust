# Bluetooth Mesh Rust

[Docs](https://docs.rs/bluetooth_mesh/)

[Crates.io](https://crates.io/crates/bluetooth_mesh) 

!! WIP and API not stable until version 1.0 !!

Cross-platform, full Bluetooth Mesh stack implemented in Rust. Following the Bluetooth Mesh Spec Core v1.0 by SIG. Designed to work with any almost any BLE radio (uses https://github.com/AndrewGi/btle/ for platform dependent Bluetooth drivers). While a stack is provided by the library, all the primitives and objects needed to customize and create your own stack are provided.

This library is designed for `#![no_std]` in mind. However, because of the complexity of the Bluetooth Mesh Stack, `std` is required for the `full_stack` which uses async tokio for message handling and processing. `#![no_std]` is also disabled for now until https://github.com/rust-lang/rust/pull/69033 hits nightly/stable.

The only heap allocations made during processing a message is allocating memory for the message at the access layer. Most Mesh PDUs are <31 bytes (to fit in a single BLE Advertisement) so the Network and Lower Transport Layer stores its data statically on the stack. Upper PDUs and above allow for allocation elsewhere than the stack (Upper Transport PDUs can be up to 380 bytes!) but a custom allocator/storage for the PDU can be genericly provided.

## Examples
See [Mesh CLI](/cli) for an application example.  

## How the Stack works
![The flowchart of the full mesh stack](/mesh_stack.png)
