#![no_std]
// Disable 'never constructed', 'never used', etc for now. It hides the more important warnings.
#![allow(dead_code)]
extern crate alloc;

mod ble;

mod random;
mod serializable;
mod time;
mod uuid;

//mod access;
mod address;
mod control;
mod crypto;
mod mesh;
mod net;
mod transport;
