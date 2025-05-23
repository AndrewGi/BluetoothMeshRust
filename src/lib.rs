//! # Pure Rust Bluetooth Mesh Stack.
//! The layers are designed so they can be put together in different ways to make different stacks
//! (single-threaded, multi-threaded, multi-radio, etc).
//! General stack glue is available in [`stack`] while a prebuilt full-stack requires `std`,
//! `async`, etc.
//! ## How a Bluetooth Mesh Stack works
//!
// No STD disabled until https://github.com/rust-lang/rust/pull/69033 goes stable/nightly.
//#![no_std]
#![deny(rustdoc::broken_intra_doc_links)]
//Might re-enable clippy::restriction later.
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(
    dead_code,
    clippy::cast_possible_truncation,
    clippy::use_self,
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "serde-1")]
extern crate serde;

extern crate alloc;
extern crate btle;
pub use btle::{bytes, uuid};
pub use driver_async::asyncs;
pub mod random;
pub mod timestamp;

pub mod access;
pub mod address;
pub mod beacon;
pub mod control;
pub mod crypto;
pub mod foundation;
pub mod lower;
pub mod mesh;
pub mod net;
pub mod reassembler;
pub mod replay;
pub mod segmenter;
pub mod upper;

pub mod device_state;
pub mod friend;
pub mod interface;
pub mod relay;
//pub mod mesh_io;
//pub mod advertisement;
pub mod stack;

pub mod models;

pub mod provisioning;

pub mod properties;

#[cfg(test)]
pub mod samples;
