//! Pure Rust Bluetooth Mesh Stack.
//! The layers are designed so they can be put together in different ways to make different stacks
//! (single-threaded, multi-threaded, multi-radio, etc).
//! A single-threaded stack is provided in [`stack`].
#![no_std]
#![deny(intra_doc_link_resolution_failure)]
//Might re-enable clippy::restriction later.
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(
    dead_code,
    clippy::cast_possible_truncation,
    clippy::use_self,
    clippy::doc_markdown,
    clippy::module_name_repetitions
)]

extern crate alloc;

pub mod ble;

pub mod random;
pub mod scheduler;
pub mod serializable;
pub mod timestamp;
pub mod uuid;

pub mod access;
pub mod address;
pub mod beacon;
pub mod bearer;
pub mod control;
pub mod crypto;
pub mod foundation;
pub mod lower;
pub mod mesh;
pub mod net;
pub mod reassembler;
pub mod replay;
pub mod upper;

pub mod device_state;
pub mod friend;
pub mod mesh_io;
pub mod stack;

pub mod models;

pub mod provisioning;

pub mod properties;
