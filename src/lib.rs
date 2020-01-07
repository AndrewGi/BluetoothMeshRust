#![no_std]
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
pub mod uuid;

// Timestamp depends on std or some other provided clock.
pub mod time;
mod timestamp;

//pub mod access;
pub mod address;
pub mod bearer;
pub mod control;
pub mod crypto;
pub mod foundation;
pub mod mesh;
pub mod model;
pub mod net;
pub mod reassembler;
pub mod transport;

pub mod mesh_io;

pub mod provisioning;

pub mod properties;
