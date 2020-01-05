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
pub mod timestamp;
pub mod uuid;

pub mod address;
pub mod bearer;
pub mod control;
pub mod crypto;
pub mod foundation;
pub mod lower;
pub mod mesh;
pub mod model;
pub mod net;
pub mod reassembler;
pub mod upper;

pub mod mesh_io;

pub mod provisioning;

pub mod properties;
