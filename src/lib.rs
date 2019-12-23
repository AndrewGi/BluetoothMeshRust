#![no_std]
// Disable 'never constructed', 'never used', etc for now. It hides the more important warnings.
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(dead_code, cast_possible_truncation, use_self, doc_markdown)]
extern crate alloc;

pub mod ble;

pub mod random;
pub mod scheduler;
pub mod serializable;
pub mod time;
pub mod uuid;

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

pub mod properties;
