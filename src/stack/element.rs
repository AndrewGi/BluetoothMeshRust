use crate::address::UnicastAddress;
use crate::stack::model::Model;
use alloc::boxed::Box;
use alloc::vec::Vec;

pub struct Element {
    address: UnicastAddress,
    models: Vec<Box<dyn Model>>,
}
