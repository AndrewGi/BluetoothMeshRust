//! Element Layer
use crate::address::UnicastAddress;
use crate::mesh::ElementIndex;
use crate::stack::model::Model;
use crate::stack::Stack;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::convert::TryInto;

pub struct Element {
    address: UnicastAddress,
    models: Vec<Box<dyn Model>>,
}

pub struct ElementRef<S: Stack, Storage: Borrow<S>> {
    _marker: core::marker::PhantomData<S>,
    stack: Storage,
    element_index: ElementIndex,
}
impl<S: Stack, Storage: Borrow<S>> ElementRef<S, Storage> {
    pub fn new(stack: Storage, element_index: ElementIndex) -> Self {
        let count = stack.borrow().element_count();
        assert!(
            element_index.0 < count.0,
            "out of bounds element_index `{}` >= `{}`",
            element_index.0,
            count.0
        );
        ElementRef {
            _marker: core::marker::PhantomData,
            stack,
            element_index,
        }
    }
    pub fn stack(&self) -> &S {
        self.stack.borrow()
    }
    pub fn element_index(&self) -> ElementIndex {
        self.element_index
    }
    pub fn element_address(&self) -> UnicastAddress {
        (u16::from(self.stack().primary_address()) + u16::from(self.element_index.0))
            .try_into()
            .expect("invalid stack unicast address range")
    }
}
