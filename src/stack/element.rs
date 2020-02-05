use crate::address::UnicastAddress;
use crate::mesh::ElementIndex;
use crate::stack::model::Model;
use crate::stack::{Stack, StackInternals};
use alloc::boxed::Box;
use alloc::vec::Vec;

pub struct Element {
    address: UnicastAddress,
    models: Vec<Box<dyn Model>>,
}

pub struct ElementRef<S: Stack, Storage: AsRef<S>> {
    stack: Storage,
    element_index: ElementIndex,
}
impl<S: Stack, Storage: AsRef<S>> ElementRef<S, Storage> {
    pub fn new(stack: Storage, element_index: ElementIndex) -> Self {
        let count = stack.as_ref().element_count();
        assert!(
            element_index.0 < count.0,
            "out of bounds element_index `{}` >= `{}`",
            element_index.0,
            count
        );
        ElementRef {
            stack,
            element_index,
        }
    }
    pub fn stack(&self) -> &S {
        self.stack.as_ref()
    }
    pub fn element_index(&self) -> ElementIndex {
        self.element_index
    }
    pub fn element_address(&self) -> UnicastAddress {
        self.stack()
            .element_address(self.element_index)
            .expect("element_index should be checked by constructor")
    }
}
