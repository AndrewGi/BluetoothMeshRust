use uuid;
pub trait Address {
    fn as_u16(&self) -> u16;
    fn label_uuid(&self) -> Option<uuid::Uuid> {
        None
    }
}

pub struct UnicastAddress {
    value: u16
}
pub struct GroupAddress {
    value: u16
}
pub struct VirtualAddress {
    value: u16,
    label: uuid::Uuid
}
impl Address for UnicastAddress {
    fn as_u16(&self) -> u16 {
        self.value
    }
}
impl Address for GroupAddress {
    fn as_u16(&self) -> u16 {
        self.value
    }
}

impl Address for VirtualAddress {
    fn as_u16(&self) -> u16 {
        self.value
    }
    fn label_uuid(&self) -> Option<uuid::Uuid> {
        Some(self.label)
    }
}