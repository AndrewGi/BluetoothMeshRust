type Bytes = [u8; 16];

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct UUID(Bytes);
