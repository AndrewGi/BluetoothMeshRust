// Generalized over the rand Library so there's no hard dependencies.

pub fn random_bool() -> bool {
    rand::random()
}

pub fn random_u8() -> u8 {
    rand::random()
}

pub fn random_u16() -> u16 {
    rand::random()
}

pub fn random_u32() -> u32 {
    rand::random()
}

pub fn random_u64() -> u64 {
    rand::random()
}

pub fn random_16_bytes() -> [u8; 16] {
    rand::random()
}

pub fn random_32_bytes() -> [u8; 32] {
    rand::random()
}
