use core::convert::TryInto;
use core::iter::Iterator;

#[derive(Copy, Clone)]
pub struct Bytes<'a> {
    data: &'a [u8],
    length: usize,
}
pub struct BytesMut<'a> {
    data: &'a mut [u8],
    length: usize,
}

pub trait Buf {
    fn length(&self) -> usize;
    fn capacity(&self) -> usize {
        self.bytes().len()
    }
    fn bytes(&self) -> &[u8];
    fn get_n_bytes(&self, index: usize, amount: usize) -> &[u8] {
        self.ensure_in_range(index + amount);
        &self.bytes()[index..index + amount]
    }
    fn remaining(&self) -> usize {
        self.capacity() - self.length()
    }
    fn ensure_remaining(&self, amount: usize) {
        if amount > self.remaining() {
            panic!("buffer out of space {} > {}", amount, self.remaining())
        }
    }
    fn ensure_in_range(&self, index: usize) {
        if index > self.length() {
            panic!("out of range {} > {}", index, self.remaining())
        }
    }

    fn get_u8(&self, index: usize) -> u8 {
        self.ensure_in_range(index);
        self.bytes()[index]
    }

    fn get_i8(&self, index: usize) -> i8 {
        self.get_u8(index) as i8
    }

    fn get_u16_be(&self, index: usize) -> u16 {
        u16::from_be_bytes(
            self.get_n_bytes(index, core::mem::size_of::<u16>())
                .try_into()
                .unwrap(),
        )
    }
    fn get_u16_le(&self, index: usize) -> u16 {
        u16::from_le_bytes(
            self.get_n_bytes(index, core::mem::size_of::<u16>())
                .try_into()
                .unwrap(),
        )
    }

    fn get_u32_be(&self, index: usize) -> u32 {
        u32::from_be_bytes(
            self.get_n_bytes(index, core::mem::size_of::<u32>())
                .try_into()
                .unwrap(),
        )
    }
    fn get_u32_le(&self, index: usize) -> u32 {
        u32::from_le_bytes(
            self.get_n_bytes(index, core::mem::size_of::<u32>())
                .try_into()
                .unwrap(),
        )
    }

    fn get_i16_be(&self, index: usize) -> i16 {
        i16::from_be_bytes(
            self.get_n_bytes(index, core::mem::size_of::<i16>())
                .try_into()
                .unwrap(),
        )
    }
    fn get_i16_le(&self, index: usize) -> i16 {
        i16::from_le_bytes(
            self.get_n_bytes(index, core::mem::size_of::<i16>())
                .try_into()
                .unwrap(),
        )
    }

    fn get_i32_be(&self, index: usize) -> i32 {
        i32::from_be_bytes(
            self.get_n_bytes(index, core::mem::size_of::<i32>())
                .try_into()
                .unwrap(),
        )
    }
    fn get_i32_le(&self, index: usize) -> i32 {
        i32::from_le_bytes(
            self.get_n_bytes(index, core::mem::size_of::<i32>())
                .try_into()
                .unwrap(),
        )
    }

    fn get_u24_be(&self, index: usize) -> u32 {
        let b = self.get_n_bytes(index, 3);
        u32::from_le_bytes([b[0], b[1], b[2], 0])
    }
    fn get_u24_le(&self, index: usize) -> u32 {
        let b = self.get_n_bytes(index, 3);
        u32::from_le_bytes([b[0], b[1], b[2], 0])
    }
}

pub trait BufMut: Buf {
    fn push_u8(&mut self, value: u8);
    fn push_bytes<'a, I: Iterator<Item = &'a u8>>(&mut self, value: I) {
        let (low, high) = value.size_hint();
        self.ensure_remaining(high.unwrap_or(low));
        for v in value {
            self.push_u8(*v)
        }
    }
    fn push_bytes_swapped(&mut self, value: &[u8]) {
        self.push_bytes(value.iter().rev())
    }

    fn push_i8(&mut self, value: i8) {
        self.push_u8(value as u8)
    }

    fn push_u16_le(&mut self, value: u16) {
        self.push_bytes(value.to_le_bytes().iter())
    }
    fn push_u16_be(&mut self, value: u16) {
        self.push_bytes(value.to_be_bytes().iter())
    }

    fn push_i16_le(&mut self, value: i16) {
        self.push_bytes(value.to_le_bytes().iter())
    }
    fn push_i16_be(&mut self, value: i16) {
        self.push_bytes(value.to_be_bytes().iter())
    }

    fn push_u32_le(&mut self, value: u32) {
        self.push_bytes(value.to_le_bytes().iter())
    }
    fn push_u32_be(&mut self, value: u32) {
        self.push_bytes(value.to_be_bytes().iter())
    }

    fn push_i32_le(&mut self, value: i32) {
        self.push_bytes(value.to_le_bytes().iter())
    }
    fn push_i32_be(&mut self, value: i32) {
        self.push_bytes(value.to_be_bytes().iter())
    }

    fn push_u24_le(&mut self, value: u32) {
        self.push_bytes(value.to_le_bytes()[..3].iter())
    }
    fn push_u24_be(&mut self, value: u32) {
        self.push_bytes(value.to_be_bytes()[..3].iter())
    }
}

impl<'a> Buf for Bytes<'a> {
    fn length(&self) -> usize {
        self.length
    }

    fn capacity(&self) -> usize {
        self.data.len()
    }

    fn bytes(&self) -> &[u8] {
        self.data
    }
}
impl<'a> From<&'a BytesMut<'a>> for Bytes<'a> {
    fn from(bytes: &'a BytesMut<'a>) -> Self {
        Bytes {
            data: bytes.data,
            length: bytes.length,
        }
    }
}
