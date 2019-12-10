use core::convert::TryInto;
use core::iter::Iterator;
use core::ops::{Deref, DerefMut, Range, RangeBounds};

#[derive(Copy, Clone)]
pub struct Bytes<'a> {
    data: &'a [u8],
    length: usize,
}
pub struct BytesMut<'a> {
    data: &'a mut [u8],
    length: usize,
}

impl Bytes<'_> {
    pub fn new_with_length(data: &[u8], length: usize) -> Bytes {
        Bytes { data, length }
    }
    pub fn new(data: &[u8]) -> Bytes {
        Self::new_with_length(data, data.len())
    }
}

impl BytesMut<'_> {
    pub fn new_with_length(data: &mut [u8], length: usize) -> BytesMut {
        BytesMut { data, length }
    }
    pub fn new(data: &mut [u8]) -> BytesMut {
        Self::new_with_length(data, data.len())
    }
}
pub trait Buf {
    fn length(&self) -> usize;
    fn capacity(&self) -> usize {
        self.bytes().len()
    }
    fn slice_to(&self, range: Range<usize>) -> Option<Bytes> {
        if range.end > self.length() {
            None
        } else {
            Some(Bytes::new(&self.bytes()[range.start..range.end]))
        }
    }
    fn bytes(&self) -> &[u8];
    fn length_mut(&mut self) -> &mut usize;
    fn add_length(&mut self, amount: usize) {
        self.ensure_remaining_space(amount);
        *self.length_mut() += amount;
    }
    fn sub_length(&mut self, amount: usize) {
        let l = self.length_mut();
        if amount > *l {
            panic!("buffer underflow amount: {} length: {}", amount, *l);
        } else {
            *l -= amount;
        }
    }
    fn get_n_bytes(&self, index: usize, amount: usize) -> &[u8] {
        self.ensure_in_range(index + amount);
        &self.bytes()[index..index + amount]
    }
    fn remaining_space(&self) -> usize {
        self.capacity() - self.length()
    }
    fn ensure_remaining_space(&self, amount: usize) {
        if amount > self.remaining_space() {
            panic!(
                "buffer out of space {} > {}",
                amount,
                self.remaining_space()
            )
        }
    }
    fn ensure_in_range(&self, index: usize) {
        if index > self.length() {
            panic!("out of range {} > {}", index, self.remaining_space())
        }
    }

    fn get_u8(&self, index: usize) -> u8 {
        self.ensure_in_range(index);
        self.bytes()[index]
    }
    fn pop_u8(&mut self) -> u8 {
        self.ensure_in_range(1);
        let v = self.get_u8(self.length() - 1);
        self.sub_length(1);
        v
    }

    fn get_i8(&self, index: usize) -> i8 {
        self.get_u8(index) as i8
    }
    fn pop_i8(&mut self) -> i8 {
        let v = self.get_i8(self.length() - core::mem::size_of::<i8>());
        self.sub_length(core::mem::size_of::<i8>());
        v
    }
    ///
    /// While writing all the methods for get/pop u8/i8/u16/i16/u32/i32/u24/i24 is not the
    /// most maintainable way of witting this code, Rust doesn't generically define from_be/le_bytes
    /// and macros don't allow for generating functions with prefix/postfixxes.
    ///

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
    fn pop_u16_be(&mut self) -> u16 {
        const SIZE: usize = core::mem::size_of::<u16>();
        let v = self.get_u16_be(self.length() - SIZE);
        self.sub_length(SIZE);
        v
    }
    fn pop_u16_le(&mut self) -> u16 {
        const SIZE: usize = core::mem::size_of::<u16>();
        let v = self.get_u16_le(self.length() - SIZE);
        self.sub_length(SIZE);
        v
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
    fn pop_u32_be(&mut self) -> u32 {
        const SIZE: usize = core::mem::size_of::<u32>();
        let v = self.get_u32_be(self.length() - SIZE);
        self.sub_length(SIZE);
        v
    }
    fn pop_u32_le(&mut self) -> u32 {
        const SIZE: usize = core::mem::size_of::<u32>();
        let v = self.get_u32_le(self.length() - SIZE);
        self.sub_length(SIZE);
        v
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

    fn pop_i32_be(&mut self) -> i32 {
        const SIZE: usize = core::mem::size_of::<i32>();
        let v = self.get_i32_be(self.length() - SIZE);
        self.sub_length(SIZE);
        v
    }
    fn pop_i32_le(&mut self) -> i32 {
        const SIZE: usize = core::mem::size_of::<i32>();
        let v = self.get_i32_le(self.length() - SIZE);
        self.sub_length(SIZE);
        v
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
    fn pop_u24_be(&mut self) -> u32 {
        const SIZE: usize = 3;
        let v = self.get_u24_be(self.length() - SIZE);
        self.sub_length(SIZE);
        v
    }
    fn pop_u24_le(&mut self) -> u32 {
        const SIZE: usize = 3;
        let v = self.get_u24_le(self.length() - SIZE);
        self.sub_length(SIZE);
        v
    }
    fn peek_bytes(&mut self, amount: usize) -> &[u8] {
        self.ensure_in_range(amount);
        let b = &self.bytes()[self.length() - amount..];
        b
    }
    fn pop_bytes(&mut self, amount: usize) -> &[u8] {
        let b = self.peek_bytes(amount);
        self.sub_length(amount);
        b
    }
}

pub trait BufMut: Buf {
    fn bytes_mut(&mut self) -> &mut [u8];
    fn slice_to_mut(&mut self, range: Range<usize>) -> Option<BytesMut> {
        if range.end > self.length() {
            None
        } else {
            Some(BytesMut::new(&mut self.bytes_mut()[range.start..range.end]))
        }
    }
    fn push_u8(&mut self, value: u8);
    fn push_bytes<'a, I: Iterator<Item = &'a u8>>(&mut self, value: I) {
        let (low, high) = value.size_hint();
        self.ensure_remaining_space(high.unwrap_or(low));
        for v in value {
            self.push_u8(*v)
        }
    }
    fn get_n_bytes_mut(&mut self, index: usize, amount: usize) -> &mut [u8] {
        self.ensure_in_range(index + amount);
        &mut self.bytes_mut()[index..index + amount]
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
impl Deref for Bytes<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}
impl Deref for BytesMut<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}
impl DerefMut for BytesMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.bytes_mut()
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
        &self.data[..self.length]
    }

    fn length_mut(&mut self) -> &mut usize {
        &mut self.length
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
impl Buf for BytesMut<'_> {
    fn length(&self) -> usize {
        self.length
    }

    fn capacity(&self) -> usize {
        self.data.len()
    }

    fn bytes(&self) -> &[u8] {
        &self.data[..self.length]
    }

    fn length_mut(&mut self) -> &mut usize {
        &mut self.length
    }
}
impl BufMut for BytesMut<'_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.length]
    }

    fn push_u8(&mut self, value: u8) {
        self.ensure_remaining_space(1);
        self.data[self.length] = value;
        self.length += 1;
    }
}

impl<'a> From<&'a [u8]> for Bytes<'a> {
    fn from(b: &'a [u8]) -> Bytes<'a> {
        Bytes::new(b)
    }
}
impl<'a> From<&'a mut [u8]> for BytesMut<'a> {
    fn from(b: &'a mut [u8]) -> BytesMut<'a> {
        BytesMut::new(b)
    }
}
