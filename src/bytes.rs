use core::convert::TryInto;
use core::iter::Iterator;
use core::ops::{Deref, DerefMut, Range, RangeBounds};

#[derive(Copy, Clone)]
pub enum Endian {
    Big,
    Little,
    Native,
}

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
    /// Returns bytes trimmed to 0..capacity()
    fn bytes(&self) -> &[u8];
    fn capacity(&self) -> usize;
    fn add_length(&mut self, amount: usize);
    fn sub_length(&mut self, amount: usize);
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
    fn slice_to(&self, range: Range<usize>) -> Option<Bytes> {
        if range.end > self.length() {
            None
        } else {
            Some(Bytes::new(&self.bytes()[range.start..range.end]))
        }
    }
    fn get_n_bytes(&self, index: usize, amount: usize) -> &[u8] {
        self.ensure_in_range(index + amount);
        &self.bytes()[index..index + amount]
    }
    fn peek_bytes(&self, amount: usize) -> &[u8] {
        self.ensure_in_range(amount);
        let b = &self.bytes()[self.length() - amount..];
        b
    }
    fn pop_bytes(&mut self, amount: usize) -> &[u8] {
        self.ensure_remaining_space(amount);
        self.sub_length(amount);
        self.peek_bytes(amount)
    }

    fn get_at<T: ToFromBytesEndian>(&self, index: usize, endian: Endian) -> Option<T> {
        self.ensure_in_range(index + T::byte_size());
        T::from_bytes_endian(self.get_n_bytes(index, T::byte_size()), endian)
    }

    fn peek_be<T: ToFromBytesEndian>(&self) -> Option<T> {
        T::from_bytes_be(self.peek_bytes(T::byte_size()))
    }
    fn peek_le<T: ToFromBytesEndian>(&self) -> Option<T> {
        T::from_bytes_be(self.peek_bytes(T::byte_size()))
    }
    fn pop_be<T: ToFromBytesEndian>(&mut self) -> Option<T> {
        let out = self.peek_be()?;
        self.sub_length(T::byte_size());
        Some(out)
    }
    fn pop_le<T: ToFromBytesEndian>(&mut self) -> Option<T> {
        let out = self.peek_le()?;
        self.sub_length(T::byte_size());
        Some(out)
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
    fn push_be(&mut self, b: impl ToFromBytesEndian) {
        self.push_bytes(b.to_bytes_be().iter())
    }
    fn push_le(&mut self, b: impl ToFromBytesEndian) {
        self.push_bytes(b.to_bytes_le().iter())
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

    fn bytes(&self) -> &[u8] {
        &self.data[..self.length]
    }

    fn capacity(&self) -> usize {
        self.data.len()
    }

    fn add_length(&mut self, amount: usize) {
        self.ensure_remaining_space(amount);
        self.length += amount;
    }
    fn sub_length(&mut self, amount: usize) {
        self.ensure_in_range(amount);
        self.length -= amount;
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

    fn bytes(&self) -> &[u8] {
        &self.data[..self.length]
    }

    fn capacity(&self) -> usize {
        self.data.len()
    }

    fn add_length(&mut self, amount: usize) {
        self.ensure_remaining_space(amount);
        self.length += amount;
    }
    fn sub_length(&mut self, amount: usize) {
        self.ensure_in_range(amount);
        self.length -= amount;
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

pub trait ToFromBytesEndian: Sized {
    fn byte_size() -> usize;
    fn to_bytes_le(&self) -> &[u8];
    fn to_bytes_be(&self) -> &[u8];
    fn to_bytes_ne(&self) -> &[u8] {
        if cfg!(target_endian = "big") {
            self.to_bytes_be()
        } else {
            self.to_bytes_le()
        }
    }
    fn from_bytes_le(bytes: &[u8]) -> Option<Self>;
    fn from_bytes_be(bytes: &[u8]) -> Option<Self>;
    fn from_bytes_ne(bytes: &[u8]) -> Option<Self> {
        if cfg!(target_endian = "big") {
            Self::from_bytes_be(bytes)
        } else {
            Self::from_bytes_le(bytes)
        }
    }
    fn to_bytes_endian(&self, endian: Endian) -> &[u8] {
        match endian {
            Endian::Big => self.to_bytes_be(),
            Endian::Little => self.to_bytes_le(),
            Endian::Native => self.to_bytes_ne(),
        }
    }
    fn from_bytes_endian(bytes: &[u8], endian: Endian) -> Option<Self> {
        match endian {
            Endian::Big => Self::from_bytes_be(bytes),
            Endian::Little => Self::from_bytes_le(bytes),
            Endian::Native => Self::from_bytes_ne(bytes),
        }
    }
}
/*
impl<T, U> ToFromBytesEndian for U
where
    T: ToFromBytesEndian,
    U: From<T> + Into<T> + Copy,
{
    fn byte_size() -> usize {
        T::byte_size()
    }

    fn to_bytes_le(&self) -> &[u8] {
        T::from(self).to_bytes_le()
    }

    fn to_bytes_be(&self) -> &[u8] {
        T::from(self).to_bytes_be()
    }

    fn to_bytes_ne(&self) -> &[u8] {
        T::from(self).to_bytes_ne()
    }

    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        Some(U::from(T::from_bytes_le(bytes)?))
    }

    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Some(U::from(T::from_bytes_be(bytes)?))
    }

    fn from_bytes_ne(bytes: &[u8]) -> Option<Self> {
        Some(U::from(T::from_bytes_ne(bytes)?))
    }
}
*/
macro_rules! implement_to_from_bytes {
    ( $( $t:ty ), *) => {
        $(
            impl ToFromBytesEndian for $t {
    fn byte_size() -> usize {
        core::mem::size_of::<Self>()
    }

    fn to_bytes_le(&self) -> &[u8] {
        self.to_bytes_le()
    }

    fn to_bytes_be(&self) -> &[u8] {
        self.to_bytes_be()
    }

    fn to_bytes_ne(&self) -> &[u8] {
        self.to_bytes_ne()
    }

    fn from_bytes_le(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes_le(bytes.try_into().ok()?)
    }

    fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes_ne(bytes.try_into().ok()?)
    }

    fn from_bytes_ne(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes_ne(bytes.try_into().ok()?)
    }
}
        )*
    }
}
implement_to_from_bytes!(u8, i8, u16, i16, u32, i32, u64, i64);
