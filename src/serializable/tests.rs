use super::bytes::*;
#[test]
fn test_basic() {
    let mut test_buffer: [u8; 20] = [0; 20];
    let mut buf = BytesMut::new_empty(&mut test_buffer[..]);
    assert_eq!(buf.len(), 0);
    assert_eq!(buf.capacity(), 20);
    buf.push_u8(0x37).unwrap();
    assert_eq!(buf.len(), 1);
    assert_eq!(buf.capacity(), 20);
    assert_eq!(buf.peek_bytes(1).unwrap()[0], 0x37);
    assert_eq!(buf.pop_bytes(1).unwrap()[0], 0x37);
    assert_eq!(buf.len(), 0);
}

#[test]
fn test_length() {
    let mut test_buffer: [u8; 20] = [0; 20];
    let mut buf = BytesMut::new_with_length(&mut test_buffer[..], 0);
    assert_eq!(buf.len(), 0);
    buf.sub_length(1);
    assert_eq!(buf.len(), 0, "shouldn't have underflowed");
    buf.add_length(3);
    assert_eq!(buf.len(), 3);
    buf.sub_length(2);
    assert_eq!(buf.len(), 1);
    buf.add_length(5);
    assert_eq!(buf.len(), 6);
    buf.add_length(100);
    assert_eq!(buf.len(), buf.capacity());
    buf.sub_length(5);
    assert_eq!(buf.len(), 15);
    let mut buf = Bytes::new_with_length(&test_buffer[..], 0);
    assert_eq!(buf.len(), 0);
    buf.sub_length(1);
    assert_eq!(buf.len(), 0, "shouldn't have underflowed");
    buf.add_length(3);
    assert_eq!(buf.len(), 3);
    buf.sub_length(2);
    assert_eq!(buf.len(), 1);
    buf.add_length(5);
    assert_eq!(buf.len(), 6);
    buf.add_length(100);
    assert_eq!(buf.len(), buf.capacity());
    buf.sub_length(5);
    assert_eq!(buf.len(), 15);
}

#[test]
fn test_to_from_endian() {
    let test_u16: [u8; 4] = [0x28, 0x48, 0xA3, 0xF1];
    let out = u32::from_bytes_le(&test_u16[..]).unwrap();
    assert_eq!(out, 0xF1A34828);
    assert_eq!(out.to_bytes_le(), test_u16);
    assert_eq!(out.to_bytes_be(), [0xF1, 0xA3, 0x48, 0x28]);
    assert_eq!(u16::from_bytes_le(&out.to_bytes_le()[..2]).unwrap(), 0x4828);
}
