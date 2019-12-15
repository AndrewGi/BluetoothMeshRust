use super::bytes::*;
#[test]
pub fn test_basic() {
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
