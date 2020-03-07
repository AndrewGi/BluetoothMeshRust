use crate::address::{Address, UnicastAddress, VirtualAddress};
use crate::crypto::key::{AppKey, DevKey, Key, NetKey};
use crate::crypto::nonce::AppNonceParts;
use crate::crypto::{aes::MicSize, MIC};
use crate::mesh::{IVIndex, SequenceNumber, U24};
use crate::uuid::UUID;
use crate::{mesh, upper};
use core::str::FromStr;

fn sample_app_key() -> AppKey {
    AppKey::new(Key::from_str("63964771734fbd76e3b40519d1d94a48").expect("from sample data"))
}
fn sample_net_key() -> NetKey {
    NetKey::new(Key::from_str("7dd7364cd842ad18c17c2b820c84c3d6").expect("from sample data"))
}
fn sample_dev_key() -> DevKey {
    DevKey::new(Key::from_str("9d6dd0e96eb25dc19a40ed9914f8f03f").expect("from sample data"))
}
#[test]
fn message22() {
    //let opcode = Opcode::Vendor(VendorOpcode::new(0x15), CompanyID(0x00a));
    let parameters = [0xd5_u8, 0x0a, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
    let payload = upper::AppPayload::new(parameters);
    let app_key = sample_app_key();
    let dst = VirtualAddress::new(&UUID(
        UUID::uuid_bytes_from_str("0073e7e4d8b9440faf8415df4c56c0e1").expect("from sample data"),
    ));
    assert_eq!(
        u16::from(dst.hash()),
        0xb529,
        "virtual address hash mismatch"
    );
    let parts = AppNonceParts {
        aszmic: false,
        seq: SequenceNumber(U24::new(0x07080B)),
        src: UnicastAddress::new(0x1234),
        dst: Address::Virtual(dst),
        iv_index: IVIndex(0x12345677),
    };
    let expected_nonce: [u8; 13] =
        mesh::bytes_str_to_buf("010007080b1234b52912345677").expect("from sample data");
    let nonce = parts.to_nonce();
    assert_eq!(
        AsRef::<[u8]>::as_ref(&nonce),
        &expected_nonce[..],
        "nonce mismatch"
    );
    let app_sm = upper::SecurityMaterials::VirtualAddress(nonce, &app_key, app_key.aid(), &dst);
    let encrypted = payload.encrypt(&app_sm, MicSize::Small);
    let expected_encrypted = [0x38_u8, 0x71, 0xb9, 0x04, 0xd4, 0x31, 0x52, 0x63];
    let expect_mic = MIC::Small(0x16CA48A0);
    assert_eq!(encrypted.mic(), expect_mic, "mic mismatch");
    assert_eq!(
        encrypted.data(),
        &expected_encrypted[..],
        "encrypted data mismatch"
    );
}
