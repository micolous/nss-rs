use nss_rs::hash::{DigestContext, HashAlgorithm, hash};
use test_fixture::fixture_init;

fn check_sha256(data: &[u8], expected: &[u8; 32]) {
    // One-shot API
    let r = hash(&HashAlgorithm::SHA2_256, data).expect("hash");
    assert_eq!(expected, r.as_slice());

    // Test with multiple update calls
    let (a, b) = if data.len() >= 2 {
        data.split_at(data.len() / 2)
    } else {
        (data, b"".as_slice())
    };

    let mut c = DigestContext::new(HashAlgorithm::SHA2_256).expect("DigestContext::new");
    c.update(a).expect("DigestContext::update(a)");
    c.update(b).expect("DigestContext::update(b)");

    let r = c.digest().expect("DigestContext::digest");
    assert_eq!(expected, r.as_slice());
    assert_eq!(32, c.digest_size());
}

#[test]
fn sha256() {
    fixture_init();
    check_sha256(
        b"",
        &[
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
    );
    check_sha256(
        b"hello",
        &[
            44, 242, 77, 186, 95, 176, 163, 14, 38, 232, 59, 42, 197, 185, 226, 158, 27, 22, 30,
            92, 31, 167, 66, 94, 115, 4, 51, 98, 147, 139, 152, 36,
        ],
    );
}

/// Hash 10 GiB of null bytes.
#[test]
fn huge_sha256() {
    fixture_init();

    // dd if=/dev/zero bs=10240 count=1048576 | sha256sum
    let expected = [
        0x73, 0x23, 0x77, 0xe7, 0xf4, 0xa2, 0xab, 0xdc, 0x13, 0xdd, 0xfa, 0x1e, 0xb4, 0xc9, 0xc4,
        0x97, 0xfd, 0x2a, 0x2b, 0x29, 0x46, 0x74, 0xd0, 0x56, 0xcf, 0x51, 0x58, 0x1b, 0x47, 0xdd,
        0x58, 0x6d,
    ];
    let block = [0; 10240];
    let mut c = DigestContext::new(HashAlgorithm::SHA2_256).expect("DigestContext::new");
    for _ in 0..1048576 {
        c.update(&block).expect("DigestContext::update");
    }

    let r = c.digest().expect("DigestContext::digest");
    assert_eq!(expected, r.as_slice());
}
