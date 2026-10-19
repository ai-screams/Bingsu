use bingsu_core::collection::cwd_hash::{address, sha256};
// 이것을 실패시키는 것: SHA-256 padding/round/원문 입력에 접두사 또는 정규화를 섞는 것.
#[test]
fn cwd_sha256_matches_nist_vectors_and_raw_input() {
    let vectors: Vec<(Vec<u8>, &str)> = vec![
        (
            vec![],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            vec![97, 98, 99],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            vec![
                97, 98, 99, 100, 98, 99, 100, 101, 99, 100, 101, 102, 100, 101, 102, 103, 101, 102,
                103, 104, 102, 103, 104, 105, 103, 104, 105, 106, 104, 105, 106, 107, 105, 106,
                107, 108, 106, 107, 108, 109, 107, 108, 109, 110, 108, 109, 110, 111, 109, 110,
                111, 112, 110, 111, 112, 113,
            ],
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            vec![b'a'; 1_000_000],
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        ),
        (
            vec![b'a'; 55],
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
        ),
        (
            vec![b'a'; 56],
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
        ),
        (
            vec![b'a'; 63],
            "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
        ),
        (
            vec![b'a'; 64],
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        ),
        (
            vec![b'a'; 65],
            "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
        ),
        (
            vec![47],
            "8a5edab282632443219e051e4ade2d1d5bbc671c781051bf1437897cbdfea0f1",
        ),
        (
            vec![47, 255, 254],
            "eb3d3d1fc8e8e37829502e2bdbb0dfebd75393613bf92b6708a8f220b6afb4dc",
        ),
        (
            [b"/".as_slice(), &vec![b'a'; 65_535]].concat(),
            "d4292b5f100dda7defb2fff5dbbb6caa5106d170b814978e614289e9cdec0c4f",
        ),
    ];
    for (input, expected) in vectors {
        assert_eq!(address(&input), expected, "length {}", input.len());
        let bytes: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&expected[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(sha256(&input).as_slice(), bytes);
    }
    assert_ne!(sha256(b"/a/../b"), sha256(b"/b"));
    assert_ne!(sha256(b"/"), sha256(b"/\0"));
}
