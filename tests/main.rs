use simple_rs_sha2_512::{digest, sha2_512};

const TESTS: &[(&str, &str)] = &[
    ("", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
    ("hello", "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"),
    ("abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    ("zxcv", "5a46ff4ed1ad5ed8ad2acdbf8f6dab532351f3dd999708e3f179aed0ede4849d07727f85afb64ddb8a71edc6dc633e4556d2e75330e8a8227bfb6a267c7e4d96"),
    ("The quick brown fox jumps over the lazy dog", "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"),
    ("The quick brown fox jumps over the lazy dog.", "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed"),
    ("1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm", "7331b56d040445f700b884939d83dbcf0b4eca9baa428fd6420d1520e681c213c2415022bc980d6ddb26eb90bc043491538321d81dcc9ae7f913987c986445c2"),
    ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"),
    ("1abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "4afb077f8f88427ea6e17c1a6d65dcd25e9f2947f3281a03a3d578b9a1495dcebbe276bbc3c49bf80c5cb24748332feb1eeae538758175f0d7a32efaa907b771"),
    ("héllo wörld 🦀", "bbbdeb9c6c6d654d1fa07982a4bf7c0598add88d222036cffb7f1e479f5612d5cb0c26ab9893eda696c5cac2569781596deab8b12c74acce6ab7dd09e0d5cb3a"),
];

#[test]
fn known_vectors() {
    for (input, expected) in TESTS {
        assert_eq!(&sha2_512(input), expected, "input: {input:?}");
    }
}

/// Every length around the padding boundaries (one and two final blocks).
#[test]
fn all_lengths_up_to_300() {
    let expected = include_str!("lengths.txt");
    let data: Vec<u8> = (0..300u32).map(|i| (i * 31 + 7) as u8).collect();
    for (len, line) in expected.lines().enumerate() {
        assert_eq!(sha2_512(&data[..len]), line, "length {len}");
    }
}

#[test]
fn bytes_and_str_agree() {
    assert_eq!(
        sha2_512("hello"),
        sha2_512(String::from("hello").into_bytes())
    );
    assert_eq!(digest("hello").len(), 64);
}
