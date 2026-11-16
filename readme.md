Rust port of [simple-js-sha2-512](https://github.com/Azero123/simple-js-sha2-512). No dependencies.

how to import (`Cargo.toml`):
```toml
[dependencies]
simple-rs-sha2-512 = "1"
```
hashing:
```rust
use simple_rs_sha2_512::sha2_512;

sha2_512("hello"); // 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043
simple_rs_sha2_512::digest(b"hello"); // raw [u8; 64]
```
Accepts anything that is `AsRef<[u8]>` (`&str`, `String`, `&[u8]`, `Vec<u8>`, ...). Strings are hashed as UTF-8.

performance:
```
cargo run --release --example performance
```
```
3673.93 kh/s ~ (Ryzen 9 7950X3D single thread, portable)
```
The portable implementation fully unrolls the rounds and computes the message schedule inline
(3211.14 kh/s -> 3673.93 kh/s, 587 MB/s -> 744 MB/s for large inputs).

On x86_64 CPUs with the SHA512 extensions (Intel Arrow Lake / Lunar Lake and newer) the hardware
`vsha512rnds2`/`vsha512msg*` instructions are used automatically (runtime-detected, still no dependencies).
That path is checked in the test suite against the portable one, on real hardware when available and
otherwise against software models of the instructions; it has not been benchmarked yet.
