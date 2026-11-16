use std::time::Instant;

fn main() {
    let amount = 1_000_000u64;
    let start = Instant::now();
    let mut seed = 0x2545f4914f6cdd1du64;
    for _ in 0..amount {
        // xorshift so each input differs, like Math.random() in the JS version
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let input = format!("0.{seed}");
        std::hint::black_box(simple_rs_sha2_512::sha2_512(&input));
    }
    let secs = start.elapsed().as_secs_f64();
    println!("{:.2} kh/s", amount as f64 / secs / 1000.0);
}
