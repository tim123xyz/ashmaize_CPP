use ashmaize::{hash, Rom, RomGenerationType};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::time::Instant;

const ITERATION: u32 = 100000;
const LOOP_COUNT: u32 = 8;
const INSTRUCTION_COUNT: u32 = 256;
const ROM_SIZE: usize = 1_073_741_824;
const ROM_PRE_SIZE: usize = 16_777_216;
const ROM_MIXING_NUMBERS: usize = 4;
const ROM_KEY: &[u8] = b"RomKey_strRomKey_strRomKey_strRomKey_strRomKey_str";
const SALT: &[u8] = b"Salt_strSalt_strSalt_strSalt_strSalt_str";

fn print_vector(label: &str, data: &[u8]) -> () {
    print!("{label}=");
    for (i, byte) in data.iter().enumerate() {
        if i > 0 {
            print!(" ");
        }
        print!("{:02x}", byte);
    }
    println!();
}

fn main() {
    let rom = Rom::new(
        ROM_KEY,
        RomGenerationType::TwoStep {
            pre_size: ROM_PRE_SIZE,
            mixing_numbers: ROM_MIXING_NUMBERS,
        },
        ROM_SIZE,
    );

    let digest = hash(SALT, &rom, LOOP_COUNT, INSTRUCTION_COUNT);

    print_vector("hash", &digest);

    let start = Instant::now();
    (0..ITERATION).into_par_iter().for_each(|_| {hash(&SALT, &rom, LOOP_COUNT, INSTRUCTION_COUNT);});
    let stop = Instant::now();

    let total_seconds = stop.duration_since(start).as_secs_f64();
    let hashes_per_sec = ITERATION as f64 / total_seconds;

    println!("Total time: {:.3} s", total_seconds);
    println!("Throughput: {:.2} hash/s", hashes_per_sec);
}
