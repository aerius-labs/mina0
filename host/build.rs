use std::fs::File;
use std::{mem, slice};
use std::io::Write;
use std::path::Path;
use kimchi::mina_curves::pasta::Vesta;
use kimchi::poly_commitment::srs::SRS;

#[repr(C, packed)]
struct SRSWrapper(SRS<Vesta>);

fn main() {
    // load vesta srs from file
    let srs_path = std::env::var("SRS_PATH").expect("SRS_PATH env var not set");

    // join "vesta.srs" and srs folder path
    let vesta_srs_path = Path::new(&srs_path).join("vesta.srs");
    let out_path = Path::new(&srs_path).join("vesta_raw");

    // Check if the flag file exists
    if out_path.exists() {
        // If the file exists, return early
        println!("Build script already executed, skipping...");
        return;
    }

    let srs_file = File::open(vesta_srs_path).expect("failed to open vesta srs file");
    let srs = SRSWrapper((rmp_serde::from_read::<File, SRS<Vesta>>(srs_file).expect("failed to deserialize vesta srs")).clone());

    // write raw memory to a file
    let obj_ptr: *const SRSWrapper = &srs;
    let obj_size = mem::size_of::<SRSWrapper>();
    let obj_slice = unsafe { slice::from_raw_parts(obj_ptr as *const u8, obj_size) };

    // write to file
    let mut out_file = File::create(out_path).expect("Unable to create output file");
    out_file.write_all(obj_slice).expect("Failed to write to file");

}