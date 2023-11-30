use kimchi::mina_curves::pasta::Vesta;
use kimchi::poly_commitment::srs::SRS;
use rmp_serde;
use std::mem;
use std::fs::File;
use std::path::Path;
use std::io::Write;
use num_traits::identities::Zero;
use std::thread;

include!("generated_const_params.rs");
// #[derive(Debug)]
#[repr(C)]
pub struct SrsSized<G, const N: usize> {
    pub g: [G; N],
    pub h: G
}

fn main () {
    // Define the desired stack size in bytes
    let stack_size = 32 * 1024 * 1024; // 16 MB

    // Create a new thread with the specified stack size
    let builder = thread::Builder::new().stack_size(stack_size);

    let handler = builder.spawn(|| {
        // load vesta srs from file
        let srs_path = "../../srs".to_string();

        // join "vesta.srs" and srs folder path
        let vesta_srs_path = Path::new(&srs_path).join("vesta.srs");

        let mut srs_sized = SrsSized{
            g: [Vesta::zero(); VESTA_FIELD_PARAMS],
            h: Vesta::zero(),
        };

        {
            // read vesta srs file
            let srs_file = File::open(vesta_srs_path).expect("failed to open vesta srs file");
            let srs = rmp_serde::from_read::<File, SRS<Vesta>>(srs_file).expect("failed to deserialize vesta srs");

            // println!("srs_sized: {}", srs_sized.h.to_string());

            srs_sized.g.copy_from_slice(&srs.g[..VESTA_FIELD_PARAMS]);
            srs_sized.h = srs.h;
        }

        // Open a file in write mode
        let mut file = File::create("../../srs/vesta.bin").unwrap();

        // Ensure the type is safe to treat as raw bytes
        assert_eq!(mem::size_of::<SrsSized<Vesta, VESTA_FIELD_PARAMS>>(), mem::size_of_val(&srs_sized));

        // Use unsafe to get the raw bytes of the object
        unsafe {
            let byte_ptr = &srs_sized as *const SrsSized<Vesta, VESTA_FIELD_PARAMS> as *const u8;
            let bytes = std::slice::from_raw_parts(byte_ptr, mem::size_of::<SrsSized<Vesta, VESTA_FIELD_PARAMS>>());
            file.write_all(bytes).unwrap();
        }
    }).unwrap();

    // Wait for the thread to finish executing
    handler.join().unwrap();
}