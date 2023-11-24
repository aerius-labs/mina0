use serde::{Deserialize, Serialize};
use rmp_serde;
use lazy_static::lazy_static;
use kimchi::poly_commitment::srs::SRS;

static SRS_BYTES: [u8; include_bytes!("vesta.srs").len()] = *include_bytes!("vesta.srs");

lazy_static! {
    static ref LOADED_SRS: SRS<Vesta> = SRS::<Vesta>::deserialize(&mut rmp_serde::Deserializer::new(BufReader::new(&SRS_BYTES[..]))).unwrap();
}

fn main() {
    uneval::to_out_dir(LOADED_SRS.clone(), "vesta.rs");
}