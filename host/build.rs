use std::fs::File;

struct SrsWrapper(pub SRS<Vesta>);

fn main() {
    // load vesta srs from file
    let srs_path = std::env::var("VESTA_SRS_PATH").expect("VESTA_SRS_PATH env var not set");
    let srs_file = File::open(srs_path).expect("failed to open vesta srs file");
    let srs = rmp_serde::from_read(srs_file).expect("failed to deserialize vesta srs");

}