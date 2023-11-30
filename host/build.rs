use std::fs::File;
use std::io::Write;
use std::path::Path;
use kimchi::mina_curves::pasta::Vesta;
use kimchi::poly_commitment::srs::SRS;

fn main() {
    // load vesta srs from file
    let srs_path = "../srs".to_string();

    // join "vesta.srs" and srs folder path
    let vesta_srs_path = Path::new(&srs_path).join("vesta.srs");

    // read vesta srs file
    let srs_file = File::open(vesta_srs_path).expect("failed to open vesta srs file");
    let srs = rmp_serde::from_read::<File, SRS<Vesta>>(srs_file).expect("failed to deserialize vesta srs");

    let srs_group_elements_len = srs.g.len();

    // write vesta field parameters to a json file
    let vesta_field_params_path = Path::new("build_srs_raw").join("generated_const_params.rs");
    let mut vesta_field_params_file = File::create(vesta_field_params_path).expect("failed to create vesta field params file");

    // write vesta field as a const to a rust file
    let vesta_field_params = format!("pub const VESTA_FIELD_PARAMS: usize = {};", srs_group_elements_len);
    write!(vesta_field_params_file, "{}", vesta_field_params).expect("failed to write vesta field params to file");


    let second_build_folder = Path::new("build_srs_raw");
    assert!(std::env::set_current_dir(&second_build_folder).is_ok());

    // compile and run main.rs in build_srs_raw
    // let output = std::process::Command::new("cargo")
    //     .args(&["run", "--manifest-path", "./Cargo.toml"])
    //     .output()
    //     .expect("failed to execute second build");
    //
    // println!("Status: {}", output.status);
    // println!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
    // println!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
}