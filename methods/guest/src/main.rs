#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
// #![no_std]  // std support is experimental

use kimchi::bench::BenchmarkCtx;
use kimchi::groupmap::{BWParameters, GroupMap};
use kimchi::mina_curves::pasta::{Fp, Vesta, VestaParameters};
use kimchi::o1_utils::FieldHelpers;
use kimchi::poly_commitment::evaluation_proof::OpeningProof;
use kimchi::precomputed_srs::get_srs;
use kimchi::proof::ProverProof;
use kimchi::verifier::{batch_verify, Context, verify};
use kimchi::verifier_index::VerifierIndex;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

risc0_zkvm::guest::entry!(main);

#[derive(Serialize, Deserialize)]
struct ContextWithProof {
    index: VerifierIndex<Vesta, OpeningProof<Vesta>>,
    // group: BWParameters<VestaParameters>,
    proof: ProverProof<Vesta, OpeningProof<Vesta>>,
    public_input: Vec<Vec<u8>>,
}

// static SRS: [u8; include_bytes!("../srs/vesta.srs").len()] = *include_bytes!("../srs/vesta.srs");

pub fn main() {
    // read the input
    let input: ContextWithProof = env::read();
    let public_input = input.public_input.into_iter().map(|x| Fp::from_bytes(&x)).collect();
    let group_map = BWParameters::<VestaParameters>::setup();

    // batch_verify(&input.index, &group_map, &vec![(input.proof, input.public_input)]);
    batch_verify(&group_map, &vec![
        Context{
            verifier_index: &input.index,
            proof: &input.proof,
            public_input: &public_input
        }
    ]).unwrap();

    // TODO: do something with the input

    // write public output to the journal
    let val: u64 = 10;
    env::commit(&val);
}
