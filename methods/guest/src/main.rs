#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
// #![no_std]  // std support is experimental

use std::io::BufReader;
use std::sync::Arc;
use kimchi::bench::BenchmarkCtx;
use kimchi::groupmap::{BWParameters, GroupMap};
use kimchi::mina_curves::pasta::{Fp, Vesta, VestaParameters};
use kimchi::mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use kimchi::mina_poseidon::sponge::{DefaultFqSponge, DefaultFrSponge};
use kimchi::o1_utils::FieldHelpers;
use kimchi::poly_commitment::evaluation_proof::OpeningProof;
use kimchi::poly_commitment::srs::SRS;
use kimchi::precomputed_srs::get_srs;
use kimchi::proof::ProverProof;
use kimchi::verifier::{batch_verify, Context, verify};
use kimchi::verifier_index::VerifierIndex;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

risc0_zkvm::guest::entry!(main);

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

#[derive(Serialize, Deserialize)]
struct ContextWithProof {
    index: VerifierIndex<Vesta, OpeningProof<Vesta>>,
    // group: BWParameters<VestaParameters>,
    proof: ProverProof<Vesta, OpeningProof<Vesta>>,
    public_input: Vec<Vec<u8>>,
}

// static SRS_BYTES: [u8; include_bytes!("vesta.srs").len()] = *include_bytes!("vesta.srs");

pub fn main() {
    // read the input
    let mut input: ContextWithProof = env::read();
    let public_input: Vec<Fp> = input.public_input.iter().map(|x| Fp::from_bytes(x).unwrap()).collect();
    let group_map = BWParameters::<VestaParameters>::setup();

    // let buf_reader = BufReader::new(&SRS_BYTES[..]);
    // let srs = SRS::<Vesta>::deserialize(buf_reader).unwrap();
    // input.index.srs = Arc::new(srs);
    let srs = SRS::<Vesta>::create(17);

    // batch_verify(&input.index, &group_map, &vec![(input.proof, input.public_input)]);
    batch_verify::<Vesta, BaseSponge, ScalarSponge, OpeningProof<Vesta>>(&group_map, &vec![
        Context{
            verifier_index: &input.index,
            proof: &input.proof,
            public_input: &public_input
        }
    ]).unwrap();

    // TODO: do something with the input

    // write public output to the journal
    // let val: u64 = 10;
    env::commit(&input);
}
