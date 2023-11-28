use std::fs::File;
// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use methods::{
    KIMCHI0_ELF, KIMCHI0_ID
};
use risc0_zkvm::{default_prover, ExecutorEnv, MemoryImage, Program, ProverOpts, Receipt, VerifierContext};
use kimchi::bench::BenchmarkCtx;
use kimchi::groupmap::BWParameters;
use kimchi::mina_curves::pasta::{Fp, Vesta, VestaParameters};
use kimchi::o1_utils::FieldHelpers;
use kimchi::poly_commitment::evaluation_proof::OpeningProof;
use kimchi::proof::ProverProof;
use kimchi::prover_index::ProverIndex;
use kimchi::verifier_index::VerifierIndex;
use serde::{Deserialize, Deserializer, Serialize};
use serde::de::Error;

use risc0_zkvm::{
    serde::to_vec, GUEST_MAX_MEM, PAGE_SIZE,
};

use std::io::{BufReader, Read, Write};
use std::mem;
use std::time::Duration;
use bonsai_sdk::alpha::Client;
use rmp_serde;

use anyhow::{Result};

#[derive(Serialize, Deserialize)]
struct ContextWithProof {
    index: VerifierIndex<Vesta, OpeningProof<Vesta>>,
    // lagrange_basis: Vec<PolyComm<Vesta>>,
    // group_map: BWParameters<VestaParameters>,
    proof: ProverProof<Vesta, OpeningProof<Vesta>>,
    public_input: Vec<Vec<u8>>,
}
fn main() {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    env_logger::init();

    // An executor environment describes the configurations for the zkVM
    // including program inputs.
    // An default ExecutorEnv can be created like so:
    // `let env = ExecutorEnv::builder().build().unwrap();`
    // However, this `env` does not have any inputs.
    //
    // To add add guest input to the executor environment, use
    // ExecutorEnvBuilder::write().
    // To access this method, you'll need to use ExecutorEnv::builder(), which
    // creates an ExecutorEnvBuilder. When you're done adding input, call
    // ExecutorEnvBuilder::build().

    let mut ctx = BenchmarkCtx::new(12);

    // let srs = SRS::<Vesta>::deserialize(&mut rmp_serde::Deserializer::new(BufReader::new(&SRS_BYTES[..]))).unwrap();
    // ctx.verifier_index.srs = Arc::new(srs);

    let (proof, public_input) = ctx.create_proof();

    let ctx_with_proof = ContextWithProof {
        index: ctx.verifier_index,
        // lagrange_basis: ctx.verifier_index.srs().get_lagrange_basis(ctx.verifier_index.domain.size()).unwrap().clone(),
        proof,
        public_input: public_input.into_iter().map(|x| x.to_bytes()).collect(),
    };

    println!("{}", mem::size_of_val(&ctx_with_proof));

    println!("proving");

    // if env variable RISC0_PROVER is set to bonsai, prove with bonsai, else prove locally
    if std::env::var("RISC0_PROVER").unwrap_or(String::new()) == "bonsai" {
        run_bonsai(ctx_with_proof).unwrap();
    } else {
        let env = ExecutorEnv::builder().write(&ctx_with_proof).unwrap().build().unwrap();
        let prover = default_prover();
        let receipt = prover.prove_elf(env, KIMCHI0_ELF).unwrap();
        let _output: ContextWithProof = receipt.journal.decode().unwrap();
    }

    // Optional: Verify receipt to confirm that recipients will also be able to
    // verify your receipt
    // receipt.verify(KIMCHI0_ID).unwrap();
}

fn run_bonsai(input_data: ContextWithProof) -> Result<()> {
    let client = Client::from_env(risc0_zkvm::VERSION)?;

    // create the memoryImg, upload it and return the imageId
    let img_id = {
        let program = Program::load_elf(KIMCHI0_ELF, GUEST_MAX_MEM as u32)?;
        let image = MemoryImage::new(&program, PAGE_SIZE as u32)?;
        let image_id = hex::encode(image.compute_id());
        let image = bincode::serialize(&image).expect("Failed to serialize memory img");
        client.upload_img(&image_id, image)?;
        image_id
    };

    // Prepare input data and upload it.
    let input_data = to_vec(&input_data).unwrap();
    let input_data = bytemuck::cast_slice(&input_data).to_vec();
    let input_id = client.upload_input(input_data)?;

    // Start a session running the prover
    let session = client.create_session(img_id, input_id)?;
    loop {
        let res = session.status(&client)?;
        if res.status == "RUNNING" {
            std::thread::sleep(Duration::from_secs(15));
            continue;
        }
        if res.status == "SUCCEEDED" {
            // Download the receipt, containing the output
            let receipt_url = res
                .receipt_url
                .expect("API error, missing receipt on completed session");

            let receipt_buf = client.download(&receipt_url)?;
            let receipt: Receipt = bincode::deserialize(&receipt_buf)?;
            receipt
                .verify(KIMCHI0_ID)
                .expect("Receipt verification failed");
        } else {
            if res.error_msg.is_some() {
                panic!("Workflow exited: {}", res.error_msg.unwrap());
            } else {
                panic!("Workflow exited: {}", res.status);
            }
        }

        break;
    }

    Ok(())
}
