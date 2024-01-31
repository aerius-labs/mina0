# Mina0

Mina0 is a kimchi and pickles verifier developed using the Bonsai starter template, focusing on implementing zk-SNARKs with Risc0 for Ethereum smart contracts. This project utilizes the power of Bonsai as a coprocessor to the Ethereum application, enabling off-chain computations to be proven on-chain with RISC Zero's zkVM technology.

## Overview

Mina0 leverages the Bonsai ecosystem to offload the verification of kimchi and pickles, a task that is computationally intensive and difficult to implement directly on Ethereum. This approach enhances efficiency and security, offering a scalable solution for verifiable computations.

![Bonsai Relay Diagram](images/BonsaiRelay.png)

The process involves delegating the smart contract's logic to Bonsai, where computations are executed off-chain and proven using zk-SNARKs. The results are then verified on-chain, ensuring integrity and trustlessness in the application.

## Running Mina0

### Locally

To run Mina0 locally:

```bash
cargo run --bin host --release
```

### With Bonsai

To run Mina with bonsai:

```bash
RISC0_PROVER=bonsai cargo run --bin host --release
```

### Dependencies

Before starting, ensure you have Rust and Foundry installed. Then, install the necessary tools

```
cargo install cargo-binstall
cargo binstall cargo-risczero
cargo risczero install
```

### Quick Start

Initialize your Bonsai project with:

```
forge init -t risc0/bonsai-foundry-template ./my-project
```

This setup includes a zkVM program for the verification logic and a Solidity contract to receive and process the verification results.

### Testing

Ensure your project is correctly set up by:

* Compiling the zkVM program with `cargo build`.
* Running zkVM program tests with `cargo test`.
* Testing the Solidity contracts with `forge test`

### Configuring Bonsai

To use the Bonsai proving service:

```
export BONSAI_API_KEY="YOUR_API_KEY"
export BONSAI_API_URL="BONSAI_URL"
``` 

Run tests with Bonsai integration by setting `RISC0_DEV_MODE=false`:

```
RISC0_DEV_MODE=false forge test
```

### Project Structure
```
## Project Structure

```text
.
├── Cargo.lock                      // Lock file to ensure reproducible builds
├── Cargo.toml                      // Cargo manifest file for Rust project configuration
├── README.md                       // Project's README file
├── host                            // Host application for running and testing the zkVM program
│   ├── Cargo.toml                  // Cargo manifest file for the host application
│   └── src
│       └── main.rs                 // Main source file for the host application
├── methods                         // Contains zkVM guest programs
│   ├── Cargo.toml                  // Cargo manifest file for zkVM guest programs
│   ├── build.rs                    // Build script to compile zkVM guest programs
│   └── guest                       // Guest programs source directory
│       ├── Cargo.toml              // Cargo manifest file for guest program
│       └── src
│           └── bin
│               └── kimchi.rs       // Source file for the kimchi verifier program
│               └── pickles.rs      // Source file for the pickles verifier program
└── tests                           // Directory for integration and unit tests
    ├── host.rs                     // Test file for host application
    └── integration.rs              // Integration tests for the entire application
```

This structure outlines the organization of the Mina0 project, including the main components like the host application, methods (zkVM guest programs), and tests. Each part is designed to facilitate the development, testing, and deployment of the kimchi and pickles verifier within the Risc0 environment.

### Future
Further development requires working in the methods and contracts directories to expand the application's off-chain and on-chain components, respectively.

> [!Note]
> Mina0 and its use of Bonsai are examples of leveraging cutting-edge technology for verifiable off-chain computations. This project is a demonstration and should not be used in production as is.


#### This README is designed to provide a comprehensive guide to the Mina0 project, integrating specific details about running the project, setting up dependencies, testing, and further development steps.

