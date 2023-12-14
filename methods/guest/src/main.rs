#![no_main]
#![feature(once_cell)]
// If you want to try std support, also update the guest Cargo.toml file
// #![no_std]  // std support is experimental

use std::cell::OnceCell;
use std::io::BufReader;
use std::sync::Arc;
use ark_ff::{Field, One, PrimeField};
use kimchi::circuits::argument::ArgumentType;
use kimchi::circuits::berkeley_columns::Column;
use kimchi::circuits::constraints::ConstraintSystem;
use kimchi::circuits::expr::{Constants, Linearization, PolishToken};
use kimchi::circuits::gate::GateType;
use kimchi::circuits::lookup::lookups::LookupPattern;
use kimchi::circuits::lookup::tables::combine_table;
use kimchi::circuits::polynomials::permutation;
use kimchi::circuits::wires::PERMUTS;
use kimchi::curve::KimchiCurve;
use kimchi::error::VerifyError;
use kimchi::groupmap::{BWParameters, GroupMap};
use kimchi::mina_curves::pasta::{Fp, Vesta, VestaParameters};
use kimchi::mina_poseidon::constants::PlonkSpongeConstantsKimchi;
use kimchi::mina_poseidon::FqSponge;
use kimchi::mina_poseidon::sponge::{DefaultFqSponge, DefaultFrSponge};
use kimchi::o1_utils::FieldHelpers;
use kimchi::oracles::OraclesResult;
use kimchi::plonk_sponge::FrSponge;
use kimchi::poly_commitment::evaluation_proof::OpeningProof;
use kimchi::poly_commitment::{OpenProof, PolyComm, SRS};
use kimchi::poly_commitment::commitment::{BatchEvaluationProof, Evaluation};
use kimchi::proof::{PointEvaluations, ProofEvaluations, ProverProof};
use kimchi::verifier::Context;
use kimchi::verifier_index::{LookupVerifierIndex, VerifierIndex};
use kimchi::circuits::wires::COLUMNS;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use rand::thread_rng;
use ark_ec::AffineCurve;
use ark_poly::domain::EvaluationDomain;
use ark_poly::Polynomial;
use ark_poly::{univariate::DensePolynomial,  Radix2EvaluationDomain as D};
use kimchi::alphas::Alphas;
use serde_with::serde_as;

risc0_zkvm::guest::entry!(main);

pub const VESTA_FIELD_PARAMS: usize = 131072;

pub type Result<T> = std::result::Result<T, VerifyError>;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifierIndex<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    /// evaluation domain
    #[serde_as(as = "kimchi::o1_utils::serialization::SerdeAs")]
    pub domain: D<G::ScalarField>,
    /// maximal size of polynomial section
    pub max_poly_size: usize,
    /// the number of randomized rows to achieve zero knowledge
    pub zk_rows: u64,
    /// polynomial commitment keys
    #[serde(skip)]
    #[serde(bound(deserialize = "SrsSized<G, VESTA_FIELD_PARAMS>: Default"))]
    pub srs: Arc<SrsSized<G, VESTA_FIELD_PARAMS>>,
    /// number of public inputs
    pub public: usize,
    /// number of previous evaluation challenges, for recursive proving
    pub prev_challenges: usize,

    // index polynomial commitments
    /// permutation commitment array
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub sigma_comm: [PolyComm<G>; PERMUTS],
    /// coefficient commitment array
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub coefficients_comm: [PolyComm<G>; COLUMNS],
    /// coefficient commitment array
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub generic_comm: PolyComm<G>,

    // poseidon polynomial commitments
    /// poseidon constraint selector polynomial commitment
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub psm_comm: PolyComm<G>,

    // ECC arithmetic polynomial commitments
    /// EC addition selector polynomial commitment
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub complete_add_comm: PolyComm<G>,
    /// EC variable base scalar multiplication selector polynomial commitment
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub mul_comm: PolyComm<G>,
    /// endoscalar multiplication selector polynomial commitment
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub emul_comm: PolyComm<G>,
    /// endoscalar multiplication scalar computation selector polynomial commitment
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub endomul_scalar_comm: PolyComm<G>,

    /// RangeCheck0 polynomial commitments
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub range_check0_comm: Option<PolyComm<G>>,

    /// RangeCheck1 polynomial commitments
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub range_check1_comm: Option<PolyComm<G>>,

    /// Foreign field addition gates polynomial commitments
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub foreign_field_add_comm: Option<PolyComm<G>>,

    /// Foreign field multiplication gates polynomial commitments
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub foreign_field_mul_comm: Option<PolyComm<G>>,

    /// Xor commitments
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub xor_comm: Option<PolyComm<G>>,

    /// Rot commitments
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub rot_comm: Option<PolyComm<G>>,

    /// wire coordinate shifts
    #[serde_as(as = "[kimchi::o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub shift: [G::ScalarField; PERMUTS],
    /// zero-knowledge polynomial
    #[serde(skip)]
    pub permutation_vanishing_polynomial_m: OnceCell<DensePolynomial<G::ScalarField>>,
    // TODO(mimoo): isn't this redundant with domain.d1.group_gen ?
    /// domain offset for zero-knowledge
    #[serde(skip)]
    pub w: OnceCell<G::ScalarField>,
    /// endoscalar coefficient
    #[serde(skip)]
    pub endo: G::ScalarField,

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub lookup_index: Option<LookupVerifierIndex<G>>,

    #[serde(skip)]
    pub linearization: Linearization<Vec<PolishToken<G::ScalarField, Column>>, Column>,
    /// The mapping between powers of alpha and constraints
    #[serde(skip)]
    pub powers_of_alpha: Alphas<G::ScalarField>,
}

#[derive(Serialize, Deserialize)]
struct ContextWithProof {
    index: VerifierIndex<Vesta, OpeningProof<Vesta>>,
    // lagrange_basis: Vec<PolyComm<Vesta>>,
    // group: BWParameters<VestaParameters>,
    proof: ProverProof<Vesta, OpeningProof<Vesta>>,
    public_input: Vec<Vec<u8>>,
}

#[repr(C)]
pub struct SrsSized<G, const N: usize> {
    pub g: [G; N],
    pub h: G
}

static SRS_BYTES: [u8; include_bytes!("../../../srs/vesta.bin").len()] = *include_bytes!("../../../srs/vesta.bin");

pub fn main() {
    // read the input
    let mut input: ContextWithProof = env::read();
    let public_input: Vec<Fp> = input.public_input.iter().map(|x| Fp::from_bytes(x).unwrap()).collect();
    let group_map = BWParameters::<VestaParameters>::setup();

    let srs = unsafe {
        std::mem::transmute::<&u8, &SrsSized<Vesta, VESTA_FIELD_PARAMS>>(&SRS_BYTES[0])
    };

    // input.index.srs = Arc::new(srs.clone());

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
}

pub fn batch_verify<G, EFqSponge, EFrSponge, OpeningProof: OpenProof<G>>(
    group_map: &G::Map,
    proofs: &[Context<G, OpeningProof>],
) -> Result<()>
    where
        G: KimchiCurve,
        G::BaseField: PrimeField,
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
{
    //~ #### Batch verification of proofs
    //~
    //~ Below, we define the steps to verify a number of proofs
    //~ (each associated to a [verifier index](#verifier-index)).
    //~ You can, of course, use it to verify a single proof.
    //~

    //~ 1. If there's no proof to verify, the proof validates trivially.
    if proofs.is_empty() {
        return Ok(());
    }

    //~ 1. Ensure that all the proof's verifier index have a URS of the same length. (TODO: do they have to be the same URS though? should we check for that?)
    // TODO: Account for the different SRS lengths
    let srs = proofs[0].verifier_index.srs();
    for &Context { verifier_index, .. } in proofs {
        if verifier_index.srs().max_poly_size() != srs.max_poly_size() {
            return Err(VerifyError::DifferentSRS);
        }
    }

    //~ 1. Validate each proof separately following the [partial verification](#partial-verification) steps.
    let mut batch = vec![];
    for &Context {
        verifier_index,
        proof,
        public_input,
    } in proofs
    {
        batch.push(to_batch::<G, EFqSponge, EFrSponge, OpeningProof>(
            verifier_index,
            proof,
            public_input,
        )?);
    }

    //~ 1. Use the [`PolyCom.verify`](#polynomial-commitments) to verify the partially evaluated proofs.
    if OpeningProof::verify(srs, group_map, &mut batch, &mut thread_rng()) {
        Ok(())
    } else {
        Err(VerifyError::OpenProof)
    }
}

fn check_proof_evals_len<G, OpeningProof>(
    proof: &ProverProof<G, OpeningProof>,
    expected_size: usize,
) -> Result<()>
    where
        G: KimchiCurve,
        G::BaseField: PrimeField,
{
    let ProofEvaluations {
        public,
        w,
        z,
        s,
        coefficients,
        generic_selector,
        poseidon_selector,
        complete_add_selector,
        mul_selector,
        emul_selector,
        endomul_scalar_selector,
        range_check0_selector,
        range_check1_selector,
        foreign_field_add_selector,
        foreign_field_mul_selector,
        xor_selector,
        rot_selector,
        lookup_aggregation,
        lookup_table,
        lookup_sorted,
        runtime_lookup_table,
        runtime_lookup_table_selector,
        xor_lookup_selector,
        lookup_gate_lookup_selector,
        range_check_lookup_selector,
        foreign_field_mul_lookup_selector,
    } = &proof.evals;

    let check_eval_len = |eval: &PointEvaluations<Vec<_>>, str: &'static str| -> Result<()> {
        if eval.zeta.len() != expected_size {
            Err(VerifyError::IncorrectEvaluationsLength(
                expected_size,
                eval.zeta.len(),
                str,
            ))
        } else if eval.zeta_omega.len() != expected_size {
            Err(VerifyError::IncorrectEvaluationsLength(
                expected_size,
                eval.zeta_omega.len(),
                str,
            ))
        } else {
            Ok(())
        }
    };

    if let Some(public) = public {
        check_eval_len(public, "public input")?;
    }

    for w_i in w {
        check_eval_len(w_i, "witness")?;
    }
    check_eval_len(z, "permutation accumulator")?;
    for s_i in s {
        check_eval_len(s_i, "permutation shifts")?;
    }
    for coeff in coefficients {
        check_eval_len(coeff, "coefficients")?;
    }

    // Lookup evaluations
    for sorted in lookup_sorted.iter().flatten() {
        check_eval_len(sorted, "lookup sorted")?
    }

    if let Some(lookup_aggregation) = lookup_aggregation {
        check_eval_len(lookup_aggregation, "lookup aggregation")?;
    }
    if let Some(lookup_table) = lookup_table {
        check_eval_len(lookup_table, "lookup table")?;
    }
    if let Some(runtime_lookup_table) = runtime_lookup_table {
        check_eval_len(runtime_lookup_table, "runtime lookup table")?;
    }

    check_eval_len(generic_selector, "generic selector")?;
    check_eval_len(poseidon_selector, "poseidon selector")?;
    check_eval_len(complete_add_selector, "complete add selector")?;
    check_eval_len(mul_selector, "mul selector")?;
    check_eval_len(emul_selector, "endomul selector")?;
    check_eval_len(endomul_scalar_selector, "endomul scalar selector")?;

    // Optional gates

    if let Some(range_check0_selector) = range_check0_selector {
        check_eval_len(range_check0_selector, "range check 0 selector")?
    }
    if let Some(range_check1_selector) = range_check1_selector {
        check_eval_len(range_check1_selector, "range check 1 selector")?
    }
    if let Some(foreign_field_add_selector) = foreign_field_add_selector {
        check_eval_len(foreign_field_add_selector, "foreign field add selector")?
    }
    if let Some(foreign_field_mul_selector) = foreign_field_mul_selector {
        check_eval_len(foreign_field_mul_selector, "foreign field mul selector")?
    }
    if let Some(xor_selector) = xor_selector {
        check_eval_len(xor_selector, "xor selector")?
    }
    if let Some(rot_selector) = rot_selector {
        check_eval_len(rot_selector, "rot selector")?
    }

    // Lookup selectors

    if let Some(runtime_lookup_table_selector) = runtime_lookup_table_selector {
        check_eval_len(
            runtime_lookup_table_selector,
            "runtime lookup table selector",
        )?
    }
    if let Some(xor_lookup_selector) = xor_lookup_selector {
        check_eval_len(xor_lookup_selector, "xor lookup selector")?
    }
    if let Some(lookup_gate_lookup_selector) = lookup_gate_lookup_selector {
        check_eval_len(lookup_gate_lookup_selector, "lookup gate lookup selector")?
    }
    if let Some(range_check_lookup_selector) = range_check_lookup_selector {
        check_eval_len(range_check_lookup_selector, "range check lookup selector")?
    }
    if let Some(foreign_field_mul_lookup_selector) = foreign_field_mul_lookup_selector {
        check_eval_len(
            foreign_field_mul_lookup_selector,
            "foreign field mul lookup selector",
        )?
    }

    Ok(())
}

fn to_batch<'a, G, EFqSponge, EFrSponge, OpeningProof: OpenProof<G>>(
    verifier_index: &VerifierIndex<G, OpeningProof>,
    proof: &'a ProverProof<G, OpeningProof>,
    public_input: &'a [<G as AffineCurve>::ScalarField],
) -> Result<BatchEvaluationProof<'a, G, EFqSponge, OpeningProof>>
    where
        G: KimchiCurve,
        G::BaseField: PrimeField,
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
{
    //~
    //~ #### Partial verification
    //~
    //~ For every proof we want to verify, we defer the proof opening to the very end.
    //~ This allows us to potentially batch verify a number of partially verified proofs.
    //~ Essentially, this steps verifies that $f(\zeta) = t(\zeta) * Z_H(\zeta)$.
    //~

    let zk_rows = verifier_index.zk_rows;

    if proof.prev_challenges.len() != verifier_index.prev_challenges {
        return Err(VerifyError::IncorrectPrevChallengesLength(
            verifier_index.prev_challenges,
            proof.prev_challenges.len(),
        ));
    }
    if public_input.len() != verifier_index.public {
        return Err(VerifyError::IncorrectPubicInputLength(
            verifier_index.public,
        ));
    }

    //~ 1. Check the length of evaluations inside the proof.
    let chunk_size = {
        let d1_size = verifier_index.domain.size();
        if d1_size < verifier_index.max_poly_size {
            1
        } else {
            d1_size / verifier_index.max_poly_size
        }
    };
    check_proof_evals_len(proof, chunk_size)?;

    //~ 1. Commit to the negated public input polynomial.
    let public_comm = {
        if public_input.len() != verifier_index.public {
            return Err(VerifyError::IncorrectPubicInputLength(
                verifier_index.public,
            ));
        }
        let lgr_comm = verifier_index
            .srs()
            .get_lagrange_basis(verifier_index.domain.size())
            .expect("pre-computed committed lagrange bases not found");
        let com: Vec<_> = lgr_comm.iter().take(verifier_index.public).collect();
        if public_input.is_empty() {
            PolyComm::new(
                vec![verifier_index.srs().blinding_commitment(); chunk_size],
                None,
            )
        } else {
            let elm: Vec<_> = public_input.iter().map(|s| -*s).collect();
            let public_comm = PolyComm::<G>::multi_scalar_mul(&com, &elm);
            verifier_index
                .srs()
                .mask_custom(
                    public_comm.clone(),
                    &public_comm.map(|_| G::ScalarField::one()),
                )
                .unwrap()
                .commitment
        }
    };

    //~ 1. Run the [Fiat-Shamir argument](#fiat-shamir-argument).
    let OraclesResult {
        fq_sponge,
        oracles,
        all_alphas,
        public_evals,
        powers_of_eval_points_for_chunks,
        polys,
        zeta1: zeta_to_domain_size,
        ft_eval0,
        combined_inner_product,
        ..
    } = proof.oracles::<EFqSponge, EFrSponge>(verifier_index, &public_comm, Some(public_input))?;

    //~ 1. Combine the chunked polynomials' evaluations
    //~    (TODO: most likely only the quotient polynomial is chunked)
    //~    with the right powers of $\zeta^n$ and $(\zeta * \omega)^n$.
    let evals = proof.evals.combine(&powers_of_eval_points_for_chunks);

    let context = Context {
        verifier_index,
        proof,
        public_input,
    };

    //~ 1. Compute the commitment to the linearized polynomial $f$.
    //~    To do this, add the constraints of all of the gates, of the permutation,
    //~    and optionally of the lookup.
    //~    (See the separate sections in the [constraints](#constraints) section.)
    //~    Any polynomial should be replaced by its associated commitment,
    //~    contained in the verifier index or in the proof,
    //~    unless a polynomial has its evaluation provided by the proof
    //~    in which case the evaluation should be used in place of the commitment.
    let f_comm = {
        // the permutation is written manually (not using the expr framework)
        let permutation_vanishing_polynomial = verifier_index
            .permutation_vanishing_polynomial_m()
            .evaluate(&oracles.zeta);

        let alphas = all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);

        let mut commitments = vec![&verifier_index.sigma_comm[PERMUTS - 1]];
        let mut scalars = vec![ConstraintSystem::<G::ScalarField>::perm_scalars(
            &evals,
            oracles.beta,
            oracles.gamma,
            alphas,
            permutation_vanishing_polynomial,
        )];

        // other gates are implemented using the expression framework
        {
            // TODO: Reuse constants from oracles function
            let constants = Constants {
                alpha: oracles.alpha,
                beta: oracles.beta,
                gamma: oracles.gamma,
                joint_combiner: oracles.joint_combiner.as_ref().map(|j| j.1),
                endo_coefficient: verifier_index.endo,
                mds: &G::sponge_params().mds,
                zk_rows,
            };

            for (col, tokens) in &verifier_index.linearization.index_terms {
                let scalar = PolishToken::evaluate(
                    tokens,
                    verifier_index.domain,
                    oracles.zeta,
                    &evals,
                    &constants,
                )
                    .expect("should evaluate");

                let col = *col;
                scalars.push(scalar);
                commitments.push(
                    context
                        .get_column(col)
                        .ok_or(VerifyError::MissingCommitment(col))?,
                );
            }
        }

        // MSM
        PolyComm::multi_scalar_mul(&commitments, &scalars)
    };

    //~ 1. Compute the (chuncked) commitment of $ft$
    //~    (see [Maller's optimization](../crypto/plonk/maller_15.html)).
    let ft_comm = {
        let zeta_to_srs_len = oracles.zeta.pow([verifier_index.max_poly_size as u64]);
        let chunked_f_comm = f_comm.chunk_commitment(zeta_to_srs_len);
        let chunked_t_comm = &proof.commitments.t_comm.chunk_commitment(zeta_to_srs_len);
        &chunked_f_comm - &chunked_t_comm.scale(zeta_to_domain_size - G::ScalarField::one())
    };

    //~ 1. List the polynomial commitments, and their associated evaluations,
    //~    that are associated to the aggregated evaluation proof in the proof:
    let mut evaluations = vec![];

    //~~ * recursion
    evaluations.extend(polys.into_iter().map(|(c, e)| Evaluation {
        commitment: c,
        evaluations: e,
        degree_bound: None,
    }));

    //~~ * public input commitment
    evaluations.push(Evaluation {
        commitment: public_comm,
        evaluations: public_evals.to_vec(),
        degree_bound: None,
    });

    //~~ * ft commitment (chunks of it)
    evaluations.push(Evaluation {
        commitment: ft_comm,
        evaluations: vec![vec![ft_eval0], vec![proof.ft_eval1]],
        degree_bound: None,
    });

    for col in [
        //~~ * permutation commitment
        Column::Z,
        //~~ * index commitments that use the coefficients
        Column::Index(GateType::Generic),
        Column::Index(GateType::Poseidon),
        Column::Index(GateType::CompleteAdd),
        Column::Index(GateType::VarBaseMul),
        Column::Index(GateType::EndoMul),
        Column::Index(GateType::EndoMulScalar),
    ]
        .into_iter()
        //~~ * witness commitments
        .chain((0..COLUMNS).map(Column::Witness))
        //~~ * coefficient commitments
        .chain((0..COLUMNS).map(Column::Coefficient))
        //~~ * sigma commitments
        .chain((0..PERMUTS - 1).map(Column::Permutation))
        //~~ * optional gate commitments
        .chain(
            verifier_index
                .range_check0_comm
                .as_ref()
                .map(|_| Column::Index(GateType::RangeCheck0)),
        )
        .chain(
            verifier_index
                .range_check1_comm
                .as_ref()
                .map(|_| Column::Index(GateType::RangeCheck1)),
        )
        .chain(
            verifier_index
                .foreign_field_add_comm
                .as_ref()
                .map(|_| Column::Index(GateType::ForeignFieldAdd)),
        )
        .chain(
            verifier_index
                .foreign_field_mul_comm
                .as_ref()
                .map(|_| Column::Index(GateType::ForeignFieldMul)),
        )
        .chain(
            verifier_index
                .xor_comm
                .as_ref()
                .map(|_| Column::Index(GateType::Xor16)),
        )
        .chain(
            verifier_index
                .rot_comm
                .as_ref()
                .map(|_| Column::Index(GateType::Rot64)),
        )
        //~~ * lookup commitments
        //~
        .chain(
            verifier_index
                .lookup_index
                .as_ref()
                .map(|li| {
                    // add evaluations of sorted polynomials
                    (0..li.lookup_info.max_per_row + 1)
                        .map(Column::LookupSorted)
                        // add evaluations of the aggreg polynomial
                        .chain([Column::LookupAggreg].into_iter())
                })
                .into_iter()
                .flatten(),
        ) {
        let evals = proof
            .evals
            .get_column(col)
            .ok_or(VerifyError::MissingEvaluation(col))?;
        evaluations.push(Evaluation {
            commitment: context
                .get_column(col)
                .ok_or(VerifyError::MissingCommitment(col))?
                .clone(),
            evaluations: vec![evals.zeta.clone(), evals.zeta_omega.clone()],
            degree_bound: None,
        });
    }

    if let Some(li) = &verifier_index.lookup_index {
        let lookup_comms = proof
            .commitments
            .lookup
            .as_ref()
            .ok_or(VerifyError::LookupCommitmentMissing)?;

        let lookup_table = proof
            .evals
            .lookup_table
            .as_ref()
            .ok_or(VerifyError::LookupEvalsMissing)?;
        let runtime_lookup_table = proof.evals.runtime_lookup_table.as_ref();

        // compute table commitment
        let table_comm = {
            let joint_combiner = oracles
                .joint_combiner
                .expect("joint_combiner should be present if lookups are used");
            let table_id_combiner = joint_combiner
                .1
                .pow([u64::from(li.lookup_info.max_joint_size)]);
            let lookup_table: Vec<_> = li.lookup_table.iter().collect();
            let runtime = lookup_comms.runtime.as_ref();

            combine_table(
                &lookup_table,
                joint_combiner.1,
                table_id_combiner,
                li.table_ids.as_ref(),
                runtime,
            )
        };

        // add evaluation of the table polynomial
        evaluations.push(Evaluation {
            commitment: table_comm,
            evaluations: vec![lookup_table.zeta.clone(), lookup_table.zeta_omega.clone()],
            degree_bound: None,
        });

        // add evaluation of the runtime table polynomial
        if li.runtime_tables_selector.is_some() {
            let runtime = lookup_comms
                .runtime
                .as_ref()
                .ok_or(VerifyError::IncorrectRuntimeProof)?;
            let runtime_eval = runtime_lookup_table
                .as_ref()
                .map(|x| x.map_ref(&|x| x.clone()))
                .ok_or(VerifyError::IncorrectRuntimeProof)?;

            evaluations.push(Evaluation {
                commitment: runtime.clone(),
                evaluations: vec![runtime_eval.zeta, runtime_eval.zeta_omega],
                degree_bound: None,
            });
        }
    }

    for col in verifier_index
        .lookup_index
        .as_ref()
        .map(|li| {
            (li.runtime_tables_selector
                .as_ref()
                .map(|_| Column::LookupRuntimeSelector))
                .into_iter()
                .chain(
                    li.lookup_selectors
                        .xor
                        .as_ref()
                        .map(|_| Column::LookupKindIndex(LookupPattern::Xor)),
                )
                .chain(
                    li.lookup_selectors
                        .lookup
                        .as_ref()
                        .map(|_| Column::LookupKindIndex(LookupPattern::Lookup)),
                )
                .chain(
                    li.lookup_selectors
                        .range_check
                        .as_ref()
                        .map(|_| Column::LookupKindIndex(LookupPattern::RangeCheck)),
                )
                .chain(
                    li.lookup_selectors
                        .ffmul
                        .as_ref()
                        .map(|_| Column::LookupKindIndex(LookupPattern::ForeignFieldMul)),
                )
        })
        .into_iter()
        .flatten()
    {
        let evals = proof
            .evals
            .get_column(col)
            .ok_or(VerifyError::MissingEvaluation(col))?;
        evaluations.push(Evaluation {
            commitment: context
                .get_column(col)
                .ok_or(VerifyError::MissingCommitment(col))?
                .clone(),
            evaluations: vec![evals.zeta.clone(), evals.zeta_omega.clone()],
            degree_bound: None,
        });
    }

    // prepare for the opening proof verification
    let evaluation_points = vec![oracles.zeta, oracles.zeta * verifier_index.domain.group_gen];
    Ok(BatchEvaluationProof {
        sponge: fq_sponge,
        evaluations,
        evaluation_points,
        polyscale: oracles.v,
        evalscale: oracles.u,
        opening: &proof.proof,
        combined_inner_product,
    })
}
