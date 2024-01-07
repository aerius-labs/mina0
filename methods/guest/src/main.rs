#![no_main]
#![feature(once_cell)]

use std::cell::OnceCell;
use std::sync::Arc;
use ark_ff::{FftField, Field, One, PrimeField, UniformRand, Zero as _Zero, Zero};
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
use kimchi::mina_poseidon::sponge::{DefaultFqSponge, DefaultFrSponge, ScalarChallenge};
use kimchi::o1_utils::{ExtendedDensePolynomial, FieldHelpers, math};
use kimchi::oracles::OraclesResult;
use kimchi::plonk_sponge::FrSponge;
use kimchi::poly_commitment::evaluation_proof::{combine_polys, DensePolynomialOrEvaluations};
use kimchi::poly_commitment::{OpenProof, PolyComm, SRS};
use kimchi::poly_commitment::commitment::{absorb_commitment, b_poly, b_poly_coefficients, BatchEvaluationProof, BlindedCommitment, combine_commitments, combined_inner_product, CommitmentCurve, EndoCurve, Evaluation, inner_prod, pows, shift_scalar, squeeze_challenge, squeeze_prechallenge, to_group};
use kimchi::verifier_index::{LookupVerifierIndex};
use kimchi::circuits::wires::COLUMNS;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use rand::{CryptoRng, RngCore, thread_rng};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ec::msm::VariableBaseMSM;
use ark_poly::domain::EvaluationDomain;
use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain as D, Evaluations, Polynomial};
use kimchi::alphas::Alphas;
use kimchi::bench::BenchmarkCtx;
use kimchi::circuits::lookup::index::LookupSelectors;
use kimchi::circuits::polynomials::permutation::{vanishes_on_last_n_rows, zk_w};
use kimchi::circuits::scalars::RandomOracles;
use kimchi::poly_commitment::error::CommitmentError;
use kimchi::poly_commitment::srs::endos;
use serde_with::serde_as;
use kimchi::o1_utils;
use kimchi::proof::{PointEvaluations, ProofEvaluations, ProverCommitments, RecursionChallenge};
use kimchi::verifier_index::{ VerifierIndex as VerifierIndexKimchi };

risc0_zkvm::guest::entry!(main);

pub const VESTA_FIELD_PARAMS: usize = 131072;
pub const VESTA_FIELD_LAGRANGE_BASES_PARAMS: usize = 4096;

pub type Result<T> = std::result::Result<T, VerifyError>;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

static SRS_BYTES: [u8; include_bytes!("../../../srs/vesta.bin").len()] = *include_bytes!("../../../srs/vesta.bin");
static LAGRANGE_BASIS_BYTES: [u8; include_bytes!("../../../srs/lagrange_basis.bin").len()] = *include_bytes!("../../../srs/lagrange_basis.bin");

#[derive(Serialize, Deserialize)]
struct ContextWithProof<'a, OpeningProof: OpenProof<Vesta>> {
    index: VerifierIndex<'a, Vesta>,
    // group_map: BWParameters<VestaParameters>,
    // lagrange_basis: Vec<PolyComm<Vesta>>,
    alphas: Alphas<Vesta::ScalarField>,
    linearization: Linearization<Vec<PolishToken<Vesta::ScalarField, Column>>, Column>,
    proof: ProverProof<Vesta, OpeningProof>,
    public_input: Vec<Vec<u8>>,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct PolyCommCustom<C> {
    pub unshifted: C,
    pub shifted: Option<C>,
}

pub fn main() {
    // read the input
    let mut input: ContextWithProof<OpeningProof<Vesta>> = env::read();

    let public_input: Vec<Fp> = input.public_input.iter().map(|x| Fp::from_bytes(x).unwrap()).collect();
    let group_map = BWParameters::<VestaParameters>::setup();

    let vi = &mut input.index;
    // vi.powers_of_alpha.register(ArgumentType::Permutation, permutation::CONSTRAINTS);
    vi.powers_of_alpha = input.alphas;
    vi.linearization = input.linearization;

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

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
pub struct VerifierIndex<'a, G: KimchiCurve>
{
    #[serde_as(as = "kimchi::o1_utils::serialization::SerdeAs")]
    pub domain: D<G::ScalarField>,
    pub max_poly_size: usize,
    pub zk_rows: u64,
    #[serde(skip)]
    #[serde(bound(deserialize = "&'a SrsSized<G>: Default"))]
    pub srs: Arc<&'a SrsSized<G>>,
    pub public: usize,
    pub prev_challenges: usize,

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub sigma_comm: [PolyComm<G>; PERMUTS],

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub coefficients_comm: [PolyComm<G>; COLUMNS],

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub generic_comm: PolyComm<G>,

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub psm_comm: PolyComm<G>,

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub complete_add_comm: PolyComm<G>,

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub mul_comm: PolyComm<G>,

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub emul_comm: PolyComm<G>,

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub endomul_scalar_comm: PolyComm<G>,

    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub range_check0_comm: Option<PolyComm<G>>,

    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub range_check1_comm: Option<PolyComm<G>>,

    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub foreign_field_add_comm: Option<PolyComm<G>>,

    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub foreign_field_mul_comm: Option<PolyComm<G>>,

    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub xor_comm: Option<PolyComm<G>>,

    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub rot_comm: Option<PolyComm<G>>,

    #[serde_as(as = "[kimchi::o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub shift: [G::ScalarField; PERMUTS],

    #[serde(skip)]
    pub permutation_vanishing_polynomial_m: OnceCell<DensePolynomial<G::ScalarField>>,

    #[serde(skip)]
    pub w: OnceCell<G::ScalarField>,

    #[serde(skip)]
    pub endo: G::ScalarField,

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub lookup_index: Option<LookupVerifierIndex<G>>,

    #[serde(skip)]
    pub linearization: Linearization<Vec<PolishToken<G::ScalarField, Column>>, Column>,

    #[serde(skip)]
    pub powers_of_alpha: Alphas<G::ScalarField>,
}

impl<G: KimchiCurve> VerifierIndex<'_, G> {
    pub fn srs(&self) -> &Arc<&SrsSized<G>>
        where
            G::BaseField: PrimeField,
    {
        &self.srs
    }
    pub fn permutation_vanishing_polynomial_m(&self) -> &DensePolynomial<G::ScalarField> {
        self.permutation_vanishing_polynomial_m
            .get_or_init(|| vanishes_on_last_n_rows(self.domain, self.zk_rows))
    }
}

impl<G: KimchiCurve> VerifierIndex<'_, G> {

    pub fn w(&self) -> &G::ScalarField {
        self.w.get_or_init(|| zk_w(self.domain, self.zk_rows))
    }
    pub fn digest<EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>>(
        &self,
    ) -> G::BaseField {
        let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
        let VerifierIndex {
            domain: _,
            max_poly_size: _,
            zk_rows: _,
            srs: _,
            public: _,
            prev_challenges: _,

            // Always present
            sigma_comm,
            coefficients_comm,
            generic_comm,
            psm_comm,
            complete_add_comm,
            mul_comm,
            emul_comm,
            endomul_scalar_comm,

            // Optional gates
            range_check0_comm,
            range_check1_comm,
            foreign_field_add_comm,
            foreign_field_mul_comm,
            xor_comm,
            rot_comm,

            // Lookup index; optional
            lookup_index,

            shift: _,
            permutation_vanishing_polynomial_m: _,
            w: _,
            endo: _,

            linearization: _,
            powers_of_alpha: _,
        } = &self;

        // Always present

        for comm in sigma_comm.iter() {
            fq_sponge.absorb_g(&comm.unshifted);
        }
        for comm in coefficients_comm.iter() {
            fq_sponge.absorb_g(&comm.unshifted);
        }
        fq_sponge.absorb_g(&generic_comm.unshifted);
        fq_sponge.absorb_g(&psm_comm.unshifted);
        fq_sponge.absorb_g(&complete_add_comm.unshifted);
        fq_sponge.absorb_g(&mul_comm.unshifted);
        fq_sponge.absorb_g(&emul_comm.unshifted);
        fq_sponge.absorb_g(&endomul_scalar_comm.unshifted);

        // Optional gates

        if let Some(range_check0_comm) = range_check0_comm {
            fq_sponge.absorb_g(&range_check0_comm.unshifted);
        }

        if let Some(range_check1_comm) = range_check1_comm {
            fq_sponge.absorb_g(&range_check1_comm.unshifted);
        }

        if let Some(foreign_field_mul_comm) = foreign_field_mul_comm {
            fq_sponge.absorb_g(&foreign_field_mul_comm.unshifted);
        }

        if let Some(foreign_field_add_comm) = foreign_field_add_comm {
            fq_sponge.absorb_g(&foreign_field_add_comm.unshifted);
        }

        if let Some(xor_comm) = xor_comm {
            fq_sponge.absorb_g(&xor_comm.unshifted);
        }

        if let Some(rot_comm) = rot_comm {
            fq_sponge.absorb_g(&rot_comm.unshifted);
        }

        // Lookup index; optional

        if let Some(LookupVerifierIndex {
                        joint_lookup_used: _,
                        lookup_info: _,
                        lookup_table,
                        table_ids,
                        runtime_tables_selector,

                        lookup_selectors:
                        LookupSelectors {
                            xor,
                            lookup,
                            range_check,
                            ffmul,
                        },
                    }) = lookup_index
        {
            for entry in lookup_table {
                fq_sponge.absorb_g(&entry.unshifted);
            }
            if let Some(table_ids) = table_ids {
                fq_sponge.absorb_g(&table_ids.unshifted);
            }
            if let Some(runtime_tables_selector) = runtime_tables_selector {
                fq_sponge.absorb_g(&runtime_tables_selector.unshifted);
            }

            if let Some(xor) = xor {
                fq_sponge.absorb_g(&xor.unshifted);
            }
            if let Some(lookup) = lookup {
                fq_sponge.absorb_g(&lookup.unshifted);
            }
            if let Some(range_check) = range_check {
                fq_sponge.absorb_g(&range_check.unshifted);
            }
            if let Some(ffmul) = ffmul {
                fq_sponge.absorb_g(&ffmul.unshifted);
            }
        }
        fq_sponge.digest_fq()
    }
}

#[repr(C)]
pub struct SrsSized<G> {
    pub g: [G; VESTA_FIELD_PARAMS],
    pub h: G,
}

// impl the trait `Default` is  for `&SrsSized<G, N>`
impl<G> Default for &SrsSized<G> {
    fn default() -> Self {
        unsafe {
            std::mem::transmute::<&u8, &SrsSized<G>>(&SRS_BYTES[0])
        }
    }
}

// struct LBWrapped<G> {
//     // create phantom data to make the compiler happy
//     _phantom: std::marker::PhantomData<G>,
// }
//
// impl<G> LBWrapped<G> {
//     fn get_lagrange_basis(&self, domain_size: usize) -> Option<&Vec<PolyComm<G>>> {
//         let lagrange_basis = LAGRANGE_BASIS;
//         Some(&lagrange_basis)
//     }
// }


impl<G: CommitmentCurve> SRS<G> for SrsSized<G> {

    fn max_poly_size(&self) -> usize {
        self.g.len()
    }

    fn get_lagrange_basis(&self, domain_size: usize) -> Option<&Vec<PolyComm<G>>> {
        return None;
    }

    fn blinding_commitment(&self) -> G {
        self.h
    }

    fn commit(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
        max: Option<usize>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        self.mask(self.commit_non_hiding(plnm, num_chunks, max), rng)
    }

    fn mask_custom(
        &self,
        com: PolyComm<G>,
        blinders: &PolyComm<G::ScalarField>,
    ) -> std::result::Result<BlindedCommitment<G>, CommitmentError> {
        let commitment = com
            .zip(blinders)
            .ok_or_else(|| CommitmentError::BlindersDontMatch(blinders.len(), com.len()))?
            .map(|(g, b)| {
                let mut g_masked = self.h.mul(b);
                g_masked.add_assign_mixed(&g);
                g_masked.into_affine()
            });
        Ok(BlindedCommitment {
            commitment,
            blinders: blinders.clone(),
        })
    }

    fn mask(
        &self,
        comm: PolyComm<G>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        let blinders = comm.map(|_| G::ScalarField::rand(rng));
        self.mask_custom(comm, &blinders).unwrap()
    }

    fn commit_non_hiding(
        &self,
        plnm: &DensePolynomial<G::ScalarField>,
        num_chunks: usize,
        max: Option<usize>,
    ) -> PolyComm<G> {
        let is_zero = plnm.is_zero();

        let basis_len = self.g.len();
        let coeffs_len = plnm.coeffs.len();

        let coeffs: Vec<_> = plnm.iter().map(|c| c.into_repr()).collect();

        // chunk while commiting
        let mut unshifted = vec![];
        if is_zero {
            unshifted.push(G::zero());
        } else {
            coeffs.chunks(self.g.len()).for_each(|coeffs_chunk| {
                let chunk = VariableBaseMSM::multi_scalar_mul(&self.g, coeffs_chunk);
                unshifted.push(chunk.into_affine());
            });
        }

        for _ in unshifted.len()..num_chunks {
            unshifted.push(G::zero());
        }

        // committing only last chunk shifted to the right edge of SRS
        let shifted = match max {
            None => None,
            Some(max) => {
                let start = max - (max % basis_len);
                if is_zero || start >= coeffs_len {
                    // polynomial is small, nothing was shifted
                    Some(G::zero())
                } else if max % basis_len == 0 {
                    // the number of chunks should tell the verifier everything they need to know
                    None
                } else {
                    // we shift the last chunk to the right as proof of the degree bound
                    let shifted = VariableBaseMSM::multi_scalar_mul(
                        &self.g[basis_len - (max % basis_len)..],
                        &coeffs[start..],
                    );
                    Some(shifted.into_affine())
                }
            }
        };

        PolyComm::<G> { unshifted, shifted }
    }

    fn commit_evaluations_non_hiding(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
    ) -> PolyComm<G> {
        // let basis = self.get_lagrange_basis(domain.size())
            // .unwrap_or_else(|| panic!("lagrange bases for size {} not found", domain.size()));
        let basis = unsafe {
            std::mem::transmute::<&u8, &[PolyCommCustom<G>; VESTA_FIELD_LAGRANGE_BASES_PARAMS]>(&LAGRANGE_BASIS_BYTES[0])
        }
            .iter()
            .map(|x| PolyComm::<G> {
                unshifted: vec![x.unshifted],
                shifted: x.shifted,
            })
            .collect::<Vec<_>>();
        let commit_evaluations = |evals: &Vec<G::ScalarField>, basis: &Vec<PolyComm<G>>| {
            PolyComm::<G>::multi_scalar_mul(&basis.iter().collect::<Vec<_>>()[..], &evals[..])
        };
        match domain.size.cmp(&plnm.domain().size) {
            std::cmp::Ordering::Less => {
                let s = (plnm.domain().size / domain.size) as usize;
                let v: Vec<_> = (0..(domain.size())).map(|i| plnm.evals[s * i]).collect();
                commit_evaluations(&v, &basis)
            }
            std::cmp::Ordering::Equal => commit_evaluations(&plnm.evals, &basis),
            std::cmp::Ordering::Greater => {
                panic!("desired commitment domain size greater than evaluations' domain size")
            }
        }
    }

    fn commit_evaluations(
        &self,
        domain: D<G::ScalarField>,
        plnm: &Evaluations<G::ScalarField, D<G::ScalarField>>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> BlindedCommitment<G> {
        self.mask(self.commit_evaluations_non_hiding(domain, plnm), rng)
    }
}

impl <G: CommitmentCurve> SrsSized<G> {
    fn verify<EFqSponge, RNG>(
        &self,
        group_map: &G::Map,
        batch: &mut [BatchEvaluationProof<G, EFqSponge, OpeningProof<G>>],
        rng: &mut RNG,
    ) -> bool
        where
            EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
            RNG: RngCore + CryptoRng,
            G::BaseField: PrimeField,
    {
        let nonzero_length = self.g.len();

        let max_rounds = math::ceil_log2(nonzero_length);

        let padded_length = 1 << max_rounds;

        let (_, endo_r) = endos::<G>();

        // TODO: This will need adjusting
        let padding = padded_length - nonzero_length;
        let mut points = vec![self.h];
        points.extend(self.g.clone());
        points.extend(vec![G::zero(); padding]);

        let mut scalars = vec![G::ScalarField::zero(); padded_length + 1];
        assert_eq!(scalars.len(), points.len());

        // sample randomiser to scale the proofs with
        let rand_base = G::ScalarField::rand(rng);
        let sg_rand_base = G::ScalarField::rand(rng);

        let mut rand_base_i = G::ScalarField::one();
        let mut sg_rand_base_i = G::ScalarField::one();

        for BatchEvaluationProof {
            sponge,
            evaluation_points,
            polyscale,
            evalscale,
            evaluations,
            opening,
            combined_inner_product,
        } in batch.iter_mut()
        {
            sponge.absorb_fr(&[shift_scalar::<G>(*combined_inner_product)]);

            let t = sponge.challenge_fq();
            let u: G = to_group(group_map, t);

            let Challenges { chal, chal_inv } = opening.challenges::<EFqSponge>(&endo_r, sponge);

            sponge.absorb_g(&[opening.delta]);
            let c = ScalarChallenge(sponge.challenge()).to_field(&endo_r);

            let b0 = {
                let mut scale = G::ScalarField::one();
                let mut res = G::ScalarField::zero();
                for &e in evaluation_points.iter() {
                    let term = b_poly(&chal, e);
                    res += &(scale * term);
                    scale *= *evalscale;
                }
                res
            };

            let s = b_poly_coefficients(&chal);

            let neg_rand_base_i = -rand_base_i;

            points.push(opening.sg);
            scalars.push(neg_rand_base_i * opening.z1 - sg_rand_base_i);

            {
                let terms: Vec<_> = s.iter().map(|s| sg_rand_base_i * s).collect();

                for (i, term) in terms.iter().enumerate() {
                    scalars[i + 1] += term;
                }
            }

            scalars[0] -= &(rand_base_i * opening.z2);

            scalars.push(neg_rand_base_i * (opening.z1 * b0));
            points.push(u);

            let rand_base_i_c_i = c * rand_base_i;
            for ((l, r), (u_inv, u)) in opening.lr.iter().zip(chal_inv.iter().zip(chal.iter())) {
                points.push(*l);
                scalars.push(rand_base_i_c_i * u_inv);

                points.push(*r);
                scalars.push(rand_base_i_c_i * u);
            }

            combine_commitments(
                evaluations,
                &mut scalars,
                &mut points,
                *polyscale,
                rand_base_i_c_i,
            );

            scalars.push(rand_base_i_c_i * *combined_inner_product);
            points.push(u);

            scalars.push(rand_base_i);
            points.push(opening.delta);

            rand_base_i *= &rand_base;
            sg_rand_base_i *= &sg_rand_base;
        }

        // verify the equation
        let scalars: Vec<_> = scalars.iter().map(|x| x.into_repr()).collect();
        VariableBaseMSM::multi_scalar_mul(&points, &scalars) == G::Projective::zero()
    }
}

impl<G: CommitmentCurve> SrsSized<G> {
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::many_single_char_names)]
    pub fn open<EFqSponge, RNG, D: EvaluationDomain<G::ScalarField>>(
        &self,
        group_map: &G::Map,
        // TODO(mimoo): create a type for that entry
        plnms: &[(
            DensePolynomialOrEvaluations<G::ScalarField, D>,
            Option<usize>,
            PolyComm<G::ScalarField>,
        )],
        elm: &[G::ScalarField],
        polyscale: G::ScalarField,
        evalscale: G::ScalarField,
        mut sponge: EFqSponge,
        rng: &mut RNG,
    ) -> OpeningProof<G>
        where
            EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
            RNG: RngCore + CryptoRng,
            G::BaseField: PrimeField,
            G: EndoCurve,
    {
        let (endo_q, endo_r) = endos::<G>();

        let rounds = math::ceil_log2(self.g.len());
        let padded_length = 1 << rounds;

        let mut g = self.g.clone();
        // TODO: This is not needed because the SRS group elements list will have a length of
        // power of 2, in this case 2^17. So the padding is not needed.
        // let padding = padded_length - g.len();
        // g.extend(vec![G::zero(); padding]);

        let (p, blinding_factor) = combine_polys::<G, D>(plnms, polyscale, self.g.len());

        let rounds = math::ceil_log2(self.g.len());

        // b_j = sum_i r^i elm_i^j
        let b_init = {
            // randomise/scale the eval powers
            let mut scale = G::ScalarField::one();
            let mut res: Vec<G::ScalarField> =
                (0..padded_length).map(|_| G::ScalarField::zero()).collect();
            for e in elm {
                for (i, t) in pows(padded_length, *e).iter().enumerate() {
                    res[i] += &(scale * t);
                }
                scale *= &evalscale;
            }
            res
        };

        let combined_inner_product = p
            .coeffs
            .iter()
            .zip(b_init.iter())
            .map(|(a, b)| *a * b)
            .fold(G::ScalarField::zero(), |acc, x| acc + x);

        sponge.absorb_fr(&[shift_scalar::<G>(combined_inner_product)]);

        let t = sponge.challenge_fq();
        let u: G = to_group(group_map, t);

        let mut a = p.coeffs;
        assert!(padded_length >= a.len());
        a.extend(vec![G::ScalarField::zero(); padded_length - a.len()]);

        let mut b = b_init;

        let mut lr = vec![];

        let mut blinders = vec![];

        let mut chals = vec![];
        let mut chal_invs = vec![];

        for _ in 0..rounds {
            let n = g.len() / 2;
            let (g_lo, g_hi) = (g[0..n].to_vec(), g[n..].to_vec());
            let (a_lo, a_hi) = (&a[0..n], &a[n..]);
            let (b_lo, b_hi) = (&b[0..n], &b[n..]);

            let rand_l = <G::ScalarField as UniformRand>::rand(rng);
            let rand_r = <G::ScalarField as UniformRand>::rand(rng);

            let l = VariableBaseMSM::multi_scalar_mul(
                &[&g[0..n], &[self.h, u]].concat(),
                &[&a[n..], &[rand_l, inner_prod(a_hi, b_lo)]]
                    .concat()
                    .iter()
                    .map(|x| x.into_repr())
                    .collect::<Vec<_>>(),
            )
                .into_affine();

            let r = VariableBaseMSM::multi_scalar_mul(
                &[&g[n..], &[self.h, u]].concat(),
                &[&a[0..n], &[rand_r, inner_prod(a_lo, b_hi)]]
                    .concat()
                    .iter()
                    .map(|x| x.into_repr())
                    .collect::<Vec<_>>(),
            )
                .into_affine();

            lr.push((l, r));
            blinders.push((rand_l, rand_r));

            sponge.absorb_g(&[l]);
            sponge.absorb_g(&[r]);

            let u_pre = squeeze_prechallenge(&mut sponge);
            let u = u_pre.to_field(&endo_r);
            let u_inv = u.inverse().unwrap();

            chals.push(u);
            chal_invs.push(u_inv);

            a = a_hi
                .iter()
                .zip(a_lo)
                .map(|(&hi, &lo)| {
                    // lo + u_inv * hi
                    let mut res = hi;
                    res *= u_inv;
                    res += &lo;
                    res
                })
                .collect();

            b = b_lo
                .iter()
                .zip(b_hi)
                .map(|(&lo, &hi)| {
                    // lo + u * hi
                    let mut res = hi;
                    res *= u;
                    res += &lo;
                    res
                })
                .collect();

            g = <[G; VESTA_FIELD_PARAMS]>::try_from(G::combine_one_endo(endo_r, endo_q, &g_lo, &g_hi, u_pre)).unwrap();
        }

        assert!(g.len() == 1);
        let a0 = a[0];
        let b0 = b[0];
        let g0 = g[0];

        let r_prime = blinders
            .iter()
            .zip(chals.iter().zip(chal_invs.iter()))
            .map(|((l, r), (u, u_inv))| ((*l) * u_inv) + (*r * u))
            .fold(blinding_factor, |acc, x| acc + x);

        let d = <G::ScalarField as UniformRand>::rand(rng);
        let r_delta = <G::ScalarField as UniformRand>::rand(rng);

        let delta = ((g0.into_projective() + (u.mul(b0))).into_affine().mul(d)
            + self.h.mul(r_delta))
            .into_affine();

        sponge.absorb_g(&[delta]);
        let c = ScalarChallenge(sponge.challenge()).to_field(&endo_r);

        let z1 = a0 * c + d;
        let z2 = c * r_prime + r_delta;

        OpeningProof {
            delta,
            lr,
            z1,
            z2,
            sg: g0,
        }
    }
}

pub struct Context<'a, G: KimchiCurve, OpeningProof: OpenProof<G>> {
    pub verifier_index: &'a VerifierIndex<'a, G>,

    pub proof: &'a ProverProof<G, OpeningProof>,

    pub public_input: &'a [G::ScalarField],
}

impl<'a, G: KimchiCurve, OpeningProof: OpenProof<G>> Context<'a, G, OpeningProof> {
    pub fn get_column(&self, col: Column) -> Option<&'a PolyComm<G>> {
        use Column::*;
        match col {
            Witness(i) => Some(&self.proof.commitments.w_comm[i]),
            Coefficient(i) => Some(&self.verifier_index.coefficients_comm[i]),
            Permutation(i) => Some(&self.verifier_index.sigma_comm[i]),
            Z => Some(&self.proof.commitments.z_comm),
            LookupSorted(i) => Some(&self.proof.commitments.lookup.as_ref()?.sorted[i]),
            LookupAggreg => Some(&self.proof.commitments.lookup.as_ref()?.aggreg),
            LookupKindIndex(i) => {
                Some(self.verifier_index.lookup_index.as_ref()?.lookup_selectors[i].as_ref()?)
            }
            LookupTable => None,
            LookupRuntimeSelector => Some(
                self.verifier_index
                    .lookup_index
                    .as_ref()?
                    .runtime_tables_selector
                    .as_ref()?,
            ),
            LookupRuntimeTable => self.proof.commitments.lookup.as_ref()?.runtime.as_ref(),
            Index(t) => {
                use GateType::*;
                match t {
                    Zero => None,
                    Generic => Some(&self.verifier_index.generic_comm),
                    Lookup => None,
                    CompleteAdd => Some(&self.verifier_index.complete_add_comm),
                    VarBaseMul => Some(&self.verifier_index.mul_comm),
                    EndoMul => Some(&self.verifier_index.emul_comm),
                    EndoMulScalar => Some(&self.verifier_index.endomul_scalar_comm),
                    Poseidon => Some(&self.verifier_index.psm_comm),
                    CairoClaim | CairoInstruction | CairoFlags | CairoTransition => None,
                    RangeCheck0 => Some(self.verifier_index.range_check0_comm.as_ref()?),
                    RangeCheck1 => Some(self.verifier_index.range_check1_comm.as_ref()?),
                    ForeignFieldAdd => Some(self.verifier_index.foreign_field_add_comm.as_ref()?),
                    ForeignFieldMul => Some(self.verifier_index.foreign_field_mul_comm.as_ref()?),
                    Xor16 => Some(self.verifier_index.xor_comm.as_ref()?),
                    Rot64 => Some(self.verifier_index.rot_comm.as_ref()?),
                    KeccakRound => todo!(),
                    KeccakSponge => todo!(),
                }
            }
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct OpeningProof<G: AffineCurve> {
    /// vector of rounds of L & R commitments
    #[serde_as(as = "Vec<(o1_utils::serialization::SerdeAs, o1_utils::serialization::SerdeAs)>")]
    pub lr: Vec<(G, G)>,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub delta: G,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub z1: G::ScalarField,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub z2: G::ScalarField,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub sg: G,
}

impl<
    BaseField: PrimeField,
    G: AffineCurve<BaseField = BaseField> + CommitmentCurve + EndoCurve,
> crate::OpenProof<G> for OpeningProof<G>
{
    type SRS = SrsSized<G>;

    fn open<EFqSponge, RNG, D: EvaluationDomain<<G as AffineCurve>::ScalarField>>(
        srs: &Self::SRS,
        group_map: &<G as CommitmentCurve>::Map,
        plnms: &[(
            DensePolynomialOrEvaluations<<G as AffineCurve>::ScalarField, D>,
            Option<usize>,
            PolyComm<<G as AffineCurve>::ScalarField>,
        )], // vector of polynomial with optional degree bound and commitment randomness
        elm: &[<G as AffineCurve>::ScalarField], // vector of evaluation points
        polyscale: <G as AffineCurve>::ScalarField, // scaling factor for polynoms
        evalscale: <G as AffineCurve>::ScalarField, // scaling factor for evaluation point powers
        sponge: EFqSponge,                       // sponge
        rng: &mut RNG,
    ) -> Self
        where
            EFqSponge:
            Clone + FqSponge<<G as AffineCurve>::BaseField, G, <G as AffineCurve>::ScalarField>,
            RNG: RngCore + CryptoRng,
    {
        srs.open(group_map, plnms, elm, polyscale, evalscale, sponge, rng)
    }

    fn verify<EFqSponge, RNG>(
        srs: &Self::SRS,
        group_map: &G::Map,
        batch: &mut [BatchEvaluationProof<G, EFqSponge, Self>],
        rng: &mut RNG,
    ) -> bool
        where
            EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
            RNG: RngCore + CryptoRng,
    {
        srs.verify(group_map, batch, rng)
    }
}

pub struct Challenges<F> {
    pub chal: Vec<F>,
    pub chal_inv: Vec<F>,
}

impl<G: AffineCurve> OpeningProof<G> {
    pub fn prechallenges<EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
        &self,
        sponge: &mut EFqSponge,
    ) -> Vec<ScalarChallenge<G::ScalarField>> {
        let _t = sponge.challenge_fq();
        self.lr
            .iter()
            .map(|(l, r)| {
                sponge.absorb_g(&[*l]);
                sponge.absorb_g(&[*r]);
                squeeze_prechallenge(sponge)
            })
            .collect()
    }

    pub fn challenges<EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>>(
        &self,
        endo_r: &G::ScalarField,
        sponge: &mut EFqSponge,
    ) -> Challenges<G::ScalarField> {
        let chal: Vec<_> = self
            .lr
            .iter()
            .map(|(l, r)| {
                sponge.absorb_g(&[*l]);
                sponge.absorb_g(&[*r]);
                squeeze_challenge(endo_r, sponge)
            })
            .collect();

        let chal_inv = {
            let mut cs = chal.clone();
            ark_ff::batch_inversion(&mut cs);
            cs
        };

        Challenges { chal, chal_inv }
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct ProverProof<G: AffineCurve, OpeningProof> {
    pub commitments: ProverCommitments<G>,

    #[serde(bound(
    serialize = "OpeningProof: Serialize",
    deserialize = "OpeningProof: Deserialize<'de>"
    ))]
    pub proof: OpeningProof,

    pub evals: ProofEvaluations<PointEvaluations<Vec<G::ScalarField>>>,

    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub ft_eval1: G::ScalarField,

    pub prev_challenges: Vec<kimchi::proof::RecursionChallenge<G>>,
}

impl<G: KimchiCurve, OpeningProof: OpenProof<G>> ProverProof<G, OpeningProof>
    where
        G::BaseField: PrimeField,
{
    pub fn oracles<
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
    >(
        &self,
        index: &VerifierIndex<G>,
        public_comm: &PolyComm<G>,
        public_input: Option<&[G::ScalarField]>,
    ) -> Result<OraclesResult<G, EFqSponge>> {
        let n = index.domain.size;
        let (_, endo_r) = G::endos();

        let chunk_size = {
            let d1_size = index.domain.size();
            if d1_size < index.max_poly_size {
                1
            } else {
                d1_size / index.max_poly_size
            }
        };

        let zk_rows = index.zk_rows;

        let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

        let verifier_index_digest = index.digest::<EFqSponge>();
        fq_sponge.absorb_fq(&[verifier_index_digest]);

        for RecursionChallenge { comm, .. } in &self.prev_challenges {
            absorb_commitment(&mut fq_sponge, comm);
        }

        absorb_commitment(&mut fq_sponge, public_comm);

        self.commitments
            .w_comm
            .iter()
            .for_each(|c| absorb_commitment(&mut fq_sponge, c));

        if let Some(l) = &index.lookup_index {
            let lookup_commits = self
                .commitments
                .lookup
                .as_ref()
                .ok_or(VerifyError::LookupCommitmentMissing)?;

            if l.runtime_tables_selector.is_some() {
                let runtime_commit = lookup_commits
                    .runtime
                    .as_ref()
                    .ok_or(VerifyError::IncorrectRuntimeProof)?;
                absorb_commitment(&mut fq_sponge, runtime_commit);
            }
        }

        let joint_combiner = if let Some(l) = &index.lookup_index {
            let joint_combiner = if l.joint_lookup_used {
                fq_sponge.challenge()
            } else {
                G::ScalarField::zero()
            };

            let joint_combiner = ScalarChallenge(joint_combiner);
            let joint_combiner_field = joint_combiner.to_field(endo_r);
            let joint_combiner = (joint_combiner, joint_combiner_field);

            Some(joint_combiner)
        } else {
            None
        };

        if index.lookup_index.is_some() {
            let lookup_commits = self
                .commitments
                .lookup
                .as_ref()
                .ok_or(VerifyError::LookupCommitmentMissing)?;

            for com in &lookup_commits.sorted {
                absorb_commitment(&mut fq_sponge, com);
            }
        }

        let beta = fq_sponge.challenge();

        let gamma = fq_sponge.challenge();

        self.commitments.lookup.iter().for_each(|l| {
            absorb_commitment(&mut fq_sponge, &l.aggreg);
        });

        absorb_commitment(&mut fq_sponge, &self.commitments.z_comm);

        let alpha_chal = ScalarChallenge(fq_sponge.challenge());

        let alpha = alpha_chal.to_field(endo_r);

        if self.commitments.t_comm.unshifted.len() > chunk_size * 7 {
            return Err(VerifyError::IncorrectCommitmentLength(
                "t",
                chunk_size * 7,
                self.commitments.t_comm.unshifted.len(),
            ));
        }

        absorb_commitment(&mut fq_sponge, &self.commitments.t_comm);

        let zeta_chal = ScalarChallenge(fq_sponge.challenge());

        let zeta = zeta_chal.to_field(endo_r);

        let digest = fq_sponge.clone().digest();
        let mut fr_sponge = EFrSponge::new(G::sponge_params());

        fr_sponge.absorb(&digest);

        let prev_challenge_digest = {
            // Note: we absorb in a new sponge here to limit the scope in which we need the
            // more-expensive 'optional sponge'.
            let mut fr_sponge = EFrSponge::new(G::sponge_params());
            for RecursionChallenge { chals, .. } in &self.prev_challenges {
                fr_sponge.absorb_multiple(chals);
            }
            fr_sponge.digest()
        };
        fr_sponge.absorb(&prev_challenge_digest);

        let zeta1 = zeta.pow([n]);
        let zetaw = zeta * index.domain.group_gen;
        let evaluation_points = [zeta, zetaw];
        let powers_of_eval_points_for_chunks = PointEvaluations {
            zeta: zeta.pow([index.max_poly_size as u64]),
            zeta_omega: zetaw.pow([index.max_poly_size as u64]),
        };

        let polys: Vec<(PolyComm<G>, _)> = self
            .prev_challenges
            .iter()
            .map(|challenge| {
                let evals = challenge.evals(
                    index.max_poly_size,
                    &evaluation_points,
                    &[
                        powers_of_eval_points_for_chunks.zeta,
                        powers_of_eval_points_for_chunks.zeta_omega,
                    ],
                );
                let RecursionChallenge { chals: _, comm } = challenge;
                (comm.clone(), evals)
            })
            .collect();

        let mut all_alphas = index.powers_of_alpha.clone();
        all_alphas.instantiate(alpha);

        let public_evals = if let Some(public_evals) = &self.evals.public {
            [public_evals.zeta.clone(), public_evals.zeta_omega.clone()]
        } else if chunk_size > 1 {
            return Err(VerifyError::MissingPublicInputEvaluation);
        } else if let Some(public_input) = public_input {
            // compute Lagrange base evaluation denominators
            let w: Vec<_> = index.domain.elements().take(public_input.len()).collect();

            let mut zeta_minus_x: Vec<_> = w.iter().map(|w| zeta - w).collect();

            w.iter()
                .take(public_input.len())
                .for_each(|w| zeta_minus_x.push(zetaw - w));

            ark_ff::fields::batch_inversion::<G::ScalarField>(&mut zeta_minus_x);

            if public_input.is_empty() {
                [vec![G::ScalarField::zero()], vec![G::ScalarField::zero()]]
            } else {
                [
                    vec![
                        (public_input
                            .iter()
                            .zip(zeta_minus_x.iter())
                            .zip(index.domain.elements())
                            .map(|((p, l), w)| -*l * p * w)
                            .fold(G::ScalarField::zero(), |x, y| x + y))
                            * (zeta1 - G::ScalarField::one())
                            * index.domain.size_inv,
                    ],
                    vec![
                        (public_input
                            .iter()
                            .zip(zeta_minus_x[public_input.len()..].iter())
                            .zip(index.domain.elements())
                            .map(|((p, l), w)| -*l * p * w)
                            .fold(G::ScalarField::zero(), |x, y| x + y))
                            * index.domain.size_inv
                            * (zetaw.pow([n]) - G::ScalarField::one()),
                    ],
                ]
            }
        } else {
            return Err(VerifyError::MissingPublicInputEvaluation);
        };

        fr_sponge.absorb(&self.ft_eval1);

        fr_sponge.absorb_multiple(&public_evals[0]);
        fr_sponge.absorb_multiple(&public_evals[1]);
        fr_sponge.absorb_evaluations(&self.evals);

        let v_chal = fr_sponge.challenge();

        let v = v_chal.to_field(endo_r);

        let u_chal = fr_sponge.challenge();

        let u = u_chal.to_field(endo_r);

        let evals = self.evals.combine(&powers_of_eval_points_for_chunks);

        let ft_eval0 = {
            let permutation_vanishing_polynomial =
                index.permutation_vanishing_polynomial_m().evaluate(&zeta);
            let zeta1m1 = zeta1 - G::ScalarField::one();

            let mut alpha_powers =
                all_alphas.get_alphas(ArgumentType::Permutation, permutation::CONSTRAINTS);
            let alpha0 = alpha_powers
                .next()
                .expect("missing power of alpha for permutation");
            let alpha1 = alpha_powers
                .next()
                .expect("missing power of alpha for permutation");
            let alpha2 = alpha_powers
                .next()
                .expect("missing power of alpha for permutation");

            let init = (evals.w[PERMUTS - 1].zeta + gamma)
                * evals.z.zeta_omega
                * alpha0
                * permutation_vanishing_polynomial;
            let mut ft_eval0 = evals
                .w
                .iter()
                .zip(evals.s.iter())
                .map(|(w, s)| (beta * s.zeta) + w.zeta + gamma)
                .fold(init, |x, y| x * y);

            ft_eval0 -= DensePolynomial::eval_polynomial(
                &public_evals[0],
                powers_of_eval_points_for_chunks.zeta,
            );

            ft_eval0 -= evals
                .w
                .iter()
                .zip(index.shift.iter())
                .map(|(w, s)| gamma + (beta * zeta * s) + w.zeta)
                .fold(
                    alpha0 * permutation_vanishing_polynomial * evals.z.zeta,
                    |x, y| x * y,
                );

            let numerator = ((zeta1m1 * alpha1 * (zeta - index.w()))
                + (zeta1m1 * alpha2 * (zeta - G::ScalarField::one())))
                * (G::ScalarField::one() - evals.z.zeta);

            let denominator = (zeta - index.w()) * (zeta - G::ScalarField::one());
            let denominator = denominator.inverse().expect("negligible probability");

            ft_eval0 += numerator * denominator;

            let constants = Constants {
                alpha,
                beta,
                gamma,
                joint_combiner: joint_combiner.as_ref().map(|j| j.1),
                endo_coefficient: index.endo,
                mds: &G::sponge_params().mds,
                zk_rows,
            };

            ft_eval0 -= PolishToken::evaluate(
                &index.linearization.constant_term,
                index.domain,
                zeta,
                &evals,
                &constants,
            )
                .unwrap();

            ft_eval0
        };

        let combined_inner_product =
            {
                let ft_eval0 = vec![ft_eval0];
                let ft_eval1 = vec![self.ft_eval1];

                #[allow(clippy::type_complexity)]
                    let mut es: Vec<(Vec<Vec<G::ScalarField>>, Option<usize>)> =
                    polys.iter().map(|(_, e)| (e.clone(), None)).collect();
                es.push((public_evals.to_vec(), None));
                es.push((vec![ft_eval0, ft_eval1], None));
                for col in [
                    Column::Z,
                    Column::Index(GateType::Generic),
                    Column::Index(GateType::Poseidon),
                    Column::Index(GateType::CompleteAdd),
                    Column::Index(GateType::VarBaseMul),
                    Column::Index(GateType::EndoMul),
                    Column::Index(GateType::EndoMulScalar),
                ]
                    .into_iter()
                    .chain((0..COLUMNS).map(Column::Witness))
                    .chain((0..COLUMNS).map(Column::Coefficient))
                    .chain((0..PERMUTS - 1).map(Column::Permutation))
                    .chain(
                        index
                            .range_check0_comm
                            .as_ref()
                            .map(|_| Column::Index(GateType::RangeCheck0)),
                    )
                    .chain(
                        index
                            .range_check1_comm
                            .as_ref()
                            .map(|_| Column::Index(GateType::RangeCheck1)),
                    )
                    .chain(
                        index
                            .foreign_field_add_comm
                            .as_ref()
                            .map(|_| Column::Index(GateType::ForeignFieldAdd)),
                    )
                    .chain(
                        index
                            .foreign_field_mul_comm
                            .as_ref()
                            .map(|_| Column::Index(GateType::ForeignFieldMul)),
                    )
                    .chain(
                        index
                            .xor_comm
                            .as_ref()
                            .map(|_| Column::Index(GateType::Xor16)),
                    )
                    .chain(
                        index
                            .rot_comm
                            .as_ref()
                            .map(|_| Column::Index(GateType::Rot64)),
                    )
                    .chain(
                        index
                            .lookup_index
                            .as_ref()
                            .map(|li| {
                                (0..li.lookup_info.max_per_row + 1)
                                    .map(Column::LookupSorted)
                                    .chain([Column::LookupAggreg, Column::LookupTable].into_iter())
                                    .chain(
                                        li.runtime_tables_selector
                                            .as_ref()
                                            .map(|_| [Column::LookupRuntimeTable].into_iter())
                                            .into_iter()
                                            .flatten(),
                                    )
                                    .chain(
                                        self.evals
                                            .runtime_lookup_table_selector
                                            .as_ref()
                                            .map(|_| Column::LookupRuntimeSelector),
                                    )
                                    .chain(
                                        self.evals
                                            .xor_lookup_selector
                                            .as_ref()
                                            .map(|_| Column::LookupKindIndex(LookupPattern::Xor)),
                                    )
                                    .chain(
                                        self.evals
                                            .lookup_gate_lookup_selector
                                            .as_ref()
                                            .map(|_| Column::LookupKindIndex(LookupPattern::Lookup)),
                                    )
                                    .chain(
                                        self.evals.range_check_lookup_selector.as_ref().map(|_| {
                                            Column::LookupKindIndex(LookupPattern::RangeCheck)
                                        }),
                                    )
                                    .chain(self.evals.foreign_field_mul_lookup_selector.as_ref().map(
                                        |_| Column::LookupKindIndex(LookupPattern::ForeignFieldMul),
                                    ))
                            })
                            .into_iter()
                            .flatten(),
                    ) {
                    es.push((
                        {
                            let evals = self
                                .evals
                                .get_column(col)
                                .ok_or(VerifyError::MissingEvaluation(col))?;
                            vec![evals.zeta.clone(), evals.zeta_omega.clone()]
                        },
                        None,
                    ))
                }

                combined_inner_product(&evaluation_points, &v, &u, &es, index.srs().max_poly_size())
            };

        let oracles = RandomOracles {
            joint_combiner,
            beta,
            gamma,
            alpha_chal,
            alpha,
            zeta,
            v,
            u,
            zeta_chal,
            v_chal,
            u_chal,
        };

        Ok(OraclesResult {
            fq_sponge,
            digest,
            oracles,
            all_alphas,
            public_evals,
            powers_of_eval_points_for_chunks,
            polys,
            zeta1,
            ft_eval0,
            combined_inner_product,
        })
    }
}

pub fn batch_verify<'a, G, EFqSponge, EFrSponge, OpeningProof: OpenProof<G, SRS = SrsSized<G>>>(
    group_map: &G::Map,
    proofs: &[Context<G, OpeningProof>],
) -> Result<()>
    where
        G: KimchiCurve,
        G::BaseField: PrimeField,
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
{
    if proofs.is_empty() {
        return Ok(());
    }

    let srs = proofs[0].verifier_index.srs.clone();
    for &Context { verifier_index, .. } in proofs {
        if (&verifier_index.srs).max_poly_size() != srs.max_poly_size() {
            return Err(VerifyError::DifferentSRS);
        }
    }

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

    panic!("pushed to batch");

    if OpeningProof::verify(*srs, group_map, batch.as_mut_slice(), &mut thread_rng()) {
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
    verifier_index: &VerifierIndex<G>,
    proof: &'a ProverProof<G, OpeningProof>,
    public_input: &'a [<G as AffineCurve>::ScalarField],
) -> Result<BatchEvaluationProof<'a, G, EFqSponge, OpeningProof>>
    where
        G: KimchiCurve,
        G::BaseField: PrimeField,
        EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
        EFrSponge: FrSponge<G::ScalarField>,
{

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

    let chunk_size = {
        let d1_size = verifier_index.domain.size();
        if d1_size < verifier_index.max_poly_size {
            1
        } else {
            d1_size / verifier_index.max_poly_size
        }
    };
    check_proof_evals_len(proof, chunk_size)?;

    let public_comm = {
        if public_input.len() != verifier_index.public {
            return Err(VerifyError::IncorrectPubicInputLength(
                verifier_index.public,
            ));
        }
        // let lgr_comm = (&verifier_index
        //     .srs)
        //     .get_lagrange_basis(verifier_index.domain.size())
        //     .expect("pre-computed committed lagrange bases not found");

        let lgr_comm = unsafe {
            std::mem::transmute::<&u8, &[PolyCommCustom<G>; VESTA_FIELD_LAGRANGE_BASES_PARAMS]>(&LAGRANGE_BASIS_BYTES[0])
        }.iter()
            .map(|x| PolyComm::<G> {
                unshifted: vec![x.unshifted],
                shifted: x.shifted,
            })
            .collect::<Vec<_>>();;
        let com: Vec<_> = lgr_comm.iter().take(verifier_index.public).collect();
        if public_input.is_empty() {
            PolyComm::new(
                vec![(&verifier_index.srs).blinding_commitment(); chunk_size],
                None,
            )
        } else {
            let elm: Vec<_> = public_input.iter().map(|s| -*s).collect();
            let public_comm = PolyComm::<G>::multi_scalar_mul(&com, &elm);
            (&verifier_index
                .srs)
                .mask_custom(
                    public_comm.clone(),
                    &public_comm.map(|_| G::ScalarField::one()),
                )
                .unwrap()
                .commitment
        }
    };

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

    let evals = proof.evals.combine(&powers_of_eval_points_for_chunks);

    let context = Context {
        verifier_index,
        proof,
        public_input,
    };

    let f_comm = {
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

        PolyComm::multi_scalar_mul(&commitments, &scalars)
    };

    let ft_comm = {
        let zeta_to_srs_len = oracles.zeta.pow([verifier_index.max_poly_size as u64]);
        let chunked_f_comm = f_comm.chunk_commitment(zeta_to_srs_len);
        let chunked_t_comm = &proof.commitments.t_comm.chunk_commitment(zeta_to_srs_len);
        &chunked_f_comm - &chunked_t_comm.scale(zeta_to_domain_size - G::ScalarField::one())
    };

    let mut evaluations = vec![];

    evaluations.extend(polys.into_iter().map(|(c, e)| Evaluation {
        commitment: c,
        evaluations: e,
        degree_bound: None,
    }));

    evaluations.push(Evaluation {
        commitment: public_comm,
        evaluations: public_evals.to_vec(),
        degree_bound: None,
    });

    evaluations.push(Evaluation {
        commitment: ft_comm,
        evaluations: vec![vec![ft_eval0], vec![proof.ft_eval1]],
        degree_bound: None,
    });

    for col in [
        Column::Z,
        Column::Index(GateType::Generic),
        Column::Index(GateType::Poseidon),
        Column::Index(GateType::CompleteAdd),
        Column::Index(GateType::VarBaseMul),
        Column::Index(GateType::EndoMul),
        Column::Index(GateType::EndoMulScalar),
    ]
        .into_iter()
        .chain((0..COLUMNS).map(Column::Witness))
        .chain((0..COLUMNS).map(Column::Coefficient))
        .chain((0..PERMUTS - 1).map(Column::Permutation))
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
        evaluations.push(Evaluation {
            commitment: table_comm,
            evaluations: vec![lookup_table.zeta.clone(), lookup_table.zeta_omega.clone()],
            degree_bound: None,
        });
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
