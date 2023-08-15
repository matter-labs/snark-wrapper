use boojum::cs::implementations::verifier::{Verifier, VerificationKey};
use boojum::algebraic_props::round_function::AbsorptionModeTrait;
use boojum::cs::implementations::prover::ProofConfig;
use boojum::cs::implementations::verifier::VerificationKeyCircuitGeometry;
use boojum::field::goldilocks::{GoldilocksField as GL, GoldilocksExt2 as GLExt2};
use boojum::field::Field as BoojumField;
use boojum::field::PrimeField as BoojumPrimeField;
use boojum::field::traits::field_like::PrimeFieldLike;
use boojum::cs::implementations::utils::domain_generator_for_size;
use boojum::cs::LookupParameters;

use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::plonk::circuit::boolean::Boolean;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::{Field, SynthesisError, PrimeField};
use franklin_crypto::plonk::circuit::linear_combination::LinearCombination;
use franklin_crypto::plonk::circuit::goldilocks::GoldilocksField;
use franklin_crypto::plonk::circuit::goldilocks::{
    GoldilocksFieldExt, 
    prime_field_like::{GoldilocksAsFieldWrapper, GoldilocksExtAsFieldWrapper}
};

use crate::verifier_structs::{*, allocated_proof::*};
use crate::traits::transcript::CircuitGLTranscript;
use crate::traits::tree_hasher::CircuitGLTreeHasher;
use crate::verifier_structs::challenges::{ChallengesHolder, EvaluationsHolder};
use crate::verifier_structs::allocated_vk::AllocatedVerificationKey;
use crate::verifier_structs::constants::ConstantsHolder;

mod first_step;
mod quotient_contributions;
mod fri;
pub(crate) mod utils;

use first_step::*;
use quotient_contributions::*;
use fri::*;
use utils::*;

pub fn verify<
    E: Engine, 
    CS: ConstraintSystem<E> + 'static,
    H: CircuitGLTreeHasher<E>,
    TR: CircuitGLTranscript<
        E,
        CircuitCompatibleCap = H::CircuitOutput,
    >,
    // TODO POW
>(
    cs: &mut CS,
    transcript_params: TR::TranscriptParameters,
    proof_config: &ProofConfig,
    proof: &AllocatedProof<E, H>,
    verifier: &WrapperVerifier<E, CS>,
    fixed_parameters: &VerificationKeyCircuitGeometry,
    vk: &AllocatedVerificationKey<E, H>,
) -> Result<Boolean, SynthesisError> {
    let mut validity_flags = Vec::with_capacity(256);

    let mut transcript = TR::new(cs, transcript_params)?;
    let mut challenges = ChallengesHolder::new(cs);

    // prepare constants
    let constants = ConstantsHolder::generate(proof_config, verifier, fixed_parameters);
    assert_eq!(fixed_parameters.cap_size, vk.setup_merkle_tree_cap.len());

    // let zero_num = Num::<F>::zero(cs);

    // let zero_base = NumAsFieldWrapper::<F, CS>::zero(cs);

    // let zero_ext = GoldilocksExtAsFieldWrapper::<E, CS>::zero(cs);
    // let one_ext = NumExtAsFieldWrapper::<F, EXT, CS>::one(cs);

    // let multiplicative_generator =
    //     NumAsFieldWrapper::constant(F::multiplicative_generator(), cs);

    let public_input_opening_tuples = verify_first_step(
        cs,
        proof,
        vk,
        &mut challenges,
        &mut transcript,
        verifier,
        fixed_parameters,
        &constants,
    )?;

    check_quotient_contributions_in_z(
        cs,
        proof,
        &challenges,
        verifier,
        fixed_parameters,
        &constants,
    )?;

    // TODO: implement

    // Check sizes and get challenges

    // Check quotient contributions at z:
    // - lookup
    // - specialized gates
    // - general purpose gates
    // - copy_permutation

    // PoW

    validity_flags.extend(verify_fri_part::<E, CS, H, TR>(
        cs,
        proof,
        vk,
        &mut challenges,
        &mut transcript,
        public_input_opening_tuples,
        verifier,
        fixed_parameters,
        &constants,
    )?);

    let correct = smart_and(cs, &validity_flags)?;

    Ok(correct)
}
