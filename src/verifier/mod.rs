use boojum::cs::implementations::verifier::{Verifier, VerificationKey};
use boojum::algebraic_props::round_function::AbsorptionModeTrait;
use boojum::cs::implementations::prover::ProofConfig;
use boojum::cs::implementations::verifier::VerificationKeyCircuitGeometry;
use boojum::field::goldilocks::{GoldilocksField as GL, GoldilocksExt2 as GLExt2};
use boojum::field::Field as BoojumField;
use boojum::field::PrimeField as BoojumPrimeField;
use boojum::field::traits::field_like::PrimeFieldLike;
use boojum::cs::implementations::utils::domain_generator_for_size;

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
use crate::verifier_structs::challenges::ChallengesHolder;
use crate::verifier_structs::allocated_vk::AllocatedVerificationKey;
use crate::verifier_structs::constants::ConstantsHolder;

mod fri;
pub(crate) mod utils;

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
    verifier: &WrapperVerifier,
    fixed_parameters: &VerificationKeyCircuitGeometry,
    vk: &AllocatedVerificationKey<E, H>,
) -> Result<Boolean, SynthesisError> {
    let mut validity_flags = vec![];

    let mut transcript = TR::new(cs, transcript_params)?;
    let mut challenges = ChallengesHolder::new(cs);
    let constants = ConstantsHolder::generate(proof_config, verifier, fixed_parameters);

    let num_public_inputs = proof.public_inputs.len();
    let mut public_inputs_with_values = Vec::with_capacity(num_public_inputs);
    let mut public_input_allocated = Vec::with_capacity(num_public_inputs);

    // commit public inputs
    for ((column, row), value) in fixed_parameters
        .public_inputs_locations
        .iter()
        .copied()
        .zip(proof.public_inputs.iter().copied())
    {
        transcript.witness_field_elements(cs, &[value])?;
        public_input_allocated.push(value);
        let value = value.into();
        public_inputs_with_values.push((column, row, value));
    }

    // and public inputs should also go into quotient
    let mut public_input_opening_tuples: Vec<(GL, Vec<(usize, GoldilocksAsFieldWrapper<E, CS>)>)> =
        vec![];
    {
        let omega = domain_generator_for_size::<GL>(fixed_parameters.domain_size as u64);

        for (column, row, value) in public_inputs_with_values.into_iter() {
            let open_at = BoojumField::pow_u64(&omega, row as u64);
            let pos = public_input_opening_tuples
                .iter()
                .position(|el| el.0 == open_at);
            if let Some(pos) = pos {
                public_input_opening_tuples[pos].1.push((column, value));
            } else {
                public_input_opening_tuples.push((open_at, vec![(column, value)]));
            }
        }
    }

    let all_values_at_z: Vec<_> = proof
        .values_at_z
        .iter()
        .map(|el| 
            GoldilocksExtAsFieldWrapper::<E, CS>::from_coeffs_in_base(*el)
        ).collect();
    let all_values_at_z_omega: Vec<_> = proof
        .values_at_z_omega
        .iter()
        .map(|el| 
            GoldilocksExtAsFieldWrapper::<E, CS>::from_coeffs_in_base(*el)
        ).collect();
    let all_values_at_0: Vec<_> = proof
        .values_at_0
        .iter()
        .map(|el| 
            GoldilocksExtAsFieldWrapper::<E, CS>::from_coeffs_in_base(*el)
        ).collect(); 

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
        verifier,
        vk,
        &mut challenges,
        &mut transcript,
        fixed_parameters,
        public_input_opening_tuples,
        &constants,
        &all_values_at_z,
        &all_values_at_z_omega,
        &all_values_at_0,
    )?);

    let correct = smart_and(cs, &validity_flags)?;

    Ok(correct)
}
