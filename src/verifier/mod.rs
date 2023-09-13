use boojum::cs::implementations::prover::ProofConfig;
use boojum::cs::implementations::verifier::VerificationKeyCircuitGeometry;
use boojum::field::goldilocks::{GoldilocksField as GL, GoldilocksExt2 as GLExt2};
use boojum::field::Field as BoojumField;
use boojum::field::PrimeField as BoojumPrimeField;
use boojum::field::traits::field_like::PrimeFieldLike;
use boojum::cs::implementations::utils::domain_generator_for_size;
use boojum::cs::LookupParameters;
use boojum::cs::implementations::proof::Proof;
use boojum::cs::oracle::TreeHasher;

use franklin_crypto::plonk::circuit::allocated_num::{Num, AllocatedNum};
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::plonk::circuit::boolean::Boolean;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::{Field, SynthesisError, PrimeField};
use franklin_crypto::plonk::circuit::linear_combination::LinearCombination;
use franklin_crypto::plonk::circuit::goldilocks::GoldilocksField;
use franklin_crypto::plonk::circuit::goldilocks::
    prime_field_like::{GoldilocksAsFieldWrapper, GoldilocksExtAsFieldWrapper};
use franklin_crypto::bellman::plonk::better_better_cs::cs::*;
use franklin_crypto::plonk::circuit::custom_rescue_gate::Rescue5CustomGate;
use franklin_crypto::plonk::circuit::bigint_new::BITWISE_LOGICAL_OPS_TABLE_NAME;
use crate::franklin_crypto::plonk::circuit::Assignment;
use franklin_crypto::bellman::plonk::better_better_cs::gates
    ::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;

use crate::verifier_structs::{*, allocated_proof::*};
use crate::traits::transcript::CircuitGLTranscript;
use crate::traits::tree_hasher::CircuitGLTreeHasher;
use crate::verifier_structs::challenges::{ChallengesHolder, EvaluationsHolder};
use crate::verifier_structs::allocated_vk::AllocatedVerificationKey;
use crate::verifier_structs::constants::ConstantsHolder;
use crate::traits::circuit::*;

mod first_step;
mod quotient_contributions;
mod fri;
pub(crate) mod utils;

use first_step::*;
use quotient_contributions::*;
use fri::*;
use utils::*;

#[derive(Clone, Debug)]
pub struct WrapperCircuit<
    E: Engine,
    HS: TreeHasher<GL, Output = E::Fr>,
    H: CircuitGLTreeHasher<E, CircuitOutput = Num<E>, NonCircuitSimulator = HS>,
    TR: CircuitGLTranscript<
        E,
        CircuitCompatibleCap = H::CircuitOutput,
    >,
    PWF: ProofWrapperFunction<E>,
> {
    pub witness: Option<Proof<GL, HS, GLExt2>>,
    pub vk: AllocatedVerificationKey<E, H>,
    pub fixed_parameters: VerificationKeyCircuitGeometry,
    pub transcript_params: TR::TranscriptParameters,
    pub wrapper_function: PWF,
}

impl<
    E: Engine,
    HS: TreeHasher<GL, Output = E::Fr>,
    H: CircuitGLTreeHasher<E, CircuitOutput = Num<E>, NonCircuitSimulator = HS>,
    TR: CircuitGLTranscript<
        E,
        CircuitCompatibleCap = H::CircuitOutput,
    >,
    PWF: ProofWrapperFunction<E>,
> Circuit<E> for WrapperCircuit<E, HS, H, TR, PWF> {
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(
            vec![Self::MainGate::default().into_internal(),
                Rescue5CustomGate::default().into_internal(),
            ]
        )
    }

    fn synthesize<CS: ConstraintSystem<E> + 'static>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        // add table for range check
        let columns3 = vec![
            PolyIdentifier::VariablesPolynomial(0),
            PolyIdentifier::VariablesPolynomial(1),
            PolyIdentifier::VariablesPolynomial(2),
        ];

        let name = BITWISE_LOGICAL_OPS_TABLE_NAME;
        let bitwise_logic_table = LookupTableApplication::new(
            name,
            TwoKeysOneValueBinopTable::<E, XorBinop>::new(8, name),
            columns3.clone(),
            None,
            true,
        );
        cs.add_table(bitwise_logic_table).unwrap();

        // ADD CUSTOM GATE

        let verifier_builder = self.wrapper_function.builder_for_wrapper();
        let verifier = verifier_builder.create_wrapper_verifier(cs);

        let proof_config = self.wrapper_function.proof_config_for_compression_step();

        let fixed_parameters = self.fixed_parameters.clone();

        let proof: AllocatedProof<E, H> = AllocatedProof::allocate_from_witness(
            cs,
            &self.witness,
            &verifier,
            &fixed_parameters,
            &proof_config,
        )?;

        // Verify proof
        crate::verifier::verify::<E, CS, H, TR>(
            cs,
            self.transcript_params.clone(),
            &proof_config,
            &proof,
            &verifier,
            &fixed_parameters,
            &self.vk,
        )?;

        // aggregate public inputs to one scalar field element
        assert!(proof.public_inputs.len() * (GL::CAPACITY_BITS / 8) <= E::Fr::CAPACITY as usize, 
            "scalar field capacity is not enough to fit all public inputs");
        let mut tmp = E::Fr::one();
        let shift = E::Fr::from_raw_repr(<E::Fr as PrimeField>::Repr::from(1 << (GL::CAPACITY_BITS % 8))).unwrap();
        let mut lc = LinearCombination::<E>::zero();
        for pi in proof.public_inputs.iter() {
            lc.add_assign_number_with_coeff(&pi.into_num(), tmp);
            tmp.mul_assign(&shift);
        }
        let mut minus_one = E::Fr::one();
        minus_one.negate();
        let pi = Num::Variable(AllocatedNum::alloc_input(cs, || Ok(*lc.get_value().get()?))?);
        lc.add_assign_number_with_coeff(&pi, minus_one);
        lc.enforce_zero(cs)?;

        Ok(())
    }
}

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
