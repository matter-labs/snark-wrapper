use crate::traits::transcript::CircuitGLTranscript;

use super::*;
use super::allocated_proof::AllocatedProof;
use boojum::field::traits::field_like::PrimeFieldLike;

use franklin_crypto::plonk::circuit::goldilocks::prime_field_like::*;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;

pub(crate) struct ChallengesHolder<E: Engine, CS: ConstraintSystem<E>> {
    // pub(crate) beta: GoldilocksFieldExt<E>,
    // pub(crate) gamma: GoldilocksFieldExt<E>,
    // pub(crate) alpha_powers: Vec<GoldilocksFieldExt<E>>,
    pub(crate) z: GoldilocksExtAsFieldWrapper<E, CS>,
    pub(crate) z_omega: GoldilocksExtAsFieldWrapper<E, CS>,

    pub(crate) challenges_for_fri_quotiening: Vec<GoldilocksExtAsFieldWrapper<E, CS>>,
    pub(crate) fri_intermediate_challenges: Vec<Vec<GoldilocksExtAsFieldWrapper<E, CS>>>,

    // pub(crate) challenges: Vec<GoldilocksFieldExt<E>>,
}

impl<E: Engine, CS: ConstraintSystem<E> + 'static> ChallengesHolder<E, CS> {
    pub fn new(cs: &mut CS) -> Self {
        Self {
            // beta: GoldilocksFieldExt::zero(),
            // gamma: GoldilocksFieldExt::zero(),
            // alpha_powers: vec![],
            z: GoldilocksExtAsFieldWrapper::zero(cs),
            z_omega: GoldilocksExtAsFieldWrapper::zero(cs),

            challenges_for_fri_quotiening: vec![],
            fri_intermediate_challenges: vec![],

            // challenges: vec![],
        }
    }

    pub fn get_challenges_for_fri_quotiening<T: CircuitGLTranscript<E>>(
        &mut self,
        cs: &mut CS,
        transcript: &mut T,
        total_num_challenges: usize,
    ) -> Result<(), SynthesisError> {
        // get challenges
        let c0 = transcript.get_challenge(cs)?;
        let c1 = transcript.get_challenge(cs)?;

        let challenge = GoldilocksExtAsFieldWrapper::from_coeffs_in_base([c0, c1]);

        self.challenges_for_fri_quotiening =
            crate::verifier::utils::materialize_powers_serial(cs, challenge, total_num_challenges);

        Ok(())
    }

    pub fn get_fri_intermediate_challenges<
        H: CircuitGLTreeHasher<E>,
        TR: CircuitGLTranscript<
            E,
            CircuitCompatibleCap = H::CircuitOutput,
        >,
    >(
        &mut self,
        cs: &mut CS,
        transcript: &mut TR,
        proof: &AllocatedProof<E, H>,
        fixed_parameters: &VerificationKeyCircuitGeometry,
        constants: &ConstantsHolder,
    ) -> Result<(), SynthesisError> {
        {
            // now witness base FRI oracle
            assert_eq!(fixed_parameters.cap_size, proof.fri_base_oracle_cap.len());
            transcript.witness_merkle_tree_cap(cs, &proof.fri_base_oracle_cap)?;

            let reduction_degree_log_2 = constants.fri_folding_schedule[0];

            let c0 = transcript.get_challenge(cs)?;
            let c1 = transcript.get_challenge(cs)?;

            let mut challenge_powers = Vec::with_capacity(reduction_degree_log_2);
            let as_extension =
                GoldilocksExtAsFieldWrapper::from_coeffs_in_base([c0, c1]);
            challenge_powers.push(as_extension);

            let mut current = as_extension;

            for _ in 1..reduction_degree_log_2 {
                current.square(cs);
                challenge_powers.push(current);
            }

            self.fri_intermediate_challenges.push(challenge_powers);
        }

        assert_eq!(
            constants.fri_folding_schedule[1..].len(),
            proof.fri_intermediate_oracles_caps.len()
        );

        for (interpolation_degree_log2, cap) in constants.fri_folding_schedule[1..]
            .iter()
            .zip(proof.fri_intermediate_oracles_caps.iter())
        {
            // commit new oracle
            assert_eq!(fixed_parameters.cap_size, cap.len());
            transcript.witness_merkle_tree_cap(cs, &cap)?;

            // get challenge
            let reduction_degree_log_2 = *interpolation_degree_log2;
            let c0 = transcript.get_challenge(cs)?;
            let c1 = transcript.get_challenge(cs)?;

            let mut challenge_powers = Vec::with_capacity(reduction_degree_log_2);
            let as_extension =
                GoldilocksExtAsFieldWrapper::from_coeffs_in_base([c0, c1]);
            challenge_powers.push(as_extension);

            let mut current = as_extension;

            for _ in 1..reduction_degree_log_2 {
                current.square(cs);
                challenge_powers.push(current);
            }

            self.fri_intermediate_challenges.push(challenge_powers);
        }

        Ok(())
    }
}
