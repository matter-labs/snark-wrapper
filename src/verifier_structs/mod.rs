use franklin_crypto::plonk::circuit::goldilocks::GoldilocksField;

use boojum::cs::CSGeometry;
use boojum::cs::LookupParameters;
use boojum::cs::traits::gate::GatePlacementStrategy;
use boojum::cs::traits::evaluator::PerChunkOffset;
use boojum::cs::implementations::proof::Proof;
use boojum::field::goldilocks::{GoldilocksField as GL, GoldilocksExt2 as GLExt2};
use boojum::cs::implementations::prover::ProofConfig;
use boojum::cs::implementations::verifier::VerificationKeyCircuitGeometry;
use boojum::cs::oracle::TreeHasher;
use boojum::cs::implementations::proof::{OracleQuery, SingleRoundQueries};

use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::plonk::circuit::boolean::Boolean;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::plonk::circuit::allocated_num::Num;

use crate::verifier_structs::constants::ConstantsHolder;
use crate::traits::tree_hasher::CircuitGLTreeHasher;
use crate::verifier_structs::gate_evaluator::TypeErasedGateEvaluationWrapperVerificationFunction;

use std::any::TypeId;
use std::collections::HashMap;

pub mod allocated_proof;
pub mod allocated_queries;
pub mod allocated_vk;
pub mod gate_evaluator;
pub mod challenges;
pub mod constants;

pub struct WrapperVerifier<E: Engine, CS: ConstraintSystem<E> + 'static> {
    // when we init we get the following from VK
    pub parameters: CSGeometry,
    pub lookup_parameters: LookupParameters,

    pub(crate) gate_type_ids_for_specialized_columns: Vec<TypeId>,
    pub(crate) evaluators_over_specialized_columns:
        Vec<TypeErasedGateEvaluationWrapperVerificationFunction<E, CS>>,
    pub(crate) offsets_for_specialized_evaluators: Vec<(PerChunkOffset, PerChunkOffset, usize)>,

    pub(crate) evaluators_over_general_purpose_columns:
        Vec<TypeErasedGateEvaluationWrapperVerificationFunction<E, CS>>,

    pub(crate) total_num_variables_for_specialized_columns: usize,
    pub(crate) total_num_witnesses_for_specialized_columns: usize,
    pub(crate) total_num_constants_for_specialized_columns: usize,

    pub(crate) placement_strategies: HashMap<TypeId, GatePlacementStrategy>,
}

pub fn allocate_num_elements<T, R, E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    num_elements: usize,
    source: Option<impl Iterator<Item = T>>,
    allocating_function: impl Fn(&mut CS, Option<T>) -> Result<R, SynthesisError>,
) -> Result<Vec<R>, SynthesisError> {
    let mut result = Vec::with_capacity(num_elements);
    match source {
        Some(mut source) => {
            for idx in 0..num_elements {
                let witness = source.next().expect(&format!("must contain enough elements: failed to get element {} (zero enumerated) from expected list of {}", idx, num_elements));
                let el = allocating_function(cs, Some(witness))?;
                result.push(el);
            }

            assert!(source.next().is_none());
        }
        None => {
            for _ in 0..num_elements {
                let el = allocating_function(cs, None)?;
                result.push(el);
            }
        }
    }

    Ok(result)
}
