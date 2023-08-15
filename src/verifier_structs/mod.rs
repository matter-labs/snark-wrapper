use franklin_crypto::plonk::circuit::goldilocks::{GoldilocksField, GoldilocksFieldExt};

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
use boojum::cs::GateConfigurationHolder;
use boojum::cs::StaticToolboxHolder;
use boojum::cs::implementations::verifier::Verifier;

use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::plonk::circuit::boolean::Boolean;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use franklin_crypto::bellman::{Field, SynthesisError, PrimeField};
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


impl<E: Engine, CS: ConstraintSystem<E>> From<Verifier<GL, GLExt2>> for WrapperVerifier<E, CS> {
    fn from(value: Verifier<GL, GLExt2>) -> Self {
        let Verifier {
            parameters,
            lookup_parameters,
            // gates_configuration,
            gate_type_ids_for_specialized_columns,
            evaluators_over_specialized_columns,
            offsets_for_specialized_evaluators,
            evaluators_over_general_purpose_columns,
            total_num_variables_for_specialized_columns,
            total_num_witnesses_for_specialized_columns,
            total_num_constants_for_specialized_columns,
            ..
        } = value;

        // capture small pieces of information from the gate configuration
        assert_eq!(
            evaluators_over_specialized_columns.len(),
            gate_type_ids_for_specialized_columns.len()
        );

        let capacity = evaluators_over_specialized_columns.len();
        let mut placement_strategies = HashMap::with_capacity(capacity);
        // let placement_strategies = HashMap::new();

        // for gate_type_id in gate_type_ids_for_specialized_columns.iter() {
        //     let placement_strategy = gates_configuration
        //         .placement_strategy_for_type_id(*gate_type_id)
        //         .expect("gate must be allowed");
        //     placement_strategies.insert(*gate_type_id, placement_strategy);
        // }

        Self {
            parameters,
            lookup_parameters,
            gate_type_ids_for_specialized_columns,
            evaluators_over_specialized_columns: vec![],
            offsets_for_specialized_evaluators,
            evaluators_over_general_purpose_columns: vec![],
            total_num_variables_for_specialized_columns,
            total_num_witnesses_for_specialized_columns,
            total_num_constants_for_specialized_columns,
            placement_strategies,
        }
    }
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
