use super::*;
use derivative::*;

use boojum::cs::traits::evaluator::GatePurpose;
use boojum::cs::traits::evaluator::GatePlacementType;
use boojum::cs::traits::evaluator::GenericDynamicEvaluatorOverGeneralPurposeColumns;
use boojum::cs::traits::evaluator::GenericDynamicEvaluatorOverSpecializedColumns;
use boojum::cs::implementations::verifier::VerifierPolyStorage;
use boojum::cs::implementations::verifier::VerifierRelationDestination;

use franklin_crypto::plonk::circuit::goldilocks::prime_field_like::GoldilocksExtAsFieldWrapper;

#[derive(Derivative)]
#[derivative(Debug)]
pub(crate) struct TypeErasedGateEvaluationWrapperVerificationFunction<
    E: Engine,
    CS: ConstraintSystem<E> + 'static,
> {
    pub(crate) debug_name: String,
    pub(crate) evaluator_type_id: TypeId,
    pub(crate) gate_purpose: GatePurpose,
    pub(crate) max_constraint_degree: usize,
    pub(crate) num_quotient_terms: usize,
    pub(crate) num_required_constants: usize,
    pub(crate) total_quotient_terms_over_all_repetitions: usize,
    pub(crate) num_repetitions_on_row: usize,
    pub(crate) placement_type: GatePlacementType,
    #[derivative(Debug = "ignore")]
    pub(crate) columnwise_satisfiability_function: Option<
        Box<
            dyn GenericDynamicEvaluatorOverSpecializedColumns<
                    GL,
                    GoldilocksExtAsFieldWrapper<E, CS>,
                    VerifierPolyStorage<GL, GoldilocksExtAsFieldWrapper<E, CS>>,
                    VerifierRelationDestination<GL, GoldilocksExtAsFieldWrapper<E, CS>>,
                >
                + 'static
                + Send
                + Sync,
        >,
    >,
    #[derivative(Debug = "ignore")]
    pub(crate) rowwise_satisfiability_function: Option<
        Box<
            dyn GenericDynamicEvaluatorOverGeneralPurposeColumns<
                    GL,
                    GoldilocksExtAsFieldWrapper<E, CS>,
                    VerifierPolyStorage<GL, GoldilocksExtAsFieldWrapper<E, CS>>,
                    VerifierRelationDestination<GL, GoldilocksExtAsFieldWrapper<E, CS>>,
                >
                + 'static
                + Send
                + Sync,
        >,
    >,
}
