use super::*;

use crate::verifier_structs::WrapperVerifier;
use crate::boojum::cs::{CSGeometry, LookupParameters};
use crate::boojum::cs::implementations::prover::ProofConfig;

pub trait ErasedBuilderForWrapperVerifier<
    E: Engine,
    CS: ConstraintSystem<E>,
> {
    fn geometry(&self) -> CSGeometry;
    fn lookup_parameters(&self) -> LookupParameters;
    fn create_wrapper_verifier(&self, cs: &mut CS) -> WrapperVerifier<E, CS>;
}

pub trait ProofWrapperFunction<E: Engine> {
    fn builder_for_wrapper<CS: ConstraintSystem<E> + 'static>(
        &self,
    ) -> Box<dyn ErasedBuilderForWrapperVerifier<E, CS>>;

    fn proof_config_for_compression_step(&self) -> ProofConfig;
}
