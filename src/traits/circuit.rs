use super::*;

use crate::verifier_structs::WrapperVerifier;
use boojum::cs::{CSGeometry, LookupParameters};

pub trait ErasedBuilderForWrapperVerifier<
    E: Engine,
    CS: ConstraintSystem<E> + 'static,
> {
    fn geometry(&self) -> CSGeometry;
    fn lookup_parameters(&self) -> LookupParameters;
    fn create_wrapper_verifier(&self, cs: &mut CS) -> WrapperVerifier<E, CS>;
}
