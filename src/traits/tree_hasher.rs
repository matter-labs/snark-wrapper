use super::*;

use crate::boojum::cs::oracle::TreeHasher;

pub trait CircuitGLTreeHasher<E: Engine>:
    'static + Clone + Send + Sync
{
    type NonCircuitSimulator: TreeHasher<GL>;

    type CircuitOutput: Sized
        + 'static
        + Clone
        + Copy
        + Sync
        + Send
        // + PartialEq
        // + Eq
        + std::fmt::Debug
        // + CSAllocatable<E>
        // + CircuitVarLengthEncodable<E>
        ;

    fn new<CS: ConstraintSystem<E>>(cs: &mut CS) -> Result<Self, SynthesisError>;

    fn placeholder_output<CS: ConstraintSystem<E>>(cs: &mut CS) -> Result<Self::CircuitOutput, SynthesisError>;

    fn accumulate_into_leaf<CS: ConstraintSystem<E>>(&mut self, cs: &mut CS, value: &GoldilocksField<E>) -> Result<(), SynthesisError>;

    fn finalize_into_leaf_hash_and_reset<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
    ) -> Result<Self::CircuitOutput, SynthesisError>;

    fn hash_into_leaf<'a, S: IntoIterator<Item = &'a GoldilocksField<E>>, CS: ConstraintSystem<E>>(
        cs: &mut CS,
        source: S,
    ) -> Result<Self::CircuitOutput, SynthesisError>
    where
        GoldilocksField<E>: 'a;

    fn hash_into_leaf_owned<S: IntoIterator<Item = GoldilocksField<E>>, CS: ConstraintSystem<E>>(
        cs: &mut CS,
        source: S,
    ) -> Result<Self::CircuitOutput, SynthesisError>;

    fn swap_nodes<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        should_swap: Boolean,
        left: &Self::CircuitOutput,
        right: &Self::CircuitOutput,
        depth: usize,
    ) -> Result<(Self::CircuitOutput, Self::CircuitOutput), SynthesisError>;

    fn hash_into_node<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        left: &Self::CircuitOutput,
        right: &Self::CircuitOutput,
        depth: usize,
    ) -> Result<Self::CircuitOutput, SynthesisError>;

    fn select_cap_node<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        cap_bits: &[Boolean],
        cap: &[Self::CircuitOutput],
    ) -> Result<Self::CircuitOutput, SynthesisError>;

    fn compare_output<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        a: &Self::CircuitOutput,
        b: &Self::CircuitOutput,
    ) -> Result<Boolean, SynthesisError>;
}

