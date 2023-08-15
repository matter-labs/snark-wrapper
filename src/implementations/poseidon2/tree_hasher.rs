use super::*;

use crate::traits::tree_hasher::CircuitGLTreeHasher;
use rescue_poseidon::poseidon2::Poseidon2Sponge;

impl<
    E: Engine,
    const RATE: usize,
    const WIDTH: usize,
    const CHUNK_BY: usize,
    const ABSORB_BY_REPLACEMENT: bool,
> CircuitGLTreeHasher<E> for CircuitPoseidon2Sponge<E, RATE, WIDTH, CHUNK_BY, ABSORB_BY_REPLACEMENT> {
    type CircuitOutput = Num<E>;
    type NonCircuitSimulator = Poseidon2Sponge<E, GL, AbsorptionModeReplacement<E::Fr>, RATE, WIDTH>;

    fn new<CS: ConstraintSystem<E>>(_cs: &mut CS) -> Result<Self, SynthesisError> {
        Ok(Self::new())
    }

    fn placeholder_output<CS: ConstraintSystem<E>>(_cs: &mut CS) -> Result<Self::CircuitOutput, SynthesisError> {
        Ok(Num::zero())
    }

    fn accumulate_into_leaf<CS: ConstraintSystem<E>>(
        &mut self, 
        cs: &mut CS, 
        value: &GoldilocksField<E>
    ) -> Result<(), SynthesisError> {
        self.absorb_single_gl(cs, value)
    }

    fn finalize_into_leaf_hash_and_reset<CS: ConstraintSystem<E>>(
        &mut self,
        cs: &mut CS,
    ) -> Result<Self::CircuitOutput, SynthesisError> {
        Ok(self.finalize_reset(cs)?[0])
    }

    fn hash_into_leaf<'a, S: IntoIterator<Item = &'a GoldilocksField<E>>, CS: ConstraintSystem<E>>(
        cs: &mut CS,
        source: S,
    ) -> Result<Self::CircuitOutput, SynthesisError>
    where
        GoldilocksField<E>: 'a 
    {
        let mut hasher = Self::new();

        for el in source.into_iter() {
            hasher.absorb_single_gl(cs, el)?;
        }
        Ok(hasher.finalize(cs)?[0])
    }

    fn hash_into_leaf_owned<S: IntoIterator<Item = GoldilocksField<E>>, CS: ConstraintSystem<E>>(
        cs: &mut CS,
        source: S,
    ) -> Result<Self::CircuitOutput, SynthesisError> {
        let mut hasher = Self::new();

        for el in source.into_iter() {
            hasher.absorb_single_gl(cs, &el)?;
        }
        Ok(hasher.finalize(cs)?[0])
    }

    fn swap_nodes<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        should_swap: Boolean,
        left: &Self::CircuitOutput,
        right: &Self::CircuitOutput,
        _depth: usize,
    ) -> Result<(Self::CircuitOutput, Self::CircuitOutput), SynthesisError> {
        Num::conditionally_reverse(cs, left, right, &should_swap)
    }

    fn hash_into_node<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        left: &Self::CircuitOutput,
        right: &Self::CircuitOutput,
        _depth: usize,
    ) -> Result<Self::CircuitOutput, SynthesisError> {
        let params = Poseidon2Params::<E, RATE, WIDTH>::default();
        let mut state = [(); WIDTH].map(|_| LinearCombination::zero());
        state[0] = (*left).into();
        state[1] = (*right).into();

        circuit_poseidon2_round_function(cs, &params, &mut state)?;

        state[0].clone().into_num(cs)
    }


    fn select_cap_node<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        cap_bits: &[Boolean],
        cap: &[Self::CircuitOutput],
    ) -> Result<Self::CircuitOutput, SynthesisError> {
        assert_eq!(cap.len(), 1 << cap_bits.len());
        assert!(cap_bits.len() > 0);
    
        let mut input_space = Vec::with_capacity(cap.len() / 2);
        let mut dst_space = Vec::with_capacity(cap.len() / 2);
    
        for (idx, bit) in cap_bits.iter().enumerate() {
            let src = if idx == 0 { cap } else { &input_space };
    
            debug_assert_eq!(cap.len() % 2, 0);
            dst_space.clear();
    
            for src in src.array_chunks::<2>() {
                let [a, b] = src;
                // NOTE order here
                let selected = Num::conditionally_select(cs, bit, b, a)?;
                dst_space.push(selected);
            }
    
            std::mem::swap(&mut dst_space, &mut input_space);
        }
    
        assert_eq!(input_space.len(), 1);
    
        Ok(input_space.pop().unwrap())
    }

    fn compare_output<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        a: &Self::CircuitOutput,
        b: &Self::CircuitOutput,
    ) -> Result<Boolean, SynthesisError> {
        Num::equals(cs, a, b)
    }
}

use boojum::algebraic_props::round_function::AbsorptionModeTrait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbsorptionModeReplacement<F: PrimeField>(std::marker::PhantomData<F>);

impl<F: PrimeField> AbsorptionModeTrait<F> for AbsorptionModeReplacement<F> {
    fn absorb(dst: &mut F, src: &F) {
        *dst = *src;
    }

    fn pad(_dst: &mut F) {
        unimplemented!("pad is not used")
    }
}
