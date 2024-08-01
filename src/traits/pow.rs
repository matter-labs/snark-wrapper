use super::*;

pub trait RecursivePoWRunner<E: Engine> {
    fn verify_from_field_elements<CS: ConstraintSystem<E>>(
        cs: &mut CS,
        seed: Vec<GoldilocksField<E>>,
        pow_challenge: [Boolean; 64],
        pow_bits: usize,
    ) -> Result<(Boolean, [GoldilocksField<E>; 2]), SynthesisError>;
}
