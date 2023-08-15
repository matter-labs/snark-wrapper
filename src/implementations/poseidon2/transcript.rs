use super::*;

use crate::traits::transcript::CircuitGLTranscript;

#[derive(Derivative)]
#[derivative(Clone, Debug)]
pub struct CircuitPoseidon2Transcript<
    E: Engine,
    const RATE: usize,
    const WIDTH: usize,
    const CHUNK_BY: usize,
    const ABSORB_BY_REPLACEMENT: bool,
>{
    buffer: Vec<LinearCombination<E>>,
    last_filled: usize,
    available_challenges: Vec<GoldilocksField<E>>,
    #[derivative(Debug = "ignore")]
    sponge: CircuitPoseidon2Sponge<E, RATE, WIDTH, CHUNK_BY, ABSORB_BY_REPLACEMENT>,
}

impl<
    E: Engine,
    const RATE: usize,
    const WIDTH: usize,
    const CHUNK_BY: usize,
    const ABSORB_BY_REPLACEMENT: bool,
> CircuitPoseidon2Transcript<E, RATE, WIDTH, CHUNK_BY, ABSORB_BY_REPLACEMENT> {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            last_filled: 0,
            available_challenges: Vec::new(),
            sponge: CircuitPoseidon2Sponge::<E, RATE, WIDTH, CHUNK_BY, ABSORB_BY_REPLACEMENT>::new(),
        }
    }
}

impl<
    E: Engine,
    const RATE: usize,
    const WIDTH: usize,
    const CHUNK_BY: usize,
    const ABSORB_BY_REPLACEMENT: bool,
> CircuitGLTranscript<E> for CircuitPoseidon2Transcript<E, RATE, WIDTH, CHUNK_BY, ABSORB_BY_REPLACEMENT> {
    type CircuitCompatibleCap = Num<E>;
    type TranscriptParameters = ();

    const IS_ALGEBRAIC: bool = true;

    fn new<CS: ConstraintSystem<E>>(
        _cs: &mut CS, 
        _params: Self::TranscriptParameters
    ) -> Result<Self, SynthesisError> {
        Ok(Self::new())
    }

    fn witness_field_elements<CS: ConstraintSystem<E>>(
        &mut self,
        _cs: &mut CS,
        field_els: &[GoldilocksField<E>],
    ) -> Result<(), SynthesisError> {
        debug_assert!(self.last_filled < CHUNK_BY);
        
        let add_to_last = field_els.len().min(
            (CHUNK_BY - self.last_filled) % CHUNK_BY
        );

        if add_to_last != 0 {
            for (i, el) in field_els[..add_to_last].iter().enumerate() {
                let mut coeff = <E::Fr as PrimeField>::Repr::from(1);
                coeff.shl(((i + self.last_filled) * GL::CHAR_BITS) as u32);

                self.buffer.last_mut().unwrap().add_assign_number_with_coeff(
                    &el.into_num(),
                    E::Fr::from_repr(coeff).unwrap()
                );
            }
        }

        for chunk in field_els[add_to_last..].chunks(CHUNK_BY) {
            let mut new = LinearCombination::zero();
            let mut coeff = <E::Fr as PrimeField>::Repr::from(1);
            for el in chunk.iter() {
                new.add_assign_number_with_coeff(&el.into_num(), E::Fr::from_repr(coeff).unwrap());
                coeff.shl(GL::CHAR_BITS as u32);
            }
            self.buffer.push(new);
        }

        self.last_filled = (self.last_filled + field_els.len()) % CHUNK_BY;

        Ok(())
    }

    fn witness_merkle_tree_cap<CS: ConstraintSystem<E>>(
        &mut self,
        _cs: &mut CS,
        cap: &Vec<Self::CircuitCompatibleCap>,
    ) -> Result<(), SynthesisError> {
        self.last_filled = 0;
        self.buffer.extend(cap.iter().map(|&el| el.into()));

        Ok(())
    }

    fn get_challenge<CS: ConstraintSystem<E>>(&mut self, cs: &mut CS) -> Result<GoldilocksField<E>, SynthesisError> {
        assert_eq!(self.sponge.filled, 0);

        if self.buffer.is_empty() {
            if self.available_challenges.len() > 0 {
                let first_el = self.available_challenges.first().unwrap().clone();
                self.available_challenges.drain(..1);
                return Ok(first_el);
            } else {
                self.sponge.run_round_function(cs)?;

                {
                    let commitment = self
                        .sponge
                        .try_get_commitment(cs)?
                        .expect("must have no pending elements in the buffer");
                    for &el in commitment.iter() {
                        self.available_challenges.extend(get_challenges_from_num(cs, el)?);
                    }
                }

                return self.get_challenge(cs);
            }
        }

        let to_absorb = std::mem::replace(&mut self.buffer, vec![]);
        self.sponge.absorb(cs, &to_absorb)?;

        self.available_challenges = vec![];
        let commitment = self.sponge.finalize(cs)?;
        for &el in commitment.iter() {
            self.available_challenges.extend(get_challenges_from_num(cs, el)?);
        }

        // to avoid duplication
        self.get_challenge(cs)
    }
}

fn get_challenges_from_num<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    num: Num<E>,
) -> Result<Vec<GoldilocksField<E>>, SynthesisError> {
    Ok(GoldilocksField::from_num_to_multiple_with_reduction::<_, 3>(cs, num)?.to_vec())
}
