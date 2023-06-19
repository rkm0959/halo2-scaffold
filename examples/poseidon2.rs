use clap::Parser;
use halo2_base::{gates::GateChip, utils::ScalarField, AssignedValue, Context};
use halo2_scaffold::scaffold::{cmd::Cli, run};
use poseidon2::Poseidon2Chip;
use serde::{Deserialize, Serialize};

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 56;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub inputs: Vec<String>,
}

fn hash_inputs<F: ScalarField>(
    ctx: &mut Context<F>,
    inp: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    let inputs = inp.inputs.iter().map(|x| ctx.load_witness(F::from_str_vartime(&x).unwrap())).collect::<Vec<_>>();
    assert_eq!(inputs.len(), T - 1);
    make_public.extend(&inputs);

    let gate = GateChip::<F>::default();
    let mut poseidon2 = Poseidon2Chip::<F, T, RATE>::new(ctx, R_F, R_P).unwrap();
    poseidon2.update(&inputs);

    let hash = poseidon2.squeeze(ctx, &gate).unwrap();
    make_public.push(hash);
    
    println!("poseidon2(x): {:?}", hash.value());
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    run(hash_inputs, args);
}

// cargo run --example poseidon2 -- --name poseidon2 -i poseidon2-2.in -k 20 mock -> 0x0a84beb1d0a3e3c9ff62cb21216111181e960530897129f2610b2824502bed05
// cargo run --example poseidon2 -- --name poseidon2 -i poseidon2-3.in -k 20 mock -> 0x8750fcee667dd89f398f119aae3af8791b4c34da02833e0cfb57ae640d1645a
// cargo run --example poseidon2 -- --name poseidon2 -i poseidon2-7.in -k 20 mock -> 0x3119c298402b4f949130d86d6325eeb89a11b2847e2b94bde06942abefec891
