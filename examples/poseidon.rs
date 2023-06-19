use clap::Parser;
use halo2_base::{gates::GateChip, utils::ScalarField, AssignedValue, Context};
use halo2_scaffold::scaffold::{cmd::Cli, run};
use poseidon::PoseidonChip;
use serde::{Deserialize, Serialize};

const T: usize = 8;
const RATE: usize = 7;
const R_F: usize = 8;
const R_P: usize = 57;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub inputs: Vec<String>,
}

fn hash_two<F: ScalarField>(
    ctx: &mut Context<F>,
    inp: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // first we load a private input `x` (let's not worry about public inputs for now)
    let inputs = inp.inputs.iter().map(|x| ctx.load_witness(F::from_str_vartime(&x).unwrap())).collect::<Vec<_>>();
    assert_eq!(inputs.len(), T - 1);
    make_public.extend(&inputs);

    // create a Gate chip that contains methods for basic arithmetic operations
    let gate = GateChip::<F>::default();
    let mut poseidon = PoseidonChip::<F, T, RATE>::new(ctx, R_F, R_P).unwrap();
    poseidon.update(&inputs);
    let hash = poseidon.squeeze(ctx, &gate).unwrap();
    make_public.push(hash);
    println!("poseidon(x): {:?}", hash.value());
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    run(hash_two, args);
}

// cargo run --example poseidon -- --name poseidon -i poseidon2-2.in -k 20 mock
// cargo run --example poseidon -- --name poseidon -i poseidon2-3.in -k 20 mock
// cargo run --example poseidon -- --name poseidon -i poseidon2-7.in -k 20 mock