use clap::Parser;
use halo2_base::{gates::SBOXChip, utils::ScalarField, AssignedValue, Context};
use halo2_scaffold::scaffold::{cmd::Cli, run};
use aes::AESChip;
use poseidon2::Poseidon2Chip;
use serde::{Deserialize, Serialize};

const KEY_LEN: usize = 128;

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 56;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub inputs: [String; 3],
}

fn verifiable_encryption<F: ScalarField>(
    ctx: &mut Context<F>,
    inp: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // first we load a private input `x` (let's not worry about public inputs for now)
    let [ptxt, key0, key1] = inp.inputs.map(|x| ctx.load_witness(F::from_str_vartime(&x).unwrap()));

    // create a Gate chip that contains methods for basic arithmetic operations
    let sbox_gate = SBOXChip::<F>::default();
    let mut aes = AESChip::<F, KEY_LEN>::new(ctx, &sbox_gate, vec![key0, key1]).unwrap();
    let result = aes.encrypt(ctx, &sbox_gate, ptxt);
    make_public.push(result);

    let gate = sbox_gate.gate;
    let mut poseidon2 = Poseidon2Chip::<F, T, RATE>::new(ctx, R_F, R_P).unwrap();
    poseidon2.update(&[ptxt]);
    let hash = poseidon2.squeeze(ctx, &gate).unwrap();
    make_public.push(hash);

    println!("(little endian) \n ptxt: {:?} \n key0: {:?} \n key1: {:?} \n ctxt: {:?} \n hash: {:?}", ptxt.value(), key0.value(), key1.value(), result.value(), hash.value());
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    run(verifiable_encryption, args);
}

// cargo run --example verifiable_encryption -- --name verifiable_encrytion -k 20 -i verifiable_encryption.in mock