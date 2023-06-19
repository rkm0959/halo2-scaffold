use clap::Parser;
use halo2_base::{gates::SBOXChip, utils::ScalarField, AssignedValue, Context};
use halo2_scaffold::scaffold::{cmd::Cli, run};
use aes::AESChip;
use serde::{Deserialize, Serialize};

const KEY_LEN: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub inputs: Vec<String>, // two field elements, but as strings for easier deserialization
}

fn encrypt_aes<F: ScalarField>(
    ctx: &mut Context<F>,
    inp: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    // first we load a private input `x` (let's not worry about public inputs for now)
    let inputs = inp.inputs.iter().map(|x| ctx.load_witness(F::from_str_vartime(&x).unwrap())).collect::<Vec<_>>();
    assert_eq!(inputs.len(), 1 + KEY_LEN / 64);

    // create a Gate chip that contains methods for basic arithmetic operations
    let sbox_gate = SBOXChip::<F>::default();
    let mut aes = AESChip::<F, KEY_LEN>::new(ctx, &sbox_gate, inputs[1..].to_vec()).unwrap();
    let result = aes.encrypt(ctx, &sbox_gate, inputs[0]);
    make_public.push(result);

    println!("(little endian) \n ptxt: {:?} \n ctxt: {:?}", inputs[0].value(), result.value());
    println!("(little endian) keys: ");
    for i in 1..inputs.len() {
        println!("key{}: {:?}", i, inputs[i].value());
    }

   // let inputs = ctx.load_witness(F::from_str_vartime(&inp.inputs[0]).unwrap());
   // let result = aes.encrypt(ctx, &sbox_gate, inputs);
    // make_public.push(result);
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    run(encrypt_aes, args);
}

// cargo run --example aes -- --name aes -k 20 -i aes128.in mock -> 0xd7643e41274788e7666d9defb9c090f3
// cargo run --example aes -- --name aes -k 20 -i aes192.in mock -> 0xb987d55b1b3eb2dcf4b8de19e8d7c4eb
// cargo run --example aes -- --name aes -k 20 -i aes256.in mock -> 0x85246c7b6bc1bcfdd2882b1decfca88c