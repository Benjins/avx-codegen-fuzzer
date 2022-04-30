
use std::collections::HashMap;
use std::convert::TryInto;

use crate::codegen_fuzzing::CodegenFuzzer;
use crate::rand::Rand;

use crate::codegen_ctx::{X86SIMDCodegenCtx, X86SIMDCodegenNode, X86SIMDOptBaitNode};
use crate::codegen_ctx::{generate_cpp_code_from_codegen_ctx, generate_codegen_ctx};

// kinda just need all of this lol
use crate::intrinsics::*;

use crate::exec_mem::ExecPage;

pub struct X86CodegenFuzzerCodeMetadata {
	num_i_vals : usize,
	num_f_vals : usize,
	num_d_vals : usize,
	return_type : X86SIMDType
}

pub struct X86CodegenFuzzerThreadInput {
	pub thread_seed : u64,
	pub type_to_intrinsics_map : HashMap<X86SIMDType, Vec<X86SIMDIntrinsic>>
}

pub struct X86CodegenFuzzer {
	type_to_intrinsics_map : HashMap<X86SIMDType, Vec<X86SIMDIntrinsic>>,
	outer_rng : Rand,
}

#[derive(Clone, Debug)]
pub struct X86CodeFuzzerInputValues {
	pub i_vals : Vec<i32>,
	pub f_vals : Vec<f32>,
	pub d_vals : Vec<f64>
}

#[derive(Copy, Clone, Debug)]
pub enum X86SIMDOutputValues {
	SIMD128Bit(std::simd::u8x16),
	SIMD256Bit(std::simd::u8x32)
}

fn generate_random_input_for_program(num_i_vals : usize, num_f_vals : usize, num_d_vals : usize) -> X86CodeFuzzerInputValues {
	let mut rng = Rand::default();

	let mut i_vals = Vec::<i32>::with_capacity(num_i_vals);
	for _ in 0..num_i_vals {
		let rand_val = match (rng.rand() % 16) {
			0 =>  0,
			1 =>  1,
			2 =>  2,
			3 => -1,
			_ => rng.rand() as i32
		};
		i_vals.push(rand_val);
	}
	
	let mut f_vals = Vec::<f32>::with_capacity(num_f_vals);
	for _ in 0..num_f_vals { f_vals.push(rng.randf() * 2.0 - 1.0); }
	
	let mut d_vals = Vec::<f64>::with_capacity(num_d_vals);
	for _ in 0..num_d_vals { d_vals.push((rng.randf() * 2.0 - 1.0) as f64); }

	return X86CodeFuzzerInputValues { i_vals: i_vals, f_vals: f_vals, d_vals: d_vals };
}

impl CodegenFuzzer<X86CodegenFuzzerThreadInput, X86SIMDCodegenCtx, X86CodegenFuzzerCodeMetadata, X86CodeFuzzerInputValues, X86SIMDOutputValues> for X86CodegenFuzzer {
	// Each of these will go on a thread, can contain inputs like
	// a parsed spec data, seed, flags, config, etc.
	fn new_fuzzer_state(input_data : Self::ThreadInput) -> X86CodegenFuzzer {
		X86CodegenFuzzer {
			type_to_intrinsics_map: input_data.type_to_intrinsics_map,
			outer_rng: Rand::new(input_data.thread_seed)
		}
	}

	// This generates some context struct that's basically analagous to the AST
	fn generate_ctx(&mut self) -> Self::CodegenCtx {
		let mut codegen_ctx = Self::CodegenCtx::new(self.outer_rng.rand_u64());
		generate_codegen_ctx(&mut codegen_ctx, &self.type_to_intrinsics_map);
		return codegen_ctx;
	}

	// Turn the AST/context into actual CPP code, along with any metadata (i.e. number of values to pass for SIMD's iVals pointer, return value, etc.)
	fn generate_cpp_code(&self, ctx : &Self::CodegenCtx) -> (String, Self::CodeMeta) {
		let (cpp_code, num_i_vals, num_f_vals, num_d_vals) = generate_cpp_code_from_codegen_ctx(&ctx);
		let meta_data = Self::CodeMeta {
			num_i_vals: num_i_vals,
			num_f_vals: num_f_vals,
			num_d_vals: num_d_vals,
			return_type: ctx.get_return_type()
		};
		return (cpp_code, meta_data);
	}

	fn generate_random_input(&self, code_meta : &Self::CodeMeta) -> Self::FuzzerInput {
		return generate_random_input_for_program(code_meta.num_i_vals, code_meta.num_f_vals, code_meta.num_d_vals);
	}

	// If we can even bother minimizing the context
	fn can_minimize(&self) -> bool {
		// For now
		return false;
	}

	// uhh.....idk
	fn start_minimizing(&mut self) {
		todo!();
	}

	fn try_minimize(&mut self, ctx: &Self::CodegenCtx) -> Option<Self::CodegenCtx> {
		todo!();
	}

	// Actually execute it: this is probably like local, but 
	fn execute(&self, exec_page : &ExecPage, code_meta: &Self::CodeMeta, input : &Self::FuzzerInput) -> Self::FuzzerOutput {
		match code_meta.return_type {
			X86SIMDType::M256i(_) => {
				let ret = exec_page.execute_with_args_256i(&input.i_vals[..], &input.f_vals[..], &input.d_vals[..]);
				let bytes_256 : std::simd::u8x32 = ret.try_into().unwrap();
				return Self::FuzzerOutput::SIMD256Bit(bytes_256);
			},
			X86SIMDType::M128i(_) => {
				let ret = exec_page.execute_with_args_128i(&input.i_vals[..], &input.f_vals[..], &input.d_vals[..]);
				let bytes_128 : std::simd::u8x16 = ret.try_into().unwrap();
				return Self::FuzzerOutput::SIMD128Bit(bytes_128);
			},
			_ => { panic!("Bad return type for simd"); }
		}
	}

	fn are_outputs_the_same(&self, o1 : &Self::FuzzerOutput, o2 : &Self::FuzzerOutput) -> bool {
		match (o1, o2) {
			(Self::FuzzerOutput::SIMD128Bit(b1), Self::FuzzerOutput::SIMD128Bit(b2)) => {
				return b1 == b2;
			},
			(Self::FuzzerOutput::SIMD256Bit(b1), Self::FuzzerOutput::SIMD256Bit(b2)) => {
				return b1 == b2;
			},
			_ => { return false; }
		}
	}
}

