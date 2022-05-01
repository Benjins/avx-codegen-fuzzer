

use crate::arm_intrinsics::*;

use std::collections::HashMap;
use std::convert::TryInto;

use std::fmt::Write;

use crate::codegen_fuzzing::CodegenFuzzer;
use crate::rand::Rand;

use crate::arm_codegen_ctx::ARMSIMDCodegenCtx;
use crate::arm_codegen_ctx::{generate_arm_codegen_ctx, generate_cpp_code_from_arm_codegen_ctx};

use crate::exec_mem::ExecPage;



pub struct ARMCodegenFuzzerCodeMetadata {
	num_i_vals : usize,
	num_f_vals : usize,
	num_d_vals : usize,
	return_type : ARMSIMDType
}

pub struct ARMCodegenFuzzerThreadInput {
	pub thread_seed : u64,
	pub type_to_intrinsics_map : HashMap<ARMSIMDType, Vec<ARMSIMDIntrinsic>>
}

pub struct ARMCodegenFuzzer {
	type_to_intrinsics_map : HashMap<ARMSIMDType, Vec<ARMSIMDIntrinsic>>,
	all_intrinsic_return_types : Vec<ARMSIMDType>,
	outer_rng : Rand
}

#[derive(Clone, Debug)]
pub struct ARMCodeFuzzerInputValues {
	pub i_vals : Vec<i32>,
	pub f_vals : Vec<f32>,
	pub d_vals : Vec<f64>
}

#[derive(Copy, Clone, Debug)]
pub struct ARMSIMDOutputValues {
	output_bytes : [u8; 64]
}



impl CodegenFuzzer<ARMCodegenFuzzerThreadInput, ARMSIMDCodegenCtx, ARMCodegenFuzzerCodeMetadata, ARMCodeFuzzerInputValues, ARMSIMDOutputValues> for ARMCodegenFuzzer {
	// Each of these will go on a thread, can contain inputs like
	// a parsed spec data, seed, flags, config, etc.
	fn new_fuzzer_state(input_data : Self::ThreadInput) -> Self {
		let mut all_intrinsic_return_types = Vec::new();
		for (ret_type, _) in input_data.type_to_intrinsics_map.iter() {
			all_intrinsic_return_types.push(*ret_type);
		}

		ARMCodegenFuzzer {
			type_to_intrinsics_map: input_data.type_to_intrinsics_map,
			all_intrinsic_return_types: all_intrinsic_return_types,
			outer_rng: Rand::new(input_data.thread_seed)
		}
	}

	// This generates some context struct that's basically analagous to the AST
	fn generate_ctx(&mut self) -> Self::CodegenCtx {
		let mut codegen_ctx = Self::CodegenCtx::new(self.outer_rng.rand_u64());
		generate_arm_codegen_ctx(&mut codegen_ctx, &self.type_to_intrinsics_map, &self.all_intrinsic_return_types);
		return codegen_ctx;
	}

	// Turn the AST/context into actual CPP code, along with any metadata (i.e. number of values to pass for SIMD's iVals pointer, return value, etc.)
	fn generate_cpp_code(&self, ctx : &Self::CodegenCtx) -> (String, Self::CodeMeta) {
		let (cpp_code, num_i_vals, num_f_vals, num_d_vals) = generate_cpp_code_from_arm_codegen_ctx(&ctx);
		let meta_data = Self::CodeMeta {
			num_i_vals: num_i_vals,
			num_f_vals: num_f_vals,
			num_d_vals: num_d_vals,
			return_type: ctx.get_return_type()
		};
		return (cpp_code, meta_data);
	}

	fn generate_random_input(&self, code_meta : &Self::CodeMeta) -> Self::FuzzerInput {
		todo!();
	}

	// uhh.....idk
	fn try_minimize<F: Fn(&Self, &Self::CodegenCtx) -> bool>(&self, ctx: Self::CodegenCtx, func: F) -> Option<Self::CodegenCtx> {
		todo!();
	}

	// Actually execute it: this is probably like local, but 
	fn execute(&self, exec_page : &ExecPage, code_meta: &Self::CodeMeta, input : &Self::FuzzerInput) -> Self::FuzzerOutput {
		todo!();
	}

	fn are_outputs_the_same(&self, o1 : &Self::FuzzerOutput, o2 : &Self::FuzzerOutput) -> bool {
		todo!();
	}
	
	fn save_input_to_string(&self, input : &Self::FuzzerInput) -> String {
		todo!();
	}
}



